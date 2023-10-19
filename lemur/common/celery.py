"""
This module controls defines celery tasks and their applicable schedules. The celery beat server and workers will start
when invoked.

When ran in development mode (LEMUR_CONFIG=<location of development configuration file. To run both the celery
beat scheduler and a worker simultaneously, and to have jobs kick off starting at the next minute, run the following
command: celery -A lemur.common.celery worker --loglevel=info -l DEBUG -B

"""
import copy
import sys
import time
from celery import Celery
from celery.app.task import Context
from celery.exceptions import SoftTimeLimitExceeded
from celery.signals import task_failure, task_received, task_revoked, task_success
from datetime import datetime, timezone, timedelta
from flask import current_app
from sentry_sdk import capture_exception

from lemur.authorities.service import get as get_authority
from lemur.certificates import cli as cli_certificate
from lemur.certificates import service as certificate_service
from lemur.common.redis import RedisHandler
from lemur.constants import ACME_ADDITIONAL_ATTEMPTS
from lemur.dns_providers import cli as cli_dns_providers
from lemur.extensions import metrics
from lemur.factory import create_app
from lemur.notifications import cli as cli_notification
from lemur.notifications.messaging import (
    send_pending_failure_notification,
    send_reissue_no_endpoints_notification,
    send_reissue_failed_notification
)
from lemur.pending_certificates import service as pending_certificate_service
from lemur.plugins.base import plugins
from lemur.sources.cli import clean, sync, validate_sources

if current_app:
    flask_app = current_app
else:
    flask_app = create_app()

red = RedisHandler().redis()


def make_celery(app):
    celery = Celery(
        app.import_name,
        backend=app.config.get("CELERY_RESULT_BACKEND"),
        broker=app.config.get("CELERY_BROKER_URL"),
    )
    celery.conf.update(app.config)
    TaskBase = celery.Task

    class ContextTask(TaskBase):
        abstract = True

        def __call__(self, *args, **kwargs):
            with app.app_context():
                return TaskBase.__call__(self, *args, **kwargs)

    celery.Task = ContextTask
    return celery


celery_app = make_celery(flask_app)


def is_task_active(fun, task_id, args):
    if not args:
        args = "()"  # empty args

    i = celery_app.control.inspect()
    active_tasks = i.active()
    if active_tasks is None:
        return False
    for _, tasks in active_tasks.items():
        for task in tasks:
            if task.get("id") == task_id:
                continue
            if task.get("name") == fun and task.get("args") == str(args):
                return True
    return False


def get_celery_request_tags(**kwargs):
    request = kwargs.get("request")
    sender_hostname = "unknown"
    sender = kwargs.get("sender")
    if sender:
        try:
            sender_hostname = sender.hostname
        except AttributeError:
            sender_hostname = vars(sender.request).get("origin", "unknown")
    if request and not isinstance(
        request, Context
    ):  # unlike others, task_revoked sends a Context for `request`
        task_name = request.name
        task_id = request.id
        receiver_hostname = request.hostname
    else:
        task_name = sender.name
        task_id = sender.request.id
        receiver_hostname = sender.request.hostname

    tags = {
        "task_name": task_name,
        "task_id": task_id,
        "sender_hostname": sender_hostname,
        "receiver_hostname": receiver_hostname,
    }
    if kwargs.get("exception"):
        tags["error"] = repr(kwargs["exception"])
    return tags


@celery_app.task()
def report_celery_last_success_metrics():
    """
    For each celery task, this will determine the number of seconds since it has last been successful.

    Celery tasks should be emitting redis stats with a deterministic key (In our case, `f"{task}.last_success"`.
    report_celery_last_success_metrics should be ran periodically to emit metrics on when a task was last successful.
    Admins can then alert when tasks are not ran when intended. Admins should also alert when no metrics are emitted
    from this function.
    """
    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    task_id = None
    if celery_app.current_task:
        task_id = celery_app.current_task.request.id

    log_data = {
        "function": function,
        "message": "recurrent task",
        "task_id": task_id,
    }

    if task_id and is_task_active(function, task_id, None):
        log_data["message"] = "Skipping task: Task is already active"
        current_app.logger.debug(log_data)
        return

    current_time = int(time.time())
    schedule = current_app.config.get("CELERYBEAT_SCHEDULE")
    for _, t in schedule.items():
        task = t.get("task")
        last_success = int(red.get(f"{task}.last_success") or 0)
        metrics.send(
            f"{task}.time_since_last_success", "gauge", current_time - last_success
        )
    red.set(
        f"{function}.last_success", int(time.time())
    )  # Alert if this metric is not seen
    metrics.send(f"{function}.success", "counter", 1)


@task_received.connect
def report_number_pending_tasks(**kwargs):
    """
    Report the number of pending tasks to our metrics broker every time a task is published. This metric can be used
    for autoscaling workers.
    https://docs.celeryproject.org/en/latest/userguide/signals.html#task-received
    """
    with flask_app.app_context():
        metrics.send(
            "celery.new_pending_task",
            "TIMER",
            1,
            metric_tags=get_celery_request_tags(**kwargs),
        )


@task_success.connect
def report_successful_task(**kwargs):
    """
    Report a generic success metric as tasks to our metrics broker every time a task finished correctly.
    This metric can be used for autoscaling workers.
    https://docs.celeryproject.org/en/latest/userguide/signals.html#task-success
    """
    with flask_app.app_context():
        tags = get_celery_request_tags(**kwargs)
        red.set(f"{tags['task_name']}.last_success", int(time.time()))
        metrics.send("celery.successful_task", "TIMER", 1, metric_tags=tags)


@task_failure.connect
def report_failed_task(**kwargs):
    """
    Report a generic failure metric as tasks to our metrics broker every time a task fails.
    This metric can be used for alerting.
    https://docs.celeryproject.org/en/latest/userguide/signals.html#task-failure
    """
    with flask_app.app_context():
        log_data = {
            "function": f"{__name__}.{sys._getframe().f_code.co_name}",
            "message": "Celery Task Failure",
        }

        # Add traceback if exception info is in the kwargs
        einfo = kwargs.get("einfo")
        if einfo:
            log_data["traceback"] = einfo.traceback

        error_tags = get_celery_request_tags(**kwargs)

        log_data.update(error_tags)
        current_app.logger.error(log_data)
        metrics.send("celery.failed_task", "TIMER", 1, metric_tags=error_tags)


@task_revoked.connect
def report_revoked_task(**kwargs):
    """
    Report a generic failure metric as tasks to our metrics broker every time a task is revoked.
    This metric can be used for alerting.
    https://docs.celeryproject.org/en/latest/userguide/signals.html#task-revoked
    """
    with flask_app.app_context():
        log_data = {
            "function": f"{__name__}.{sys._getframe().f_code.co_name}",
            "message": "Celery Task Revoked",
        }

        error_tags = get_celery_request_tags(**kwargs)

        log_data.update(error_tags)
        current_app.logger.error(log_data)
        metrics.send("celery.revoked_task", "TIMER", 1, metric_tags=error_tags)


@celery_app.task(soft_time_limit=600)
def fetch_acme_cert(id, notify_reissue_cert_id=None):
    """
    Attempt to get the full certificate for the pending certificate listed.

    Args:
        id: an id of a PendingCertificate
        notify_reissue_cert_id: ID of existing Certificate to use for reissue notifications, if supplied
    """
    task_id = None
    if celery_app.current_task:
        task_id = celery_app.current_task.request.id

    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    log_data = {
        "function": function,
        "message": f"Resolving pending certificate {id}",
        "task_id": task_id,
        "id": id,
    }

    current_app.logger.debug(log_data)

    if task_id and is_task_active(log_data["function"], task_id, (id,)):
        log_data["message"] = "Skipping task: Task is already active"
        current_app.logger.debug(log_data)
        return

    pending_certs = pending_certificate_service.get_pending_certs([id])
    new = 0
    failed = 0
    wrong_issuer = 0
    acme_certs = []

    # We only care about certs using the acme-issuer plugin
    for cert in pending_certs:
        cert_authority = get_authority(cert.authority_id)
        if cert_authority.plugin_name == "acme-issuer":
            acme_certs.append(cert)
        else:
            wrong_issuer += 1

    authority = plugins.get("acme-issuer")
    resolved_certs = authority.get_ordered_certificates(acme_certs)

    for cert in resolved_certs:
        real_cert = cert.get("cert")
        # It's necessary to reload the pending cert due to detached instance: http://sqlalche.me/e/bhk3
        pending_cert = pending_certificate_service.get(cert.get("pending_cert").id)
        if not pending_cert or pending_cert.resolved:
            # pending_cert is cleared or it was resolved by another process
            log_data[
                "message"
            ] = "Pending certificate doesn't exist anymore. Was it resolved by another process?"
            current_app.logger.error(log_data)
            continue
        if real_cert:
            # If a real certificate was returned from issuer, then create it in Lemur and mark
            # the pending certificate as resolved
            final_cert = pending_certificate_service.create_certificate(
                pending_cert, real_cert, pending_cert.user
            )
            pending_certificate_service.update(
                cert.get("pending_cert").id, resolved_cert_id=final_cert.id
            )
            pending_certificate_service.update(
                cert.get("pending_cert").id, resolved=True
            )
            if notify_reissue_cert_id is not None:
                notify_reissue_cert = certificate_service.get(notify_reissue_cert_id)
                send_reissue_no_endpoints_notification(notify_reissue_cert, final_cert)
            # add metrics to metrics extension
            new += 1
        else:
            failed += 1
            error_log = copy.deepcopy(log_data)
            error_log["message"] = "Pending certificate creation failure"
            error_log["pending_cert_id"] = pending_cert.id
            error_log["last_error"] = cert.get("last_error")
            error_log["cn"] = pending_cert.cn

            if pending_cert.number_attempts > ACME_ADDITIONAL_ATTEMPTS:
                error_log["message"] = "Deleting pending certificate"
                send_pending_failure_notification(
                    pending_cert, notify_owner=pending_cert.notify
                )
                if notify_reissue_cert_id is not None:
                    send_reissue_failed_notification(pending_cert)
                # Mark the pending cert as resolved
                pending_certificate_service.update(
                    cert.get("pending_cert").id, resolved=True
                )
            else:
                pending_certificate_service.increment_attempt(pending_cert)
                pending_certificate_service.update(
                    cert.get("pending_cert").id, status=str(cert.get("last_error"))
                )
                # Add failed pending cert task back to queue
                fetch_acme_cert.delay(id, notify_reissue_cert_id)
            current_app.logger.error(error_log)
    log_data["message"] = "Complete"
    log_data["new"] = new
    log_data["failed"] = failed
    log_data["wrong_issuer"] = wrong_issuer
    current_app.logger.debug(log_data)
    metrics.send(f"{function}.resolved", "gauge", new)
    metrics.send(f"{function}.failed", "gauge", failed)
    metrics.send(f"{function}.wrong_issuer", "gauge", wrong_issuer)
    print(
        "[+] Certificates: New: {new} Failed: {failed} Not using ACME: {wrong_issuer}".format(
            new=new, failed=failed, wrong_issuer=wrong_issuer
        )
    )
    return log_data


@celery_app.task()
def fetch_all_pending_acme_certs():
    """Instantiate celery workers to resolve all pending Acme certificates"""

    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    task_id = None
    if celery_app.current_task:
        task_id = celery_app.current_task.request.id

    log_data = {
        "function": function,
        "message": "Starting job.",
        "task_id": task_id,
    }

    if task_id and is_task_active(function, task_id, None):
        log_data["message"] = "Skipping task: Task is already active"
        current_app.logger.debug(log_data)
        return

    current_app.logger.debug(log_data)
    pending_certs = pending_certificate_service.get_unresolved_pending_certs()

    # We only care about certs using the acme-issuer plugin
    for cert in pending_certs:
        cert_authority = get_authority(cert.authority_id)
        if cert_authority.plugin_name == "acme-issuer":
            if datetime.now(timezone.utc) - cert.last_updated > timedelta(minutes=5):
                log_data["message"] = f"Triggering job for cert {cert.name}"
                log_data["cert_name"] = cert.name
                log_data["cert_id"] = cert.id
                current_app.logger.debug(log_data)
                fetch_acme_cert.delay(cert.id)

    metrics.send(f"{function}.success", "counter", 1)
    return log_data


@celery_app.task()
def remove_old_acme_certs():
    """Prune old pending acme certificates from the database"""
    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    task_id = None
    if celery_app.current_task:
        task_id = celery_app.current_task.request.id

    log_data = {
        "function": function,
        "message": "Starting job.",
        "task_id": task_id,
    }

    if task_id and is_task_active(function, task_id, None):
        log_data["message"] = "Skipping task: Task is already active"
        current_app.logger.debug(log_data)
        return

    pending_certs = pending_certificate_service.get_pending_certs("all")

    # Delete pending certs more than a week old
    for cert in pending_certs:
        if datetime.now(timezone.utc) - cert.last_updated > timedelta(days=7):
            log_data["pending_cert_id"] = cert.id
            log_data["pending_cert_name"] = cert.name
            log_data["message"] = "Deleting pending certificate"
            current_app.logger.debug(log_data)
            pending_certificate_service.delete(cert)

    metrics.send(f"{function}.success", "counter", 1)
    return log_data


@celery_app.task()
def clean_all_sources():
    """
    This function will clean unused certificates from sources. This is a destructive operation and should only
    be ran periodically. This function triggers one celery task per source.
    """
    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    task_id = None
    if celery_app.current_task:
        task_id = celery_app.current_task.request.id

    log_data = {
        "function": function,
        "message": "Creating celery task to clean source",
        "task_id": task_id,
    }

    if task_id and is_task_active(function, task_id, None):
        log_data["message"] = "Skipping task: Task is already active"
        current_app.logger.debug(log_data)
        return

    sources = validate_sources("all")
    for source in sources:
        log_data["source"] = source.label
        current_app.logger.debug(log_data)
        clean_source.delay(source.label)

    metrics.send(f"{function}.success", "counter", 1)
    return log_data


@celery_app.task(soft_time_limit=3600)
def clean_source(source):
    """
    This celery task will clean the specified source. This is a destructive operation that will delete unused
    certificates from each source.

    :param source:
    :return:
    """
    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    task_id = None
    if celery_app.current_task:
        task_id = celery_app.current_task.request.id

    log_data = {
        "function": function,
        "message": "Cleaning source",
        "source": source,
        "task_id": task_id,
    }

    if task_id and is_task_active(function, task_id, (source,)):
        log_data["message"] = "Skipping task: Task is already active"
        current_app.logger.debug(log_data)
        return

    current_app.logger.debug(log_data)
    try:
        clean([source], True)
    except SoftTimeLimitExceeded:
        log_data["message"] = "Clean source: Time limit exceeded."
        current_app.logger.error(log_data)
        capture_exception()
        metrics.send("celery.timeout", "counter", 1, metric_tags={"function": function})
    return log_data


@celery_app.task()
def sync_all_sources():
    """
    This function will sync certificates from all sources. This function triggers one celery task per source.
    """
    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    task_id = None
    if celery_app.current_task:
        task_id = celery_app.current_task.request.id

    log_data = {
        "function": function,
        "message": "creating celery task to sync source",
        "task_id": task_id,
    }

    if task_id and is_task_active(function, task_id, None):
        log_data["message"] = "Skipping task: Task is already active"
        current_app.logger.debug(log_data)
        return

    sources = validate_sources("all")
    for source in sources:
        log_data["source"] = source.label
        current_app.logger.debug(log_data)
        sync_source.delay(source.label)

    metrics.send(f"{function}.success", "counter", 1)
    return log_data


@celery_app.task(soft_time_limit=7200)
def sync_source(source):
    """
    This celery task will sync the specified source.

    :param source:
    :return:
    """

    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    task_id = None
    if celery_app.current_task:
        task_id = celery_app.current_task.request.id

    log_data = {
        "function": function,
        "message": "Syncing source",
        "source": source,
        "task_id": task_id,
    }

    if task_id and is_task_active(function, task_id, (source,)):
        log_data["message"] = "Skipping task: Task is already active"
        current_app.logger.debug(log_data)
        return

    current_app.logger.debug(log_data)
    try:
        sync([source], current_app.config.get("CELERY_ENDPOINTS_EXPIRE_TIME_IN_HOURS", 2))
        metrics.send(
            f"{function}.success", "counter", 1, metric_tags={"source": source}
        )
    except SoftTimeLimitExceeded:
        log_data["message"] = "Error syncing source: Time limit exceeded."
        current_app.logger.error(log_data)
        capture_exception()
        metrics.send(
            "sync_source_timeout", "counter", 1, metric_tags={"source": source}
        )
        metrics.send("celery.timeout", "counter", 1, metric_tags={"function": function})
        return

    log_data["message"] = "Done syncing source"
    current_app.logger.debug(log_data)
    metrics.send(f"{function}.success", "counter", 1, metric_tags={"source": source})
    return log_data


@celery_app.task(soft_time_limit=3600)
def certificate_reissue():
    """
    This celery task reissues certificates which are pending reissue
    :return:
    """
    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    task_id = None
    if celery_app.current_task:
        task_id = celery_app.current_task.request.id

    log_data = {
        "function": function,
        "message": "reissuing certificates",
        "task_id": task_id,
    }

    if task_id and is_task_active(function, task_id, None):
        log_data["message"] = "Skipping task: Task is already active"
        current_app.logger.debug(log_data)
        return

    current_app.logger.debug(log_data)
    try:
        notify = current_app.config.get("ENABLE_REISSUE_NOTIFICATION", None)
        cli_certificate.reissue(None, notify, True)
    except SoftTimeLimitExceeded:
        log_data["message"] = "Certificate reissue: Time limit exceeded."
        current_app.logger.error(log_data)
        capture_exception()
        metrics.send("celery.timeout", "counter", 1, metric_tags={"function": function})
        return

    log_data["message"] = "reissuance completed"
    current_app.logger.debug(log_data)
    metrics.send(f"{function}.success", "counter", 1)
    return log_data


@celery_app.task(soft_time_limit=3600)
def certificate_rotate(**kwargs):

    """
    This celery task rotates certificates which are reissued but having endpoints attached to the replaced cert
    :return:
    """
    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    task_id = None
    if celery_app.current_task:
        task_id = celery_app.current_task.request.id

    region = kwargs.get("region")
    log_data = {
        "function": function,
        "message": "rotating certificates",
        "task_id": task_id,
    }

    if task_id and is_task_active(function, task_id, None):
        log_data["message"] = "Skipping task: Task is already active"
        current_app.logger.debug(log_data)
        return

    current_app.logger.debug(log_data)
    try:
        notify = current_app.config.get("ENABLE_ROTATION_NOTIFICATION", None)
        if region:
            log_data["region"] = region
            cli_certificate.rotate_region(None, None, None, notify, True, region)
        else:
            cli_certificate.rotate(None, None, None, None, notify, True)
    except SoftTimeLimitExceeded:
        log_data["message"] = "Certificate rotate: Time limit exceeded."
        current_app.logger.error(log_data)
        capture_exception()
        metrics.send("celery.timeout", "counter", 1, metric_tags={"function": function})
        return

    log_data["message"] = "rotation completed"
    current_app.logger.debug(log_data)
    metrics.send(f"{function}.success", "counter", 1)
    return log_data


@celery_app.task(soft_time_limit=600)
def get_all_zones():
    """
    This celery syncs all zones from the available dns providers
    :return:
    """
    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    task_id = None
    if celery_app.current_task:
        task_id = celery_app.current_task.request.id

    log_data = {
        "function": function,
        "message": "refresh all zones from available DNS providers",
        "task_id": task_id,
    }

    if task_id and is_task_active(function, task_id, None):
        log_data["message"] = "Skipping task: Task is already active"
        current_app.logger.debug(log_data)
        return

    current_app.logger.debug(log_data)
    try:
        cli_dns_providers.get_all_zones()
    except SoftTimeLimitExceeded:
        log_data["message"] = "get all zones: Time limit exceeded."
        current_app.logger.error(log_data)
        capture_exception()
        metrics.send("celery.timeout", "counter", 1, metric_tags={"function": function})
        return

    metrics.send(f"{function}.success", "counter", 1)
    return log_data


@celery_app.task(soft_time_limit=7200)
def check_revoked():
    """
    This celery task attempts to check if any certs are expired
    :return:
    """
    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    task_id = None
    if celery_app.current_task:
        task_id = celery_app.current_task.request.id

    log_data = {
        "function": function,
        "message": "check if any valid certificate is revoked",
        "task_id": task_id,
    }

    if task_id and is_task_active(function, task_id, None):
        log_data["message"] = "Skipping task: Task is already active"
        current_app.logger.debug(log_data)
        return

    current_app.logger.debug(log_data)
    try:
        cli_certificate.check_revoked()
    except SoftTimeLimitExceeded:
        log_data["message"] = "Checking revoked: Time limit exceeded."
        current_app.logger.error(log_data)
        capture_exception()
        metrics.send("celery.timeout", "counter", 1, metric_tags={"function": function})
        return

    metrics.send(f"{function}.success", "counter", 1)
    return log_data


@celery_app.task(soft_time_limit=3600)
def notify_expirations():
    """
    This celery task notifies about expiring certs
    :return:
    """
    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    task_id = None
    if celery_app.current_task:
        task_id = celery_app.current_task.request.id

    log_data = {
        "function": function,
        "message": "notify for cert expiration",
        "task_id": task_id,
    }

    if task_id and is_task_active(function, task_id, None):
        log_data["message"] = "Skipping task: Task is already active"
        current_app.logger.debug(log_data)
        return

    current_app.logger.debug(log_data)
    try:
        cli_notification.expirations(
            current_app.config.get("EXCLUDE_CN_FROM_NOTIFICATION", []),
            current_app.config.get("DISABLE_NOTIFICATION_PLUGINS", [])
        )
    except SoftTimeLimitExceeded:
        log_data["message"] = "Notify expiring Time limit exceeded."
        current_app.logger.error(log_data)
        capture_exception()
        metrics.send("celery.timeout", "counter", 1, metric_tags={"function": function})
        return

    metrics.send(f"{function}.success", "counter", 1)
    return log_data


@celery_app.task(soft_time_limit=3600)
def notify_authority_expirations():
    """
    This celery task notifies about expiring certificate authority certs
    :return:
    """
    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    task_id = None
    if celery_app.current_task:
        task_id = celery_app.current_task.request.id

    log_data = {
        "function": function,
        "message": "notify for certificate authority cert expiration",
        "task_id": task_id,
    }

    if task_id and is_task_active(function, task_id, None):
        log_data["message"] = "Skipping task: Task is already active"
        current_app.logger.debug(log_data)
        return

    current_app.logger.debug(log_data)
    try:
        cli_notification.authority_expirations()
    except SoftTimeLimitExceeded:
        log_data["message"] = "Notify expiring CA Time limit exceeded."
        current_app.logger.error(log_data)
        capture_exception()
        metrics.send("celery.timeout", "counter", 1, metric_tags={"function": function})
        return

    metrics.send(f"{function}.success", "counter", 1)
    return log_data


@celery_app.task(soft_time_limit=3600)
def send_security_expiration_summary():
    """
    This celery task sends a summary about expiring certificates to the security team.
    :return:
    """
    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    task_id = None
    if celery_app.current_task:
        task_id = celery_app.current_task.request.id

    log_data = {
        "function": function,
        "message": "send summary for certificate expiration",
        "task_id": task_id,
    }

    if task_id and is_task_active(function, task_id, None):
        log_data["message"] = "Skipping task: Task is already active"
        current_app.logger.debug(log_data)
        return

    current_app.logger.debug(log_data)
    try:
        cli_notification.security_expiration_summary(current_app.config.get("EXCLUDE_CN_FROM_NOTIFICATION", []))
    except SoftTimeLimitExceeded:
        log_data["message"] = "Send summary for expiring certs Time limit exceeded."
        current_app.logger.error(log_data)
        capture_exception()
        metrics.send("celery.timeout", "counter", 1, metric_tags={"function": function})
        return

    metrics.send(f"{function}.success", "counter", 1)
    return log_data


@celery_app.task(soft_time_limit=3600)
def enable_autorotate_for_certs_attached_to_endpoint():
    """
    This celery task automatically enables autorotation for unexpired certificates that are
    attached to an endpoint but do not have autorotate enabled.
    :return:
    """
    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    task_id = None
    if celery_app.current_task:
        task_id = celery_app.current_task.request.id

    log_data = {
        "function": function,
        "task_id": task_id,
        "message": "Enabling autorotate to eligible certificates",
    }
    current_app.logger.debug(log_data)

    cli_certificate.automatically_enable_autorotate_with_endpoint()
    metrics.send(f"{function}.success", "counter", 1)
    return log_data


@celery_app.task(soft_time_limit=3600)
def enable_autorotate_for_certs_attached_to_destination():
    """
    This celery task automatically enables autorotation for unexpired certificates that are
    attached to at least one destination but do not have autorotate enabled.
    :return:
    """
    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    task_id = None
    if celery_app.current_task:
        task_id = celery_app.current_task.request.id

    log_data = {
        "function": function,
        "task_id": task_id,
        "message": "Enabling autorotate to eligible certificates",
    }
    current_app.logger.debug(log_data)

    cli_certificate.automatically_enable_autorotate_with_destination()
    metrics.send(f"{function}.success", "counter", 1)
    return log_data


@celery_app.task(soft_time_limit=3600)
def deactivate_entrust_test_certificates():
    """
    This celery task attempts to deactivate all not yet deactivated Entrust certificates, and should only run in TEST
    :return:
    """
    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    task_id = None
    if celery_app.current_task:
        task_id = celery_app.current_task.request.id

    log_data = {
        "function": function,
        "message": "deactivate entrust certificates",
        "task_id": task_id,
    }

    if task_id and is_task_active(function, task_id, None):
        log_data["message"] = "Skipping task: Task is already active"
        current_app.logger.debug(log_data)
        return

    current_app.logger.debug(log_data)
    try:
        cli_certificate.deactivate_entrust_certificates()
    except SoftTimeLimitExceeded:
        log_data["message"] = "Time limit exceeded."
        current_app.logger.error(log_data)
        capture_exception()
        metrics.send("celery.timeout", "counter", 1, metric_tags={"function": function})
        return

    metrics.send(f"{function}.success", "counter", 1)
    return log_data


@celery_app.task(soft_time_limit=3600)
def disable_rotation_of_duplicate_certificates():
    """
    We occasionally get duplicate certificates with Let's encrypt. Figure out the set of duplicate certificates and
    disable auto-rotate if no endpoint is attached to the certificate. This way only the certificate with endpoints
    will get auto-rotated. If none of the certs have endpoint attached, to be on the safe side, keep auto rotate ON
    for one of the certs. This task considers all the certificates issued by the authorities listed in the config
    AUTHORITY_TO_DISABLE_ROTATE_OF_DUPLICATE_CERTIFICATES
    Determining duplicate certificates: certificates sharing same name prefix (followed by serial number to make it
    unique) which have same validity length (issuance and expiration), owner, destination, SANs.
    :return:
    """

    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    task_id = None
    if celery_app.current_task:
        task_id = celery_app.current_task.request.id

    log_data = {
        "function": function,
        "message": "Disable rotation of duplicate certs issued by Let's Encrypt",
        "task_id": task_id,
    }

    if task_id and is_task_active(function, task_id, None):
        log_data["message"] = "Skipping task: Task is already active"
        current_app.logger.debug(log_data)
        return

    current_app.logger.debug(log_data)
    try:
        cli_certificate.disable_rotation_of_duplicate_certificates(True)
    except SoftTimeLimitExceeded:
        log_data["message"] = "Time limit exceeded."
        current_app.logger.error(log_data)
        capture_exception()
        metrics.send("celery.timeout", "counter", 1, metric_tags={"function": function})
        return
    except Exception as e:
        current_app.logger.info(log_data)
        capture_exception()
        current_app.logger.exception(e)
        return

    metrics.send(f"{function}.success", "counter", 1)


@celery_app.task(soft_time_limit=3600)
def notify_expiring_deployed_certificates():
    """
    This celery task attempts to find any certificates that are expiring soon but are still deployed,
    and notifies the security team.
    """
    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    task_id = None
    if celery_app.current_task:
        task_id = celery_app.current_task.request.id

    log_data = {
        "function": function,
        "message": "notify expiring deployed certificates",
        "task_id": task_id,
    }

    if task_id and is_task_active(function, task_id, None):
        log_data["message"] = "Skipping task: Task is already active"
        current_app.logger.debug(log_data)
        return

    current_app.logger.debug(log_data)
    try:
        cli_notification.notify_expiring_deployed_certificates(
            current_app.config.get("EXCLUDE_CN_FROM_NOTIFICATION", [])
        )
    except SoftTimeLimitExceeded:
        log_data["message"] = "Time limit exceeded."
        current_app.logger.error(log_data)
        capture_exception()
        metrics.send("celery.timeout", "counter", 1, metric_tags={"function": function})
        return

    metrics.send(f"{function}.success", "counter", 1)
    return log_data


@celery_app.task(soft_time_limit=10800)  # 3 hours
def identity_expiring_deployed_certificates():
    """
    DEPRECATED: Use identify_expiring_deployed_certificates instead.
    """
    current_app.logger.warn("identity_expiring_deployed_certificates is deprecated and will be removed in a future release, please use identify_expiring_deployed_certificates instead")
    return identify_expiring_deployed_certificates()


@celery_app.task(soft_time_limit=10800)  # 3 hours
def identify_expiring_deployed_certificates():
    """
    This celery task attempts to find any certificates that are expiring soon but are still deployed,
    and stores information on which port(s) the certificate is currently being used for TLS.
    """
    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    task_id = None
    if celery_app.current_task:
        task_id = celery_app.current_task.request.id

    log_data = {
        "function": function,
        "message": "identify expiring deployed certificates",
        "task_id": task_id,
    }

    if task_id and is_task_active(function, task_id, None):
        log_data["message"] = "Skipping task: Task is already active"
        current_app.logger.debug(log_data)
        return

    current_app.logger.debug(log_data)
    try:
        exclude_domains = current_app.config.get("LEMUR_DEPLOYED_CERTIFICATE_CHECK_EXCLUDED_DOMAINS", [])
        exclude_owners = current_app.config.get("LEMUR_DEPLOYED_CERTIFICATE_CHECK_EXCLUDED_OWNERS", [])
        commit = current_app.config.get("LEMUR_DEPLOYED_CERTIFICATE_CHECK_COMMIT_MODE", False)
        cli_certificate.identify_expiring_deployed_certificates(exclude_domains, exclude_owners, commit)
    except SoftTimeLimitExceeded:
        log_data["message"] = "Time limit exceeded."
        current_app.logger.error(log_data)
        capture_exception()
        metrics.send("celery.timeout", "counter", 1, metric_tags={"function": function})
        return

    metrics.send(f"{function}.success", "counter", 1)
    return log_data


@celery_app.task(soft_time_limit=3600)
def certificate_expirations_metrics():
    """
    This celery task iterates over all eligible certificates and emits a metric for the days remaining for a certificate to expire.
    This is used for building custom dashboards and alerts for certificate expiry.
    """

    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    task_id = None
    if celery_app.current_task:
        task_id = celery_app.current_task.request.id

    log_data = {
        "function": function,
        "message": "sending metrics for expiring certificates",
        "task_id": task_id,
    }

    if task_id and is_task_active(function, task_id, None):
        log_data["message"] = "Skipping task: Task is already active"
        current_app.logger.debug(log_data)
        return

    try:
        cli_certificate.expiration_metrics(
            current_app.config.get("CERTIFICATE_EXPIRY_WINDOW_FOR_METRICS", None)
        )
    except SoftTimeLimitExceeded:
        log_data["message"] = "Time limit exceeded."
        current_app.logger.error(log_data)
        capture_exception()
        metrics.send("celery.timeout", "counter", 1, metric_tags={"function": function})
        return

    metrics.send(f"{function}.success", "counter", 1)
    return log_data
