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
import logging
from celery import Celery
from celery.app.task import Context
from celery.exceptions import SoftTimeLimitExceeded
from celery.signals import task_failure, task_received, task_revoked, task_success
from datetime import datetime, timezone, timedelta
from flask import current_app

from lemur.authorities.service import get as get_authority
from lemur.certificates import cli as cli_certificate, service as certificate_service
from lemur.common.redis import RedisHandler
from lemur.destinations import service as destinations_service
from lemur.dns_providers import cli as cli_dns_providers
from lemur.endpoints import cli as cli_endpoints
from lemur.endpoints import service as endpoint_service
from lemur.extensions import metrics, sentry
from lemur.factory import create_app
from lemur.notifications import cli as cli_notification
from lemur.notifications.messaging import send_pending_failure_notification
from lemur.pending_certificates import service as pending_certificate_service
from lemur.plugins.base import plugins
from lemur.sources.cli import clean, sync, validate_sources
from lemur.sources.service import add_aws_destination_to_sources
from lemur.sources import service as source_service
from lemur.users import service as user_service

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


celery = make_celery(flask_app)


def is_task_active(fun, task_id, args):
    from celery.task.control import inspect

    if not args:
        args = "()"  # empty args

    i = inspect()
    active_tasks = i.active()
    for _, tasks in active_tasks.items():
        for task in tasks:
            if task.get("id") == task_id:
                continue
            if task.get("name") == fun and task.get("args") == str(args):
                return True
    return False


def is_task_scheduled(fun, args):
    from celery.task.control import inspect
    i = inspect()
    for _, tasks in i.scheduled().items():
        for task in tasks:
            task_req = task.get("request", {})
            if task_req.get("name") == fun and task_req.get("args") == list(args):
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


@celery.task()
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
    if celery.current_task:
        task_id = celery.current_task.request.id

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
            "Message": "Celery Task Failure",
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
            "Message": "Celery Task Revoked",
        }

        error_tags = get_celery_request_tags(**kwargs)

        log_data.update(error_tags)
        current_app.logger.error(log_data)
        metrics.send("celery.revoked_task", "TIMER", 1, metric_tags=error_tags)

@celery.task(soft_time_limit=600)
def fetch_cert(id):
    """
    Attempt to get the full certificate for the pending certificate listed.

    Args:
        id: an id of a PendingCertificate
    """
    task_id = None
    if celery.current_task:
        task_id = celery.current_task.request.id

    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    log_data = {
        "function": function,
        "message": "Resolving pending certificate {}".format(id),
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
    for cert in pending_certs:
        cert_authority = get_authority(cert.authority_id)
        if cert_authority.plugin_name == "acme-issuer":
            current_app.log.warning("Skipping acme cert (use `fetch_acme_cert()` instead).")
            continue
        plugin = plugins.get(cert_authority.plugin_name)
        real_cert = plugin.get_ordered_certificate(cert)
        if real_cert:
            # If a real certificate was returned from issuer, then create it in
            # Lemur and mark the pending certificate as resolved
            final_cert = pending_certificate_service.create_certificate(
                cert, real_cert, cert.user
            )
            pending_certificate_service.update(cert.id, resolved_cert_id=final_cert.id)
            pending_certificate_service.update(cert.id, resolved=True)
            # add metrics to metrics extension
            new += 1
        else:
            # Double check the pending certificate still exists in the database
            # before updating the failed attempt counter
            if not pending_certificate_service.get(cert.id):
                current_app.logger.info(f"Not incrementing failed attempt counter because {cert.name} was cancelled before.")
            else:
                pending_certificate_service.increment_attempt(cert)
                failed += 1
    log_data["message"] = "Complete"
    log_data["new"] = new
    log_data["failed"] = failed
    current_app.logger.debug(log_data)
    metrics.send(f"{function}.resolved", "gauge", new)
    metrics.send(f"{function}.failed", "gauge", failed)
    print(f"[+] Certificates: New: {new} Failed: {failed}")
    return log_data


@celery.task(soft_time_limit=600)
def fetch_acme_cert(id):
    """
    Attempt to get the full certificate for the pending certificate listed.

    Args:
        id: an id of a PendingCertificate
    """
    task_id = None
    if celery.current_task:
        task_id = celery.current_task.request.id

    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    log_data = {
        "function": function,
        "message": "Resolving pending certificate {}".format(id),
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
        if not pending_cert:
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
            # add metrics to metrics extension
            new += 1
        else:
            failed += 1
            error_log = copy.deepcopy(log_data)
            error_log["message"] = "Pending certificate creation failure"
            error_log["pending_cert_id"] = pending_cert.id
            error_log["last_error"] = cert.get("last_error")
            error_log["cn"] = pending_cert.cn

            if pending_cert.number_attempts > 4:
                error_log["message"] = "Deleting pending certificate"
                send_pending_failure_notification(
                    pending_cert, notify_owner=pending_cert.notify
                )
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
                fetch_acme_cert.delay(id)
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


@celery.task()
def fetch_all_pending_acme_certs():
    """Instantiate celery workers to resolve all pending Acme certificates"""

    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    task_id = None
    if celery.current_task:
        task_id = celery.current_task.request.id

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
                log_data["message"] = "Triggering job for cert {}".format(cert.name)
                log_data["cert_name"] = cert.name
                log_data["cert_id"] = cert.id
                current_app.logger.debug(log_data)
                fetch_acme_cert.delay(cert.id)

    metrics.send(f"{function}.success", "counter", 1)
    return log_data


@celery.task()
def remove_old_acme_certs():
    """Prune old pending acme certificates from the database"""
    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    task_id = None
    if celery.current_task:
        task_id = celery.current_task.request.id

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


@celery.task()
def fetch_all_pending_certs():
    """Instantiate celery workers to resolve all  certificates"""

    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    task_id = None
    if celery.current_task:
        task_id = celery.current_task.request.id

    log_data = {
        "function": function,
        "message": "Starting fetching all pending certs.",
        "task_id": task_id,
    }

    if task_id and is_task_active(function, task_id, None):
        log_data["message"] = "Skipping task: Task is already active"
        current_app.logger.debug(log_data)
        return

    current_app.logger.debug(log_data)
    pending_certs = pending_certificate_service.get_unresolved_pending_certs()

    for cert in pending_certs:
        cert_authority = get_authority(cert.authority_id)
        # handle only certs from non-acme issuers, as acme certs are specially
        #  taken care of in the `fetach_all_pending_acme_certs` function
        if cert_authority.plugin_name != "acme-issuer":
            log_data["message"] = "Triggering job for cert {}".format(cert.name)
            log_data["cert_name"] = cert.name
            log_data["cert_id"] = cert.id
            current_app.logger.debug(log_data)
            fetch_cert.delay(cert.id)

    metrics.send(f"{function}.success", "counter", 1)
    return log_data


@celery.task()
def clean_all_sources():
    """
    This function will clean unused certificates from sources. This is a destructive operation and should only
    be ran periodically. This function triggers one celery task per source.
    """
    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    task_id = None
    if celery.current_task:
        task_id = celery.current_task.request.id

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


@celery.task(soft_time_limit=3600)
def clean_source(source):
    """
    This celery task will clean the specified source. This is a destructive operation that will delete unused
    certificates from each source.

    :param source:
    :return:
    """
    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    task_id = None
    if celery.current_task:
        task_id = celery.current_task.request.id

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
        sentry.captureException()
        metrics.send("celery.timeout", "counter", 1, metric_tags={"function": function})
    return log_data


@celery.task()
def sync_all_sources():
    """
    This function will sync certificates from all sources. This function triggers one celery task per source.
    """
    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    task_id = None
    if celery.current_task:
        task_id = celery.current_task.request.id

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


@celery.task(soft_time_limit=60)
def sync_source(source_label):
    """
    This celery task will sync the specified source.

    :param source:
    :return:
    """

    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    logger = logging.getLogger(function)

    task_id = None
    if celery.current_task:
        task_id = celery.current_task.request.id

    log_data = {
        "source": source_label,
        "task_id": task_id,
    }

    if task_id and is_task_active(function, task_id, (source_label,)):
        logger.debug("Skipping task: Task is already active", extra=log_data)
        return

    logger.info("Starting syncing source", extra=log_data)

    user = user_service.get_by_username("lemur")
    source = source_service.get_by_label(source_label)
    if not source:
        raise RuntimeError(f"Source {source_label} not found")

    result = source_service.sync(source, user)
    log_data["result"] = result

    logger.info("Done syncing source", extra=log_data)
    return


@celery.task()
def sync_source_destination():
    """
    This celery task will sync destination and source, to make sure all new destinations are also present as source.
    Some destinations do not qualify as sources, and hence should be excluded from being added as sources
    We identify qualified destinations based on the sync_as_source attributed of the plugin.
    The destination sync_as_source_name reveals the name of the suitable source-plugin.
    We rely on account numbers to avoid duplicates.
    """
    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    task_id = None
    if celery.current_task:
        task_id = celery.current_task.request.id

    log_data = {
        "function": function,
        "message": "syncing AWS destinations and sources",
        "task_id": task_id,
    }

    if task_id and is_task_active(function, task_id, None):
        log_data["message"] = "Skipping task: Task is already active"
        current_app.logger.debug(log_data)
        return

    current_app.logger.debug(log_data)
    for dst in destinations_service.get_all():
        if add_aws_destination_to_sources(dst):
            log_data["message"] = "new source added"
            log_data["source"] = dst.label
            current_app.logger.debug(log_data)

    log_data["message"] = "completed Syncing AWS destinations and sources"
    current_app.logger.debug(log_data)
    metrics.send(f"{function}.success", "counter", 1)
    return log_data


@celery.task(soft_time_limit=3600)
def certificate_reissue():
    """
    This celery task reissues certificates which are pending reissue
    :return:
    """
    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    task_id = None
    if celery.current_task:
        task_id = celery.current_task.request.id

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
        cli_certificate.reissue(None, True)
    except SoftTimeLimitExceeded:
        log_data["message"] = "Certificate reissue: Time limit exceeded."
        current_app.logger.error(log_data)
        sentry.captureException()
        metrics.send("celery.timeout", "counter", 1, metric_tags={"function": function})
        return

    log_data["message"] = "reissuance completed"
    current_app.logger.debug(log_data)
    metrics.send(f"{function}.success", "counter", 1)
    return log_data


@celery.task(soft_time_limit=3600)
def certificate_rotate(**kwargs):

    """
    This celery task rotates certificates which are reissued but having endpoints attached to the replaced cert
    :return:
    """
    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    task_id = None
    if celery.current_task:
        task_id = celery.current_task.request.id

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
            cli_certificate.rotate(None, None, None, notify, True)
    except SoftTimeLimitExceeded:
        log_data["message"] = "Certificate rotate: Time limit exceeded."
        current_app.logger.error(log_data)
        sentry.captureException()
        metrics.send("celery.timeout", "counter", 1, metric_tags={"function": function})
        return

    log_data["message"] = "rotation completed"
    current_app.logger.debug(log_data)
    metrics.send(f"{function}.success", "counter", 1)
    return log_data


@celery.task(soft_time_limit=3600)
def endpoints_expire():
    """
    This celery task removes all endpoints that have not been recently updated
    :return:
    """
    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    task_id = None
    if celery.current_task:
        task_id = celery.current_task.request.id

    log_data = {
        "function": function,
        "message": "endpoints expire",
        "task_id": task_id,
    }

    if task_id and is_task_active(function, task_id, None):
        log_data["message"] = "Skipping task: Task is already active"
        current_app.logger.debug(log_data)
        return

    current_app.logger.debug(log_data)
    try:
        cli_endpoints.expire(2)  # Time in hours
    except SoftTimeLimitExceeded:
        log_data["message"] = "endpoint expire: Time limit exceeded."
        current_app.logger.error(log_data)
        sentry.captureException()
        metrics.send("celery.timeout", "counter", 1, metric_tags={"function": function})
        return

    metrics.send(f"{function}.success", "counter", 1)
    return log_data


@celery.task(soft_time_limit=600)
def get_all_zones():
    """
    This celery syncs all zones from the available dns providers
    :return:
    """
    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    task_id = None
    if celery.current_task:
        task_id = celery.current_task.request.id

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
        sentry.captureException()
        metrics.send("celery.timeout", "counter", 1, metric_tags={"function": function})
        return

    metrics.send(f"{function}.success", "counter", 1)
    return log_data


@celery.task(soft_time_limit=3600)
def check_revoked():
    """
    This celery task attempts to check if any certs are expired
    :return:
    """
    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    task_id = None
    if celery.current_task:
        task_id = celery.current_task.request.id

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
        sentry.captureException()
        metrics.send("celery.timeout", "counter", 1, metric_tags={"function": function})
        return

    metrics.send(f"{function}.success", "counter", 1)
    return log_data


@celery.task(soft_time_limit=3600)
def notify_expirations():
    """
    This celery task notifies about expiring certs
    :return:
    """
    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    task_id = None
    if celery.current_task:
        task_id = celery.current_task.request.id

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
            current_app.config.get("EXCLUDE_CN_FROM_NOTIFICATION", [])
        )
    except SoftTimeLimitExceeded:
        log_data["message"] = "Notify expiring Time limit exceeded."
        current_app.logger.error(log_data)
        sentry.captureException()
        metrics.send("celery.timeout", "counter", 1, metric_tags={"function": function})
        return

    metrics.send(f"{function}.success", "counter", 1)
    return log_data


@celery.task(soft_time_limit=3600)
def notify_authority_expirations():
    """
    This celery task notifies about expiring certificate authority certs
    :return:
    """
    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    task_id = None
    if celery.current_task:
        task_id = celery.current_task.request.id

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
        sentry.captureException()
        metrics.send("celery.timeout", "counter", 1, metric_tags={"function": function})
        return

    metrics.send(f"{function}.success", "counter", 1)
    return log_data


@celery.task(soft_time_limit=3600)
def send_security_expiration_summary():
    """
    This celery task sends a summary about expiring certificates to the security team.
    :return:
    """
    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    task_id = None
    if celery.current_task:
        task_id = celery.current_task.request.id

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
        sentry.captureException()
        metrics.send("celery.timeout", "counter", 1, metric_tags={"function": function})
        return

    metrics.send(f"{function}.success", "counter", 1)
    return log_data


@celery.task(soft_time_limit=3600)
def enable_autorotate_for_certs_attached_to_endpoint():
    """
    This celery task automatically enables autorotation for unexpired certificates that are
    attached to an endpoint but do not have autorotate enabled.
    :return:
    """
    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    task_id = None
    if celery.current_task:
        task_id = celery.current_task.request.id

    log_data = {
        "function": function,
        "task_id": task_id,
        "message": "Enabling autorotate to eligible certificates",
    }
    current_app.logger.debug(log_data)

    cli_certificate.automatically_enable_autorotate()
    metrics.send(f"{function}.success", "counter", 1)
    return log_data


@celery.task(soft_time_limit=3600)
def deactivate_entrust_test_certificates():
    """
    This celery task attempts to deactivate all not yet deactivated Entrust certificates, and should only run in TEST
    :return:
    """
    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    task_id = None
    if celery.current_task:
        task_id = celery.current_task.request.id

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
        sentry.captureException()
        metrics.send("celery.timeout", "counter", 1, metric_tags={"function": function})
        return

    metrics.send(f"{function}.success", "counter", 1)
    return log_data


@celery.task(soft_time_limit=60)
def certificate_check_destination(cert_id, dest_id):
    """
    This celery task checks a certificate, destination pair
    to verify that the certficate has been uploaded and uploads
    it if it hasn't
    :return:
    """
    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    logger = logging.getLogger(function)
    task_id = None
    if celery.current_task:
        task_id = celery.current_task.request.id

    log_data = {
        "task_id": task_id,
    }

    if task_id and is_task_active(function, task_id, None):
        logger.debug("Skipping task: Task is already active", extra=log_data)
        return log_data

    cert = certificate_service.get(cert_id)
    dest = destinations_service.get(dest_id)

    if not cert:
        raise RuntimeError(f"certificate (id={cert_id}) does not exist in database")

    # populate log data
    log_data["certificate"] = cert.name
    log_data["destination"] = str(dest)

    logger.debug("verifying certificate/destination pair", extra=log_data)
    uploaded = dest.plugin.verify(cert.name, dest.options)
    if not uploaded:
        logger.info("uploading certificate to destination", extra=log_data)
        dest.plugin.upload(cert.name,
                        cert.body,
                        cert.private_key,
                        cert.chain,
                        dest.options)
        logger.info("certificate uploaded to destination", extra=log_data)
        metrics.send(f"{function}.destination_missing_cert_resolved", "counter", 1)

    # at this point, the certificate MUST exist on the destination
    logger.debug("certificate/destination pair valid", extra=log_data)
    metrics.send(f"{function}.destination_certificate_valid", "counter", 1)

    return log_data


@celery.task(soft_time_limit=60)
def create_certificate_check_destination_tasks():
    """
    This celery task fetches all (certificate, destination) pairs
    from Lemur and creates subtasks to verify that the certificate has
    been uploaded.
    :return:
    """
    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    logger = logging.getLogger(function)
    task_id = None
    if celery.current_task:
        task_id = celery.current_task.request.id

    log_data = {
        "task_id": task_id,
    }

    if task_id and is_task_active(function, task_id, None):
        logger.debug("Skipping task: Task is already active", extra=log_data)
        return log_data

    certs = certificate_service.get_all_valid_certs([])
    num_subtasks_created = 0
    for cert in certs:
        if cert.replaced or len(cert.destinations) == 0:
            continue

        for dest in cert.destinations:
            logger.debug("creating sub task to check certificate/destination pair", extra={
                "certificate": cert.name,
                "destination": str(dest),
            })
            certificate_check_destination.delay(cert.id, dest.id)
            num_subtasks_created += 1

    logger.debug("task creation completed",
                 extra={**log_data, "num_subtasks_created": num_subtasks_created})
    return log_data


def send_notifications(notifications, notification_type, message, **kwargs):
    for notification in notifications:
        notification.plugin.send(
            notification_type,
            message,
            None,
            notification.options,
            **kwargs)


@celery.task(soft_time_limit=60)
def rotate_endpoint(endpoint_id):
    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    logger = logging.getLogger(function)

    endpoint = endpoint_service.get(endpoint_id)

    if not endpoint:
        raise RuntimeError("endpoint did not exist")

    old_certificate_id = endpoint.certificate.id

    # schedule a task to remove it
    remove_cert_args = (endpoint_id, old_certificate_id)
    delay_before_removal = 60
    if is_task_scheduled(rotate_endpoint_remove_cert.name, remove_cert_args):
        # the remove task has already been scheduled so we skip this turn
        logger.info(f"{rotate_endpoint_remove_cert.name}{str(remove_cert_args)} already scheduled.")
        return

    new_cert_name = endpoint.certificate.replaced[0].name

    # send notification
    send_notifications(
        endpoint.certificate.notifications,
        "rotation",
        f"Rotating endpoint {endpoint.name}",
        endpoint=endpoint)

    logger.info(f"Attaching {new_cert_name} to {endpoint.name}")

    # update
    endpoint.source.plugin.update_endpoint(
        endpoint,
        new_cert_name)

    logger.info(f"Scheduling {rotate_endpoint_remove_cert.name}{str(remove_cert_args)} to execute in {delay_before_removal} seconds.")
    rotate_endpoint_remove_cert.apply_async(
        remove_cert_args,
        countdown=delay_before_removal)

    # sync source
    if not is_task_scheduled(sync_source, (endpoint.source.label,)):
        sync_source.delay(endpoint.source.label)


@celery.task(soft_time_limit=60)
def rotate_endpoint_remove_cert(endpoint_id, certificate_id):
    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    logger = logging.getLogger(function)

    endpoint = endpoint_service.get(endpoint_id)
    certificate = certificate_service.get(certificate_id)

    if not endpoint:
        # note: this can happen if this is scheduled twice
        raise RuntimeError("endpoint does not exist")

    if not certificate:
        raise RuntimeError("certificate does not exist")

    endpoint.source.plugin.remove_certificate(
        endpoint,
        certificate.name)

    # sync source
    if not is_task_scheduled(sync_source, (endpoint.source.label,)):
        sync_source.delay(endpoint.source.label)


@celery.task(soft_time_limit=60)
def rotate_all_pending_endpoints():
    """
    """
    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    logger = logging.getLogger(function)
    task_id = None
    if celery.current_task:
        task_id = celery.current_task.request.id

    log_data = {
        "task_id": task_id,
    }

    if task_id and is_task_active(function, task_id, None):
        logger.debug("Skipping task: Task is already active", extra=log_data)
        return

    for endpoint in endpoint_service.get_all_pending_rotation():
        logger.info(f"Creating task to rotate {endpoint.name} to {endpoint.certificate.replaced[0].name}")

        # TODO: stagger per certificate or source?
        rotate_endpoint.delay(endpoint.id)
