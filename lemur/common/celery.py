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
from datetime import datetime, timezone, timedelta

from celery import Celery
from celery.exceptions import SoftTimeLimitExceeded
from flask import current_app

from lemur.authorities.service import get as get_authority
from lemur.common.redis import RedisHandler
from lemur.destinations import service as destinations_service
from lemur.extensions import metrics, sentry
from lemur.factory import create_app
from lemur.notifications.messaging import send_pending_failure_notification
from lemur.pending_certificates import service as pending_certificate_service
from lemur.plugins.base import plugins
from lemur.sources.cli import clean, sync, validate_sources
from lemur.sources.service import add_aws_destination_to_sources
from lemur.certificates import cli as cli_certificate
from lemur.dns_providers import cli as cli_dns_providers
from lemur.notifications import cli as cli_notification
from lemur.endpoints import cli as cli_endpoints


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

    i = inspect()
    active_tasks = i.active()
    for _, tasks in active_tasks.items():
        for task in tasks:
            if task.get("id") == task_id:
                continue
            if task.get("name") == fun and task.get("args") == str(args):
                return True
    return False


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
    current_time = int(time.time())
    schedule = current_app.config.get('CELERYBEAT_SCHEDULE')
    for _, t in schedule.items():
        task = t.get("task")
        last_success = int(red.get(f"{task}.last_success") or 0)
        metrics.send(f"{task}.time_since_last_success", 'gauge', current_time - last_success)
    red.set(
        f"{function}.last_success", int(time.time())
    )  # Alert if this metric is not seen
    metrics.send(f"{function}.success", 'counter', 1)


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
    metrics.send(f"{function}.resolved", 'gauge', new)
    metrics.send(f"{function}.failed", 'gauge', failed)
    metrics.send(f"{function}.wrong_issuer", 'gauge', wrong_issuer)
    print(
        "[+] Certificates: New: {new} Failed: {failed} Not using ACME: {wrong_issuer}".format(
            new=new, failed=failed, wrong_issuer=wrong_issuer
        )
    )
    red.set(f'{function}.last_success', int(time.time()))


@celery.task()
def fetch_all_pending_acme_certs():
    """Instantiate celery workers to resolve all pending Acme certificates"""
    pending_certs = pending_certificate_service.get_unresolved_pending_certs()

    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    log_data = {
        "function": function,
        "message": "Starting job.",
    }

    current_app.logger.debug(log_data)

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

    red.set(f'{function}.last_success', int(time.time()))
    metrics.send(f"{function}.success", 'counter', 1)


@celery.task()
def remove_old_acme_certs():
    """Prune old pending acme certificates from the database"""
    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    log_data = {
        "function": function,
        "message": "Starting job.",
    }
    pending_certs = pending_certificate_service.get_pending_certs("all")

    # Delete pending certs more than a week old
    for cert in pending_certs:
        if datetime.now(timezone.utc) - cert.last_updated > timedelta(days=7):
            log_data["pending_cert_id"] = cert.id
            log_data["pending_cert_name"] = cert.name
            log_data["message"] = "Deleting pending certificate"
            current_app.logger.debug(log_data)
            pending_certificate_service.delete(cert)

    red.set(f'{function}.last_success', int(time.time()))
    metrics.send(f"{function}.success", 'counter', 1)


@celery.task()
def clean_all_sources():
    """
    This function will clean unused certificates from sources. This is a destructive operation and should only
    be ran periodically. This function triggers one celery task per source.
    """
    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    sources = validate_sources("all")
    for source in sources:
        current_app.logger.debug(
            "Creating celery task to clean source {}".format(source.label)
        )
        clean_source.delay(source.label)

    red.set(f'{function}.last_success', int(time.time()))
    metrics.send(f"{function}.success", 'counter', 1)


@celery.task()
def clean_source(source):
    """
    This celery task will clean the specified source. This is a destructive operation that will delete unused
    certificates from each source.

    :param source:
    :return:
    """
    current_app.logger.debug("Cleaning source {}".format(source))
    clean([source], True)


@celery.task()
def sync_all_sources():
    """
    This function will sync certificates from all sources. This function triggers one celery task per source.
    """
    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    sources = validate_sources("all")
    for source in sources:
        current_app.logger.debug(
            "Creating celery task to sync source {}".format(source.label)
        )
        sync_source.delay(source.label)

    red.set(f'{function}.last_success', int(time.time()))
    metrics.send(f"{function}.success", 'counter', 1)


@celery.task(soft_time_limit=7200)
def sync_source(source):
    """
    This celery task will sync the specified source.

    :param source:
    :return:
    """

    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    task_id = None
    if celery.current_task:
        task_id = celery.current_task.request.id
    log_data = {
        "function": function,
        "message": "Syncing source",
        "source": source,
        "task_id": task_id,
    }
    current_app.logger.debug(log_data)

    if task_id and is_task_active(function, task_id, (source,)):
        log_data["message"] = "Skipping task: Task is already active"
        current_app.logger.debug(log_data)
        return
    try:
        sync([source])
        metrics.send(f"{function}.success", 'counter', '1', metric_tags={"source": source})
    except SoftTimeLimitExceeded:
        log_data["message"] = "Error syncing source: Time limit exceeded."
        current_app.logger.error(log_data)
        sentry.captureException()
        metrics.send(
            "sync_source_timeout", "counter", 1, metric_tags={"source": source}
        )
        return

    log_data["message"] = "Done syncing source"
    current_app.logger.debug(log_data)
    metrics.send(f"{function}.success", 'counter', 1, metric_tags={"source": source})
    red.set(f'{function}.last_success', int(time.time()))


@celery.task()
def sync_source_destination():
    """
    This celery task will sync destination and source, to make sure all new destinations are also present as source.
    Some destinations do not qualify as sources, and hence should be excluded from being added as sources
    We identify qualified destinations based on the sync_as_source attributed of the plugin.
    The destination sync_as_source_name reveals the name of the suitable source-plugin.
    We rely on account numbers to avoid duplicates.
    """
    current_app.logger.debug("Syncing AWS destinations and sources")
    function = f"{__name__}.{sys._getframe().f_code.co_name}"

    for dst in destinations_service.get_all():
        if add_aws_destination_to_sources(dst):
            current_app.logger.debug("Source: %s added", dst.label)

    current_app.logger.debug("Completed Syncing AWS destinations and sources")
    red.set(f'{function}.last_success', int(time.time()))
    metrics.send(f"{function}.success", 'counter', 1)


@celery.task()
def certificate_reissue():
    """
    This celery task reissues certificates which are pending reissue
    :return:
    """
    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    current_app.logger.debug(f"{function}: reissuing certificates")
    cli_certificate.reissue(None, True)
    current_app.logger.debug(f"{function}: reissuance completed")
    red.set(f'{function}.last_success', int(time.time()))
    metrics.send(f"{function}.success", 'counter', 1)


@celery.task()
def certificate_rotate():
    """
    This celery task rotates certificates which are reissued but having endpoints attached to the replaced cert
    :return:
    """
    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    current_app.logger.debug(f"{function}: rotating certificates")
    cli_certificate.rotate(None, None, None, None, True)
    current_app.logger.debug(f"{function}: rotation completed")
    red.set(f'{function}.last_success', int(time.time()))
    metrics.send(f"{function}.success", 'counter', 1)


@celery.task()
def endpoints_expire():
    """
    This celery task removes all endpoints that have not been recently updated
    :return:
    """
    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    current_app.logger.debug(f"{function}: endpoints expire")
    cli_endpoints.expire(2)
    red.set(f'{function}.last_success', int(time.time()))
    metrics.send(f"{function}.success", 'counter', 1)


@celery.task()
def get_all_zones():
    """
    This celery syncs all zones from the available dns providers
    :return:
    """
    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    current_app.logger.debug(f"{function}: get_all_zones")
    cli_dns_providers.get_all_zones()
    red.set(f'{function}.last_success', int(time.time()))
    metrics.send(f"{function}.success", 'counter', 1)


@celery.task()
def check_revoked():
    """
    This celery task attempts to check if any certs are expired
    :return:
    """
    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    current_app.logger.debug(f"{function}: check if any certificates are revoked revoked")
    cli_certificate.check_revoked()
    red.set(f'{function}.last_success', int(time.time()))
    metrics.send(f"{function}.success", 'counter', 1)


@celery.task()
def notify_expirations():
    """
    This celery task notifies about expiring certs
    :return:
    """
    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    current_app.logger.debug(f"{function}: Cert Expiration Notifcation")
    cli_notification.expirations(["MetatronUserCertfor", "Metatron-User-Cert-for"])
    red.set(f'{function}.last_success', int(time.time()))
    metrics.send(f"{function}.success", 'counter', 1)
