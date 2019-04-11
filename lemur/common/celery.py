"""
This module controls defines celery tasks and their applicable schedules. The celery beat server and workers will start
when invoked.

When ran in development mode (LEMUR_CONFIG=<location of development configuration file. To run both the celery
beat scheduler and a worker simultaneously, and to have jobs kick off starting at the next minute, run the following
command: celery -A lemur.common.celery worker --loglevel=info -l DEBUG -B

"""
import copy
import sys
from datetime import datetime, timezone, timedelta

from celery import Celery
from flask import current_app

from lemur.authorities.service import get as get_authority
from lemur.factory import create_app
from lemur.notifications.messaging import send_pending_failure_notification
from lemur.pending_certificates import service as pending_certificate_service
from lemur.plugins.base import plugins, IPlugin
from lemur.sources.cli import clean, sync, validate_sources
from lemur.destinations import service as destinations_service
from lemur.sources import service as sources_service


if current_app:
    flask_app = current_app
else:
    flask_app = create_app()


def make_celery(app):
    celery = Celery(app.import_name, backend=app.config.get('CELERY_RESULT_BACKEND'),
                    broker=app.config.get('CELERY_BROKER_URL'))
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
def fetch_acme_cert(id):
    """
    Attempt to get the full certificate for the pending certificate listed.

    Args:
        id: an id of a PendingCertificate
    """
    log_data = {
        "function": "{}.{}".format(__name__, sys._getframe().f_code.co_name),
        "message": "Resolving pending certificate {}".format(id)
    }
    current_app.logger.debug(log_data)
    pending_certs = pending_certificate_service.get_pending_certs([id])
    new = 0
    failed = 0
    wrong_issuer = 0
    acme_certs = []

    # We only care about certs using the acme-issuer plugin
    for cert in pending_certs:
        cert_authority = get_authority(cert.authority_id)
        if cert_authority.plugin_name == 'acme-issuer':
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
            log_data["message"] = "Pending certificate doesn't exist anymore. Was it resolved by another process?"
            current_app.logger.error(log_data)
            continue
        if real_cert:
            # If a real certificate was returned from issuer, then create it in Lemur and mark
            # the pending certificate as resolved
            final_cert = pending_certificate_service.create_certificate(pending_cert, real_cert, pending_cert.user)
            pending_certificate_service.update(
                cert.get("pending_cert").id,
                resolved=True
            )
            pending_certificate_service.update(
                cert.get("pending_cert").id,
                resolved_cert_id=final_cert.id
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
                send_pending_failure_notification(pending_cert, notify_owner=pending_cert.notify)
                # Mark the pending cert as resolved
                pending_certificate_service.update(
                    cert.get("pending_cert").id,
                    resolved=True
                )
            else:
                pending_certificate_service.increment_attempt(pending_cert)
                pending_certificate_service.update(
                    cert.get("pending_cert").id,
                    status=str(cert.get("last_error"))
                )
                # Add failed pending cert task back to queue
                fetch_acme_cert.delay(id)
            current_app.logger.error(error_log)
    log_data["message"] = "Complete"
    log_data["new"] = new
    log_data["failed"] = failed
    log_data["wrong_issuer"] = wrong_issuer
    current_app.logger.debug(log_data)
    print(
        "[+] Certificates: New: {new} Failed: {failed} Not using ACME: {wrong_issuer}".format(
            new=new,
            failed=failed,
            wrong_issuer=wrong_issuer
        )
    )


@celery.task()
def fetch_all_pending_acme_certs():
    """Instantiate celery workers to resolve all pending Acme certificates"""
    pending_certs = pending_certificate_service.get_unresolved_pending_certs()

    log_data = {
        "function": "{}.{}".format(__name__, sys._getframe().f_code.co_name),
        "message": "Starting job."
    }

    current_app.logger.debug(log_data)

    # We only care about certs using the acme-issuer plugin
    for cert in pending_certs:
        cert_authority = get_authority(cert.authority_id)
        if cert_authority.plugin_name == 'acme-issuer':
            if datetime.now(timezone.utc) - cert.last_updated > timedelta(minutes=5):
                log_data["message"] = "Triggering job for cert {}".format(cert.name)
                log_data["cert_name"] = cert.name
                log_data["cert_id"] = cert.id
                current_app.logger.debug(log_data)
                fetch_acme_cert.delay(cert.id)


@celery.task()
def remove_old_acme_certs():
    """Prune old pending acme certificates from the database"""
    log_data = {
        "function": "{}.{}".format(__name__, sys._getframe().f_code.co_name)
    }
    pending_certs = pending_certificate_service.get_pending_certs('all')

    # Delete pending certs more than a week old
    for cert in pending_certs:
        if datetime.now(timezone.utc) - cert.last_updated > timedelta(days=7):
            log_data['pending_cert_id'] = cert.id
            log_data['pending_cert_name'] = cert.name
            log_data['message'] = "Deleting pending certificate"
            current_app.logger.debug(log_data)
            pending_certificate_service.delete(cert.id)


@celery.task()
def clean_all_sources():
    """
    This function will clean unused certificates from sources. This is a destructive operation and should only
    be ran periodically. This function triggers one celery task per source.
    """
    sources = validate_sources("all")
    for source in sources:
        current_app.logger.debug("Creating celery task to clean source {}".format(source.label))
        clean_source.delay(source.label)


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
    sources = validate_sources("all")
    for source in sources:
        current_app.logger.debug("Creating celery task to sync source {}".format(source.label))
        sync_source.delay(source.label)


@celery.task()
def sync_source(source):
    """
    This celery task will sync the specified source.

    :param source:
    :return:
    """

    function = "{}.{}".format(__name__, sys._getframe().f_code.co_name)
    task_id = celery.current_task.request.id
    log_data = {
        "function": function,
        "message": "Syncing source",
        "source": source,
        "task_id": task_id,
    }
    current_app.logger.debug(log_data)

    if is_task_active(function, task_id, (source,)):
        log_data["message"] = "Skipping task: Task is already active"
        current_app.logger.debug(log_data)
        return
    sync([source])
    log_data["message"] = "Done syncing source"
    current_app.logger.debug(log_data)


@celery.task()
def sync_source_destination():
    """
    This celery task will sync destination and source, to make sure all new destinations are also present as source.
    Some destinations do not qualify as sources, and hence should be excluded from being added as sources
    We identify qualified destinations based on the sync_as_source attributed of the plugin.
    The destination sync_as_source_name reviels the name of the suitable source-plugin.
    We rely on account numbers to avoid duplicates.
    """
    current_app.logger.debug("Syncing source and destination")

    # a set of all accounts numbers available as sources
    src_accounts = set()
    sources = validate_sources("all")
    for src in sources:
        src_accounts.add(IPlugin.get_option('accountNumber', src.options))

    for dst in destinations_service.get_all():
        destination_plugin = plugins.get(dst.plugin_name)
        account_number = IPlugin.get_option('accountNumber', dst.options)
        if destination_plugin.sync_as_source and (account_number not in src_accounts):
            src_options = copy.deepcopy(plugins.get(destination_plugin.sync_as_source_name).options)
            for o in src_options:
                if o.get('name') == 'accountNumber':
                    o.update({'value': account_number})
            sources_service.create(label=dst.label,
                                   plugin_name=destination_plugin.sync_as_source_name,
                                   options=src_options,
                                   description=dst.description)
            current_app.logger.info("Source: %s added", dst.label)
