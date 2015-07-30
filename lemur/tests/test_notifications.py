from lemur.notifications.service import *  # noqa
from lemur.notifications.views import *  # noqa


def test_crud(session):
    notification = create('testnotify', 'email-notification', {}, 'notify1', [])
    assert notification.id > 0

    notification = update(notification.id, 'testnotify2', {}, 'notify2', [])
    assert notification.label == 'testnotify2'

    assert len(get_all()) == 1

    delete(1)
    assert len(get_all()) == 0


def test_notification_get(client):
    assert client.get(api.url_for(Notifications, notification_id=1)).status_code == 401


def test_notification_post(client):
    assert client.post(api.url_for(Notifications, notification_id=1), data={}).status_code == 405


def test_notification_put(client):
    assert client.put(api.url_for(Notifications, notification_id=1), data={}).status_code == 401


def test_notification_delete(client):
    assert client.delete(api.url_for(Notifications, notification_id=1)).status_code == 401


def test_notification_patch(client):
    assert client.patch(api.url_for(Notifications, notification_id=1), data={}).status_code == 405


VALID_USER_HEADER_TOKEN = {
    'Authorization': 'Basic ' + 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0MzUyMzMzNjksInN1YiI6MSwiZXhwIjoxNTIxNTQ2OTY5fQ.1qCi0Ip7mzKbjNh0tVd3_eJOrae3rNa_9MCVdA4WtQI'}


def test_auth_notification_get(client):
    assert client.get(api.url_for(Notifications, notification_id=1), headers=VALID_USER_HEADER_TOKEN).status_code == 200


def test_auth_notification_post_(client):
    assert client.post(api.url_for(Notifications, notification_id=1), data={}, headers=VALID_USER_HEADER_TOKEN).status_code == 405


def test_auth_notification_put(client):
    assert client.put(api.url_for(Notifications, notification_id=1), data={}, headers=VALID_USER_HEADER_TOKEN).status_code == 400


def test_auth_notification_delete(client):
    assert client.delete(api.url_for(Notifications, notification_id=1), headers=VALID_USER_HEADER_TOKEN).status_code == 200


def test_auth_notification_patch(client):
    assert client.patch(api.url_for(Notifications, notification_id=1), data={}, headers=VALID_USER_HEADER_TOKEN).status_code == 405


VALID_ADMIN_HEADER_TOKEN = {
    'Authorization': 'Basic ' + 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0MzUyNTAyMTgsInN1YiI6MiwiZXhwIjoxNTIxNTYzODE4fQ.6mbq4-Ro6K5MmuNiTJBB153RDhlM5LGJBjI7GBKkfqA'}


def test_admin_notification_get(client):
    assert client.get(api.url_for(Notifications, notification_id=1), headers=VALID_ADMIN_HEADER_TOKEN).status_code == 200


def test_admin_notification_post(client):
    assert client.post(api.url_for(Notifications, notification_id=1), data={}, headers=VALID_ADMIN_HEADER_TOKEN).status_code == 405


def test_admin_notification_put(client):
    assert client.put(api.url_for(Notifications, notification_id=1), data={}, headers=VALID_ADMIN_HEADER_TOKEN).status_code == 400


def test_admin_notification_delete(client):
    assert client.delete(api.url_for(Notifications, notification_id=1), headers=VALID_ADMIN_HEADER_TOKEN).status_code == 200


def test_admin_notification_patch(client):
    assert client.patch(api.url_for(Notifications, notification_id=1), data={}, headers=VALID_ADMIN_HEADER_TOKEN).status_code == 405


def test_notifications_get(client):
    assert client.get(api.url_for(NotificationsList)).status_code == 401


def test_notifications_post(client):
    assert client.post(api.url_for(NotificationsList), data={}).status_code == 401


def test_notifications_put(client):
    assert client.put(api.url_for(NotificationsList), data={}).status_code == 405


def test_notifications_delete(client):
    assert client.delete(api.url_for(NotificationsList)).status_code == 405


def test_notifications_patch(client):
    assert client.patch(api.url_for(NotificationsList), data={}).status_code == 405


def test_auth_notifications_get(client):
    assert client.get(api.url_for(NotificationsList), headers=VALID_USER_HEADER_TOKEN).status_code == 200


def test_auth_notifications_post(client):
    assert client.post(api.url_for(NotificationsList), data={}, headers=VALID_USER_HEADER_TOKEN).status_code == 400


def test_admin_notifications_get(client):
    resp = client.get(api.url_for(NotificationsList), headers=VALID_ADMIN_HEADER_TOKEN)
    assert resp.status_code == 200
    assert resp.json == {'items': [], 'total': 0}
