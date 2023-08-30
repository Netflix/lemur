import pytest

from lemur.notifications.views import *  # noqa


from .vectors import (
    VALID_ADMIN_API_TOKEN,
    VALID_ADMIN_HEADER_TOKEN,
    VALID_USER_HEADER_TOKEN,
)


def test_notification_input_schema(client, notification_plugin, notification):
    from lemur.notifications.schemas import NotificationInputSchema

    input_data = {
        "label": "notification1",
        "options": {},
        "description": "my notification",
        "active": True,
        "plugin": {"slug": "test-notification"},
    }

    data, errors = NotificationInputSchema().load(input_data)

    assert not errors


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 200),
        (VALID_ADMIN_HEADER_TOKEN, 200),
        (VALID_ADMIN_API_TOKEN, 200),
        ("", 401),
    ],
)
def test_notification_get(client, notification_plugin, notification, token, status):
    assert (
        client.get(
            api.url_for(Notifications, notification_id=notification.id), headers=token
        ).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_notification_post_(client, token, status):
    assert (
        client.post(
            api.url_for(Notifications, notification_id=1), data={}, headers=token
        ).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 400),
        (VALID_ADMIN_HEADER_TOKEN, 400),
        (VALID_ADMIN_API_TOKEN, 400),
        ("", 401),
    ],
)
def test_notification_put(client, token, status):
    assert (
        client.put(
            api.url_for(Notifications, notification_id=1), data={}, headers=token
        ).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 200),
        (VALID_ADMIN_HEADER_TOKEN, 200),
        (VALID_ADMIN_API_TOKEN, 200),
        ("", 401),
    ],
)
def test_notification_delete(client, token, status):
    assert (
        client.delete(
            api.url_for(Notifications, notification_id=1), headers=token
        ).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_notification_patch(client, token, status):
    assert (
        client.patch(
            api.url_for(Notifications, notification_id=1), data={}, headers=token
        ).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 400),
        (VALID_ADMIN_HEADER_TOKEN, 400),
        (VALID_ADMIN_API_TOKEN, 400),
        ("", 401),
    ],
)
def test_notification_list_post_(client, token, status):
    assert (
        client.post(api.url_for(NotificationsList), data={}, headers=token).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 200),
        (VALID_ADMIN_HEADER_TOKEN, 200),
        (VALID_ADMIN_API_TOKEN, 200),
        ("", 401),
    ],
)
def test_notification_list_get(
    client, notification_plugin, notification, token, status
):
    assert (
        client.get(api.url_for(NotificationsList), headers=token).status_code == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_notification_list_delete(client, token, status):
    assert (
        client.delete(api.url_for(NotificationsList), headers=token).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_notification_list_patch(client, token, status):
    assert (
        client.patch(api.url_for(NotificationsList), data={}, headers=token).status_code
        == status
    )
