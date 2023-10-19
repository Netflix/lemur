from lemur.plugins.bases import NotificationPlugin


class TestNotificationPlugin(NotificationPlugin):
    title = "Test"
    slug = "test-notification"
    description = "Enables testing"

    author = "Kevin Glisson"
    author_url = "https://github.com/netflix/lemur.git"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    @staticmethod
    def send(notification_type, message, targets, options, **kwargs):
        return
