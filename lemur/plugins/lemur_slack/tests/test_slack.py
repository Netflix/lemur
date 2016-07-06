

def test_formatting(certificate):
    from lemur.plugins.lemur_slack.plugin import create_expiration_attachments
    from lemur.notifications.service import _get_message_data
    data = [_get_message_data(certificate)]
    assert create_expiration_attachments(data) == ''
