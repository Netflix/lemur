

def test_formatting(certificate):
    from lemur.plugins.lemur_slack.plugin import create_expiration_attachments
    from lemur.notifications.service import _get_message_data
    data = [_get_message_data(certificate)]

    attachments = [
        {
            'title': 'certificate0',
            'color': 'danger',
            'fields': [
                {
                    'short': True,
                    'value': 'joe@example.com',
                    'title': 'Owner'
                },
                {
                    'short': True,
                    'value': u'Wednesday, January 1, 2020',
                    'title': 'Expires'
                }, {
                    'short': True,
                    'value': 0,
                    'title': 'Endpoints Detected'
                }
            ],
            'title_link': 'https://lemur.example.com/#/certificates/certificate0',
            'mrkdwn_in': ['text'],
            'text': '',
            'fallback': ''
        }
    ]
    assert attachments == create_expiration_attachments(data)
