

def test_formatting(certificate):
    from lemur.plugins.lemur_slack.plugin import create_expiration_attachments
    from lemur.certificates.schemas import certificate_notification_output_schema
    data = [certificate_notification_output_schema.dump(certificate).data]

    attachment = {
        'title': certificate.name,
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
        'title_link': 'https://lemur.example.com/#/certificates/{name}'.format(name=certificate.name),
        'mrkdwn_in': ['text'],
        'text': '',
        'fallback': ''
    }

    assert attachment == create_expiration_attachments(data)[0]
