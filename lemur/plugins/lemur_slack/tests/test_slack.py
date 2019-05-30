def test_formatting(certificate):
    from lemur.plugins.lemur_slack.plugin import create_expiration_attachments
    from lemur.certificates.schemas import certificate_notification_output_schema

    data = [certificate_notification_output_schema.dump(certificate).data]

    attachment = {
        "title": certificate.name,
        "color": "danger",
        "fields": [
            {"short": True, "value": "joe@example.com", "title": "Owner"},
            {"short": True, "value": u"Tuesday, December 31, 2047", "title": "Expires"},
            {"short": True, "value": 0, "title": "Endpoints Detected"},
        ],
        "title_link": "https://lemur.example.com/#/certificates/{name}".format(
            name=certificate.name
        ),
        "mrkdwn_in": ["text"],
        "text": "",
        "fallback": "",
    }

    assert attachment == create_expiration_attachments(data)[0]
