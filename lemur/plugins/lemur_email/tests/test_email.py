import os
from lemur.plugins.lemur_email.templates.config import env

from lemur.tests.factories import CertificateFactory

dir_path = os.path.dirname(os.path.realpath(__file__))


def test_render(certificate, endpoint):
    from lemur.certificates.schemas import certificate_notification_output_schema

    new_cert = CertificateFactory()
    new_cert.replaces.append(certificate)

    data = {
        "certificates": [certificate_notification_output_schema.dump(certificate).data],
        "options": [
            {"name": "interval", "value": 10},
            {"name": "unit", "value": "days"},
        ],
    }

    template = env.get_template("{}.html".format("expiration"))

    body = template.render(dict(message=data, hostname="lemur.test.example.com"))

    template = env.get_template("{}.html".format("rotation"))

    certificate.endpoints.append(endpoint)

    body = template.render(
        dict(
            certificate=certificate_notification_output_schema.dump(certificate).data,
            hostname="lemur.test.example.com",
        )
    )
