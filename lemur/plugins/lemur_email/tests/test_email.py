import os
from lemur.plugins.lemur_email.templates.config import env

from lemur.tests.factories import CertificateFactory

dir_path = os.path.dirname(os.path.realpath(__file__))


def test_render(certificate, endpoint):
    from lemur.certificates.schemas import certificate_notification_output_schema

    new_cert = CertificateFactory()
    new_cert.replaces.append(certificate)

    certificates = [certificate_notification_output_schema.dump(certificate).data]

    template = env.get_template('{}.html'.format('expiration'))

    with open(os.path.join(dir_path, 'expiration-rendered.html'), 'w') as f:
        body = template.render(dict(certificates=certificates, hostname='lemur.test.example.com'))
        f.write(body)

    template = env.get_template('{}.html'.format('rotation'))

    certificate.endpoints.append(endpoint)

    with open(os.path.join(dir_path, 'rotation-rendered.html'), 'w') as f:
        body = template.render(
            dict(
                certificate=certificate_notification_output_schema.dump(certificate).data,
                hostname='lemur.test.example.com'
            )
        )
        f.write(body)
