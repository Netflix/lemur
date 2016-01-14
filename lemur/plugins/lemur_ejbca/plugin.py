import base64

import dateutil.parser
import dateutil.tz

from flask import current_app

from lemur.plugins.bases import IssuerPlugin
from lemur.plugins import lemur_ejbca as lemur
from lemur.plugins.lemur_ejbca.transport import SslAuthenticatedTransport
from lemur.common.utils import get_psuedo_random_string

from suds.client import Client


class EjbcaIssuerPlugin(IssuerPlugin):
    title = 'Ejbca'
    slug = 'ejbca-issuer'
    description = 'Enables the creation of certificates from EJBCA'
    version = lemur.VERSION

    author = 'William Dangerfield'
    author_url = ''

    def __init__(self, *args, **kwargs):
        self.client_cert = current_app.config.get('EJBCA_CLIENT_CERT')
        self.client_key = current_app.config.get('EJBCA_CLIENT_KEY')
        self.client_url = current_app.config.get('EJBCA_URL')

        super(EjbcaIssuerPlugin, self).__init__(*args, **kwargs)

    def create_certificate(self, csr, issuer_options):
        entity = self.getClient().factory.create('userDataVOWS')
        entity.caName = issuer_options['authority'].cn
        entity.certificateProfileName = "ENDUSER"
        entity.clearPwd = True
        entity.endEntityProfileName = "EMPTY"
        entity.password = get_psuedo_random_string()
        entity.status = 10  # STATUS_NEW
        subjectDN = []
        if 'country' in issuer_options and issuer_options['country']:
            subjectDN.append("c=" + issuer_options['country'])
        if 'state' in issuer_options and issuer_options['state']:
            subjectDN.append("s=" + issuer_options['state'])
        if 'location' in issuer_options and issuer_options['location']:
            subjectDN.append("l=" + issuer_options['location'])
        if 'organization' in issuer_options and issuer_options['organization']:
            subjectDN.append("o=" + issuer_options['organization'])
        if 'organizationalUnit' in issuer_options and issuer_options['organizationalUnit']:
            subjectDN.append("ou=" + issuer_options['organizationalUnit'])
        if 'commonName' in issuer_options and issuer_options['commonName']:
            subjectDN.append("cn=" + issuer_options['commonName'])
        entity.subjectDN = ", ".join(subjectDN)

        entity.startTime = self.toDateFormat(issuer_options['validityStart'])
        entity.endTime = self.toDateFormat(issuer_options['validityEnd'])

        entity.tokenType = "USERGENERATED"
        entity.username = issuer_options['commonName']
        entity.email = issuer_options['owner']

        self.getClient().service.editUser(entity)

        response = self.getClient().service.pkcs10Request(entity.username, entity.password, csr, None, 'CERTIFICATE')

        full_chain = self.getClient().service.getLastCAChain(issuer_options['authority'].cn)
        # Omit the root cert from the chain
        server_chain = full_chain[:-1]

        return self.toPem(response.data), self.toPemChain(server_chain)

    def create_authority(self, options):
        chain = self.getClient().service.getLastCAChain(options.caName)
        pem_cert = self.toPem(chain[0].certificateData)

        pem_chain = ""
        if len(chain) > 1:
            pem_chain = self.toPemChain(chain[1:])

        role = {'username': '', 'password': '', 'name': options.caName}
        return pem_cert, pem_chain, [role]

    def toPemChain(self, certificates):
        return "\n".join([self.toPem(certificate.certificateData) for certificate in certificates])

    def toPem(self, base64cert):
        return "-----BEGIN CERTIFICATE-----" + "\n" +\
               base64.decodestring(base64cert) + "\n" + "-----END CERTIFICATE-----"

    def getClient(self):
        transport = SslAuthenticatedTransport(cert=(self.client_cert, self.client_key))
        return Client(self.client_url + '/ejbcaws/ejbcaws?wsdl', transport=transport)

    def toDateFormat(self, isodate):
        return dateutil.parser.parse(isodate).astimezone(dateutil.tz.tzutc()).strftime("%Y-%m-%d %H:%M:%S") + "+00:00"
