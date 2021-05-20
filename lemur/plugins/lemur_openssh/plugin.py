"""
.. module: lemur.plugins.lemur_openssh.plugin
    :platform: Unix
    :copyright: (c) 2020 by Emmanuel Garette, see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Emmanuel Garette <gnunux@gnunux.info>
"""
import subprocess
from os import unlink

from flask import current_app
from cryptography.hazmat.primitives import serialization
from datetime import datetime

from lemur.utils import mktempfile
from lemur.plugins import lemur_openssh as openssh
from lemur.common.utils import parse_private_key, parse_certificate
from lemur.plugins.lemur_cryptography.plugin import CryptographyIssuerPlugin
from lemur.certificates.service import get_by_root_authority


def run_process(command):
    """
    Runs a given command with pOpen and wraps some
    error handling around it.
    :param command:
    :return:
    """
    p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    current_app.logger.debug(" ".join(command))
    stdout, stderr = p.communicate()

    if p.returncode != 0:
        current_app.logger.error(stderr.decode())
        raise Exception(stderr.decode())


def split_cert(body):
    """
    To display certificate in Lemur website, we have to split
    certificate in several line
    :param body: certificate
    :retur: splitted certificate
    """
    length = 65
    return '\n'.join([body[i:i + length] for i in range(0, len(body), length)])


def sign_certificate(common_name, public_key, authority_private_key, user, extensions, not_before, not_after):
    private_key = parse_private_key(authority_private_key).private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    with mktempfile() as issuer_tmp:
        cmd = ['ssh-keygen', '-s', issuer_tmp]
        with open(issuer_tmp, 'w') as i:
            i.writelines(private_key)
        if 'extendedKeyUsage' in extensions and extensions['extendedKeyUsage'].get('useClientAuthentication'):
            cmd.extend(['-I', user['username'] + ' user key',
                        '-n', user['username']])
        else:
            domains = {common_name}
            for name in extensions['subAltNames']['names']:
                if name['nameType'] == 'DNSName':
                    domains.add(name['value'])
            cmd.extend(['-I', common_name + ' host key',
                        '-n', ','.join(domains),
                        '-h'])
        # something like 20201024
        ssh_not_before = datetime.fromisoformat(not_before).strftime("%Y%m%d")
        ssh_not_after = datetime.fromisoformat(not_after).strftime("%Y%m%d")
        cmd.extend(['-V', ssh_not_before + ':' + ssh_not_after])
        with mktempfile() as cert_tmp:
            with open(cert_tmp, 'w') as f:
                f.write(public_key)

            cmd.append(cert_tmp)
            run_process(cmd)
    pub = cert_tmp + '-cert.pub'
    with open(pub, 'r') as p:
        body = split_cert(p.read())
    unlink(pub)
    return body


class OpenSSHIssuerPlugin(CryptographyIssuerPlugin):
    """This issuer plugins is base in Cryptography plugin
    Certificates and authorities are x509 certificates created by Cryptography plugin.
    Those certificates are converted to OpenSSH format when people get them.
    """
    title = "OpenSSH"
    slug = "openssh-issuer"
    description = "Enables the creation and signing OpenSSH keys"
    version = openssh.VERSION

    author = "Emmanuel Garette"
    author_url = "http://gnunux.info"

    def create_authority(self, options):
        # OpenSSH do not support parent's authoriy
        if options.get("parent"):
            raise Exception('cannot create authority with a parent for OpenSSH plugin')
        # create a x509 certificat
        cert_pem, private_key, chain_cert_pem, roles = super().create_authority(options)
        return cert_pem, private_key, chain_cert_pem, roles

    def wrap_certificate(self, cert):
        # get public_key in OpenSSH format
        public_key = parse_certificate(cert['body']).public_key().public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
        ).decode()
        public_key += ' ' + cert['user']['email']
        # sign it with authority private key
        if 'root_authority' in cert and cert['root_authority']:
            authority = cert['root_authority']
        else:
            authority = cert['authority']
        root_authority = get_by_root_authority(authority['id'])
        authority_private_key = root_authority.private_key
        cert['body'] = sign_certificate(
            cert['common_name'],
            public_key,
            authority_private_key,
            cert['user'],
            cert['extensions'],
            cert['not_before'],
            cert['not_after']
        )
        # convert chain in OpenSSH format
        if cert['chain']:
            chain_cert = {'body': cert['chain'], 'cn': root_authority.cn}
            self.wrap_auth_certificate(chain_cert)
            cert['chain'] = chain_cert['body']
        # OpenSSH do not support csr
        cert['csr'] = None

    @staticmethod
    def wrap_auth_certificate(auth_cert):
        # convert chain in OpenSSH format
        chain_key = parse_certificate(auth_cert['body']).public_key().public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
        ).decode()
        chain_key += ' root@' + auth_cert['cn']
        auth_cert['body'] = split_cert(chain_key)

    @staticmethod
    def wrap_private_key(cert):
        # convert private_key in OpenSSH format
        cert.private_key = parse_private_key(cert.private_key).private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption(),
        )
