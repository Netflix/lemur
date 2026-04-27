"""
.. module: lemur.plugins.lemur_csr.plugin

An export plugin that exports CSR from a private key and certificate.
"""
import subprocess

from flask import current_app

from lemur.utils import mktempfile, mktemppath
from lemur.plugins.bases import ExportPlugin
from lemur.plugins import lemur_csr as csr


def run_process(command):
    """
    Runs a given command with pOpen and wraps some
    error handling around it.
    :param command:
    :return:
    """
    p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    current_app.logger.debug(command)
    stdout, stderr = p.communicate()

    if p.returncode != 0:
        current_app.logger.debug(" ".join(command))
        current_app.logger.error(stderr)
        raise Exception(stderr)


def create_csr(cert, chain, csr_tmp, key):
    """
    Creates a csr from key and cert file.
    :param cert:
    :param chain:
    :param csr_tmp:
    :param key:
    """
    assert isinstance(cert, str)
    assert isinstance(chain, str)
    assert isinstance(key, str)

    with mktempfile() as key_tmp:
        with open(key_tmp, "w") as f:
            f.write(key)

        with mktempfile() as cert_tmp:
            with open(cert_tmp, "w") as f:
                if chain:
                    f.writelines([cert.strip() + "\n", chain.strip() + "\n"])
                else:
                    f.writelines([cert.strip() + "\n"])

            output = subprocess.check_output(
                ["openssl", "x509", "-x509toreq", "-in", cert_tmp, "-signkey", key_tmp]
            )
            subprocess.run(["openssl", "req", "-out", csr_tmp], input=output)


class CSRExportPlugin(ExportPlugin):
    title = "CSR"
    slug = "openssl-csr"
    description = "Exports a CSR"
    version = csr.VERSION

    author = "jchuong"
    author_url = "https://github.com/jchuong"

    def export(self, body, chain, key, options, **kwargs):
        """
        Creates CSR from certificate

        :param key:
        :param chain:
        :param body:
        :param options:
        :param kwargs:
        """
        with mktemppath() as output_tmp:
            if not key:
                raise Exception("Private Key required by CSR")

            create_csr(body, chain, output_tmp, key)
            extension = "csr"

            with open(output_tmp, "rb") as f:
                raw = f.read()
        # passphrase is None
        return extension, None, raw
