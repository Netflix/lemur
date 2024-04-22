"""
Lemur
=====

Is a TLS management and orchestration tool.

:copyright: (c) 2018 by Netflix, see AUTHORS for more
:license: Apache, see LICENSE for more details.
"""
from __future__ import absolute_import

import datetime
import json
import logging
import os.path
import sys
from subprocess import check_output
from typing import Dict, Any

from setuptools import Command
from setuptools import setup, find_packages
from setuptools.command.develop import develop
from setuptools.command.install import install
from setuptools.command.sdist import sdist

ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__)))

# When executing the setup.py, we need to be able to import ourselves, this
# means that we need to add the src/ directory to the sys.path.
sys.path.insert(0, ROOT)

about: Dict[str, Any] = {}
with open(os.path.join(ROOT, 'lemur', '__about__.py')) as f:
    exec(f.read(), about)  # nosec: about file is benign

# Parse requirements files
with open('requirements.txt') as f:
    install_requirements = f.read().splitlines()

with open('requirements-tests.txt') as f:
    tests_requirements = f.read().splitlines()

with open('requirements-docs.txt') as f:
    docs_requirements = f.read().splitlines()

with open('requirements-dev.txt') as f:
    dev_requirements = f.read().splitlines()


class SmartInstall(install):
    """
    Installs Lemur into the Python environment.
    If the package indicator is missing, this will also force a run of
    `build_static` which is required for JavaScript assets and other things.
    """

    def _needs_static(self):
        return not os.path.exists(os.path.join(ROOT, 'lemur/static/dist'))

    def run(self):
        if self._needs_static():
            self.run_command('build_static')
        install.run(self)


class DevelopWithBuildStatic(develop):
    def install_for_development(self):
        self.run_command('build_static')
        return develop.install_for_development(self)


class SdistWithBuildStatic(sdist):
    def make_release_tree(self, *a, **kw):
        dist_path = self.distribution.get_fullname()

        sdist.make_release_tree(self, *a, **kw)

        self.reinitialize_command('build_static', work_path=dist_path)
        self.run_command('build_static')

        with open(os.path.join(dist_path, 'lemur-package.json'), 'w') as fp:
            json.dump({
                'createdAt': datetime.datetime.utcnow().isoformat() + 'Z',
            }, fp)


class BuildStatic(Command):
    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        logging.info("running [npm install --quiet] in {0}".format(ROOT))
        try:
            check_output(['npm', 'install', '--quiet'], cwd=ROOT)

            logging.info("running [gulp build]")
            check_output([os.path.join(ROOT, 'node_modules', '.bin', 'gulp'), 'build'], cwd=ROOT)
            logging.info("running [gulp package]")
            check_output([os.path.join(ROOT, 'node_modules', '.bin', 'gulp'), 'package'], cwd=ROOT)
        except Exception as e:
            logging.warn("Unable to build static content")


setup(
    name=about["__title__"],
    version=about["__version__"],
    author=about["__author__"],
    author_email=about["__email__"],
    url=about["__uri__"],
    description=about["__summary__"],
    long_description=open(os.path.join(ROOT, 'README.rst')).read(),
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    install_requires=install_requirements,
    extras_require={
        'tests': tests_requirements,
        'docs': docs_requirements,
        'dev': dev_requirements,
    },
    cmdclass={
        'build_static': BuildStatic,
        'sdist': SdistWithBuildStatic,
        'install': SmartInstall
    },
    entry_points={
        'console_scripts': [
            'lemur = lemur.manage:main',
        ],
        'lemur.plugins': [
            'verisign_issuer = lemur.plugins.lemur_verisign.plugin:VerisignIssuerPlugin',
            'acme_issuer = lemur.plugins.lemur_acme.plugin:ACMEIssuerPlugin',
            'acme_http_issuer = lemur.plugins.lemur_acme.plugin:ACMEHttpIssuerPlugin',
            'aws_destination = lemur.plugins.lemur_aws.plugin:AWSDestinationPlugin',
            'aws_acm_destination = lemur.plugins.lemur_aws.plugin:ACMDestinationPlugin',
            'aws_source = lemur.plugins.lemur_aws.plugin:AWSSourcePlugin',
            'aws_acm_source = lemur.plugins.lemur_aws.plugin:AWSACMSourcePlugin',
            'aws_s3 = lemur.plugins.lemur_aws.plugin:S3DestinationPlugin',
            'aws_sns = lemur.plugins.lemur_aws.plugin:SNSNotificationPlugin',
            'email_notification = lemur.plugins.lemur_email.plugin:EmailNotificationPlugin',
            'slack_notification = lemur.plugins.lemur_slack.plugin:SlackNotificationPlugin',
            'java_truststore_export = lemur.plugins.lemur_jks.plugin:JavaTruststoreExportPlugin',
            'java_keystore_export = lemur.plugins.lemur_jks.plugin:JavaKeystoreExportPlugin',
            'openssl_export = lemur.plugins.lemur_openssl.plugin:OpenSSLExportPlugin',
            'atlas_metric = lemur.plugins.lemur_atlas.plugin:AtlasMetricPlugin',
            'atlas_metric_redis = lemur.plugins.lemur_atlas_redis.plugin:AtlasMetricRedisPlugin',
            'kubernetes_destination = lemur.plugins.lemur_kubernetes.plugin:KubernetesDestinationPlugin',
            'cryptography_issuer = lemur.plugins.lemur_cryptography.plugin:CryptographyIssuerPlugin',
            'cfssl_issuer = lemur.plugins.lemur_cfssl.plugin:CfsslIssuerPlugin',
            'digicert_issuer = lemur.plugins.lemur_digicert.plugin:DigiCertIssuerPlugin',
            'digicert_source = lemur.plugins.lemur_digicert.plugin:DigiCertSourcePlugin',
            'digicert_cis_issuer = lemur.plugins.lemur_digicert.plugin:DigiCertCISIssuerPlugin',
            'digicert_cis_source = lemur.plugins.lemur_digicert.plugin:DigiCertCISSourcePlugin',
            'csr_export = lemur.plugins.lemur_csr.plugin:CSRExportPlugin',
            'sftp_destination = lemur.plugins.lemur_sftp.plugin:SFTPDestinationPlugin',
            'vault_source = lemur.plugins.lemur_vault_dest.plugin:VaultSourcePlugin',
            'vault_desination = lemur.plugins.lemur_vault_dest.plugin:VaultDestinationPlugin',
            'adcs_issuer = lemur.plugins.lemur_adcs.plugin:ADCSIssuerPlugin',
            'adcs_source = lemur.plugins.lemur_adcs.plugin:ADCSSourcePlugin',
            'entrust_issuer = lemur.plugins.lemur_entrust.plugin:EntrustIssuerPlugin',
            'entrust_source = lemur.plugins.lemur_entrust.plugin:EntrustSourcePlugin',
            'azure_destination = lemur.plugins.lemur_azure_dest.plugin:AzureDestinationPlugin',

            'google_ca_issuer = lemur.plugins.lemur_google_ca.plugin:GoogleCaIssuerPlugin'
        ],
    },
    classifiers=[
        'Framework :: Flask',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Operating System :: OS Independent',
        'Topic :: Software Development',
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Natural Language :: English",
        "License :: OSI Approved :: Apache Software License"
    ]
)
