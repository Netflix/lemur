"""
Lemur
=====

Is a TLS management and orchestration tool.

:copyright: (c) 2018 by Netflix, see AUTHORS for more
:license: Apache, see LICENSE for more details.
"""
from __future__ import absolute_import

import sys
import json
import os.path
import datetime

from distutils import log
from distutils.core import Command
from setuptools.command.develop import develop
from setuptools.command.install import install
from setuptools.command.sdist import sdist
from setuptools import setup, find_packages
from subprocess import check_output

import pip
if tuple(map(int, pip.__version__.split('.'))) >= (19, 3, 0):
    from pip._internal.network.session import PipSession
    from pip._internal.req import parse_requirements

elif tuple(map(int, pip.__version__.split('.'))) >= (10, 0, 0):
    from pip._internal.download import PipSession
    from pip._internal.req import parse_requirements
else:
    from pip.download import PipSession
    from pip.req import parse_requirements

ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__)))

# When executing the setup.py, we need to be able to import ourselves, this
# means that we need to add the src/ directory to the sys.path.
sys.path.insert(0, ROOT)

about = {}
with open(os.path.join(ROOT, 'lemur', '__about__.py')) as f:
    exec(f.read(), about)  # nosec: about file is benign

install_requires_g = parse_requirements("requirements.txt", session=PipSession())
tests_require_g = parse_requirements("requirements-tests.txt", session=PipSession())
docs_require_g = parse_requirements("requirements-docs.txt", session=PipSession())
dev_requires_g = parse_requirements("requirements-dev.txt", session=PipSession())

if tuple(map(int, pip.__version__.split('.'))) >= (20, 1):
    install_requires = [str(ir.requirement) for ir in install_requires_g]
    tests_require = [str(ir.requirement) for ir in tests_require_g]
    docs_require = [str(ir.requirement) for ir in docs_require_g]
    dev_requires = [str(ir.requirement) for ir in dev_requires_g]
else:
    install_requires = [str(ir.req) for ir in install_requires_g]
    tests_require = [str(ir.req) for ir in tests_require_g]
    docs_require = [str(ir.req) for ir in docs_require_g]
    dev_requires = [str(ir.req) for ir in dev_requires_g]


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
        log.info("running [npm install --quiet] in {0}".format(ROOT))
        try:
            check_output(['npm', 'install', '--quiet'], cwd=ROOT)

            log.info("running [gulp build]")
            check_output([os.path.join(ROOT, 'node_modules', '.bin', 'gulp'), 'build'], cwd=ROOT)
            log.info("running [gulp package]")
            check_output([os.path.join(ROOT, 'node_modules', '.bin', 'gulp'), 'package'], cwd=ROOT)
        except Exception as e:
            log.warn("Unable to build static content")


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
    install_requires=install_requires,
    extras_require={
        'tests': tests_require,
        'docs': docs_require,
        'dev': dev_requires,
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
            'aws_destination = lemur.plugins.lemur_aws.plugin:AWSDestinationPlugin',
            'aws_source = lemur.plugins.lemur_aws.plugin:AWSSourcePlugin',
            'aws_s3 = lemur.plugins.lemur_aws.plugin:S3DestinationPlugin',
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
            'digicert_cis_issuer = lemur.plugins.lemur_digicert.plugin:DigiCertCISIssuerPlugin',
            'digicert_cis_source = lemur.plugins.lemur_digicert.plugin:DigiCertCISSourcePlugin',
            'csr_export = lemur.plugins.lemur_csr.plugin:CSRExportPlugin',
            'sftp_destination = lemur.plugins.lemur_sftp.plugin:SFTPDestinationPlugin',
            'vault_source = lemur.plugins.lemur_vault_dest.plugin:VaultSourcePlugin',
            'vault_desination = lemur.plugins.lemur_vault_dest.plugin:VaultDestinationPlugin',
            'faslty_destination = lemur.plugins.lemur_fastly.plugin:FastlyDestinationPlugin',
            'adcs_issuer = lemur.plugins.lemur_adcs.plugin:ADCSIssuerPlugin',
            'adcs_source = lemur.plugins.lemur_adcs.plugin:ADCSSourcePlugin'
        ],
    },
    classifiers=[
        'Framework :: Flask',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Operating System :: OS Independent',
        'Topic :: Software Development',
        "Programming Language :: Python :: 3.5",
        "Natural Language :: English",
        "License :: OSI Approved :: Apache Software License"
    ]
)
