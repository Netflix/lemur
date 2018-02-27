"""
Lemur
=====

Is a TLS management and orchestration tool.

:copyright: (c) 2015 by Netflix, see AUTHORS for more
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

ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__)))

# When executing the setup.py, we need to be able to import ourselves, this
# means that we need to add the src/ directory to the sys.path.
sys.path.insert(0, ROOT)

about = {}
with open(os.path.join(ROOT, 'lemur', '__about__.py')) as f:
    exec(f.read(), about)  # nosec: about file is benign


install_requires = [
    'CloudFlare==1.7.5',
    'Flask==0.12',
    'Flask-RESTful==0.3.6',
    'Flask-SQLAlchemy==2.1',
    'Flask-Script==2.0.6',
    'Flask-Migrate==2.1.1',
    'Flask-Bcrypt==0.7.1',
    'Flask-Principal==0.4.0',
    'Flask-Mail==0.9.1',
    'SQLAlchemy-Utils==0.32.21',
    'requests==2.11.1',
    'ndg-httpsclient==0.4.2',
    'psycopg2==2.7.3.2',
    'arrow==0.12.0',
    'six==1.11.0',
    'marshmallow-sqlalchemy==0.13.1',
    'gunicorn==19.7.1',
    'marshmallow==2.15.0',
    'cryptography==1.9',
    'xmltodict==0.11.0',
    'pyjwt==1.5.3',
    'lockfile==0.12.2',
    'inflection==0.3.1',
    'future==0.16.0',
    'boto3==1.6.0',
    'acme==0.20.0',
    'retrying==1.3.3',
    'tabulate==0.8.2',
    'pyOpenSSL==17.2.0',
    'pem==17.1.0',
    'raven[flask]==6.2.1',
    'jinja2==2.10',
    'paramiko==2.4.0',  # required for lemur_linuxdst plugin
    'pyldap==2.4.45',   # required by ldap auth provider
    'alembic-autogenerate-enums==0.0.2'
]

tests_require = [
    'pyflakes',
    'moto==1.1.25',
    'nose==1.3.7',
    'pytest==3.3.2',
    'factory-boy==2.9.2',
    'fake-factory==0.7.2',
    'pytest-flask==0.10.0',
    'freezegun==0.3.9',
    'requests-mock==1.4.0',
    'pytest-mock'
]

docs_require = [
    'sphinx',
    'sphinxcontrib-httpdomain',
    'sphinx-rtd-theme'
]

dev_requires = [
    'flake8>=3.2,<4.0',
    'pre-commit',
    'invoke',
    'twine'
]


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
            'java_truststore_export = lemur.plugins.lemur_java.plugin:JavaTruststoreExportPlugin',
            'java_keystore_export = lemur.plugins.lemur_java.plugin:JavaKeystoreExportPlugin',
            'openssl_export = lemur.plugins.lemur_openssl.plugin:OpenSSLExportPlugin',
            'atlas_metric = lemur.plugins.lemur_atlas.plugin:AtlasMetricPlugin',
            'kubernetes_destination = lemur.plugins.lemur_kubernetes.plugin:KubernetesDestinationPlugin',
            'cryptography_issuer = lemur.plugins.lemur_cryptography.plugin:CryptographyIssuerPlugin',
            'cfssl_issuer = lemur.plugins.lemur_cfssl.plugin:CfsslIssuerPlugin',
            'digicert_issuer = lemur.plugins.lemur_digicert.plugin:DigiCertIssuerPlugin',
            'digicert_cis_issuer = lemur.plugins.lemur_digicert.plugin:DigiCertCISIssuerPlugin',
            'digicert_cis_source = lemur.plugins.lemur_digicert.plugin:DigiCertCISSourcePlugin'
            'csr_export = lemur.plugins.lemur_csr.plugin:CSRExportPlugin',
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
