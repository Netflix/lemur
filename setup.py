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
with open(os.path.join(ROOT, "lemur", "__about__.py")) as f:
    exec(f.read(), about)


install_requires = [
    'Flask==0.10.1',
    'Flask-RESTful==0.3.3',
    'Flask-SQLAlchemy==2.1',
    'Flask-Script==2.0.5',
    'Flask-Migrate==1.7.0',
    'Flask-Bcrypt==0.7.1',
    'Flask-Principal==0.4.0',
    'Flask-Mail==0.9.1',
    'SQLAlchemy-Utils==0.31.4',
    'BeautifulSoup4==4.4.1',
    'requests==2.11.1',
    'psycopg2==2.6.1',
    'arrow==0.7.0',
    'six==1.10.0',
    'gunicorn==19.4.1',
    'marshmallow-sqlalchemy==0.8.0',
    'marshmallow==2.4.0',
    'pycrypto==2.6.1',
    'cryptography==1.5',
    'pyopenssl==0.15.1',
    'pyjwt==1.4.0',
    'xmltodict==0.9.2',
    'lockfile==0.12.2',
    'inflection==0.3.1',
    'future==0.15.2',
    'boto==2.38.0',  # we might make this optional
    'boto3==1.3.0',
    'acme==0.1.0',
    'retrying==1.3.3',
    'tabulate==0.7.5'
]

tests_require = [
    'pyflakes',
    'moto==0.4.19',
    'nose==1.3.7',
    'pytest==2.8.5',
    'factory-boy==2.7.0',
    'pytest-flask==0.10.0'
]

docs_require = [
    'sphinx',
    'sphinxcontrib-httpdomain',
    'sphinx-rtd-theme'
]

dev_requires = [
    'flake8>=2.0,<3.0',
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
        ],
    },
    classifiers=[
        'Framework :: Flask',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Operating System :: OS Independent',
        'Topic :: Software Development',
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Natural Language :: English",
        "License :: OSI Approved :: Apache Software License"
    ]
)
