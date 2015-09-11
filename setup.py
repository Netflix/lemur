"""
Lemur
=====

Is an SSL management and orchestration tool.

:copyright: (c) 2015 by Netflix, see AUTHORS for more
:license: Apache, see LICENSE for more details.
"""
from __future__ import absolute_import

import os.path

from distutils import log
from distutils.core import Command
from setuptools.command.develop import develop
from setuptools.command.install import install
from setuptools.command.sdist import sdist
from setuptools import setup
from subprocess import check_output

ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__)))

install_requires = [
    'Flask==0.10.1',
    'Flask-RESTful==0.3.3',
    'Flask-SQLAlchemy==2.0',
    'Flask-Script==2.0.5',
    'Flask-Migrate==1.4.0',
    'Flask-Bcrypt==0.6.2',
    'Flask-Principal==0.4.0',
    'Flask-Mail==0.9.1',
    'SQLAlchemy-Utils==0.30.11',
    'BeautifulSoup4',
    'requests==2.7.0',
    'psycopg2==2.6.1',
    'arrow==0.5.4',
    'boto==2.38.0',  # we might make this optional
    'six==1.9.0',
    'gunicorn==19.3.0',
    'pycrypto==2.6.1',
    'cryptography>=1.0dev',
    'pyopenssl==0.15.1',
    'pyjwt==1.0.1',
    'xmltodict==0.9.2',
    'lockfile==0.10.2',
    'future==0.15.0',
]

tests_require = [
    'pyflakes',
    'moto==0.4.6',
    'nose==1.3.7',
    'pytest==2.7.2',
    'pytest-flask==0.8.1'
]

docs_require = [
    'sphinx',
    'sphinxcontrib-httpdomain'
]

dev_requires = [
    'flake8>=2.0,<2.1',
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
    def make_distribution(self):
        self.run_command('build_static')
        return sdist.make_distribution(self)


class BuildStatic(Command):
    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        log.info("running [npm install --quiet]")
        check_output(['npm', 'install', '--quiet'], cwd=ROOT)

        log.info("running [gulp build]")
        check_output([os.path.join(ROOT, 'node_modules', '.bin', 'gulp'), 'build'], cwd=ROOT)
        log.info("running [gulp package]")
        check_output([os.path.join(ROOT, 'node_modules', '.bin', 'gulp'), 'package'], cwd=ROOT)

setup(
    name='lemur',
    version='0.1',
    author='Kevin Glisson',
    author_email='kglisson@netflix.com',
    long_description=open(os.path.join(ROOT, 'README.rst')).read(),
    packages=['lemur'],
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
            'cloudca_issuer = lemur.plugins.lemur_cloudca.plugin:CloudCAIssuerPlugin',
            'cloudca_source = lemur.plugins.lemur_cloudca.plugin:CloudCASourcePlugin',
            'aws_destination = lemur.plugins.lemur_aws.plugin:AWSDestinationPlugin',
            'aws_source = lemur.plugins.lemur_aws.plugin:AWSSourcePlugin',
            'email_notification = lemur.plugins.lemur_email.plugin:EmailNotificationPlugin',
        ],
    },
    classifiers=[
        'Framework :: Flask',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Operating System :: OS Independent',
        'Topic :: Software Development'
    ]
)
