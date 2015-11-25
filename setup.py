"""
Lemur
=====

Is a TLS management and orchestration tool.

:copyright: (c) 2015 by Netflix, see AUTHORS for more
:license: Apache, see LICENSE for more details.
"""
from __future__ import absolute_import

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

install_requires = [
    'Flask==0.10.1',
    'Flask-RESTful==0.3.4',
    'Flask-SQLAlchemy==2.1',
    'Flask-Script==2.0.5',
    'Flask-Migrate==1.6.0',
    'Flask-Bcrypt==0.7.1',
    'Flask-Principal==0.4.0',
    'Flask-Mail==0.9.1',
    'SQLAlchemy-Utils==0.31.3',
    'BeautifulSoup4==4.4.1',
    'requests==2.8.1',
    'psycopg2==2.6.1',
    'arrow==0.7.0',
    'boto==2.38.0',  # we might make this optional
    'six==1.10.0',
    'gunicorn==19.3.0',
    'pycrypto==2.6.1',
    'cryptography==1.1.1',
    'pyopenssl==0.15.1',
    'pyjwt==1.4.0',
    'xmltodict==0.9.2',
    'lockfile==0.11.0',
    'future==0.15.2',
]

tests_require = [
    'pyflakes',
    'moto==0.4.18',
    'nose==1.3.7',
    'pytest==2.8.3',
    'pytest-flask==0.10.0'
]

docs_require = [
    'sphinx',
    'sphinxcontrib-httpdomain'
]

dev_requires = [
    'flake8>=2.0,<3.0',
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
    name='lemur',
    version='0.1.5',
    author='Kevin Glisson',
    author_email='kglisson@netflix.com',
    url='https://github.com/netflix/lemur',
    download_url='https://github.com/Netflix/lemur/archive/0.1.3.tar.gz',
    description='Certificate management and orchestration service',
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
            'aws_destination = lemur.plugins.lemur_aws.plugin:AWSDestinationPlugin',
            'aws_source = lemur.plugins.lemur_aws.plugin:AWSSourcePlugin',
            'email_notification = lemur.plugins.lemur_email.plugin:EmailNotificationPlugin',
            'java_export = lemur.plugins.lemur_java.plugin:JavaExportPlugin'
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
