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
from setuptools.command.sdist import sdist
from setuptools import setup
from subprocess import check_output

ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__)))

install_requires=[
    'Flask>=0.10.1',
    'Flask-RESTful>=0.3.3',
    'Flask-SQLAlchemy>=1.0.5',
    'Flask-Script>=2.0.5',
    'Flask-Migrate>=1.4.0',
    'Flask-Bcrypt>=0.6.2',
    'Flask-Principal>=0.4.0',
    'SQLAlchemy-Utils>=0.30.11',
    'BeautifulSoup4',
    'requests>=2.7.0',
    'psycopg2>=2.6.1',
    'arrow>=0.5.4',
    'boto>=2.38.0',  # we might make this optional
    'six>=1.9.0',
    'gunicorn>=19.3.0',
    'pycrypto>=2.6.1',
    'cryptography>=0.9',
    'pyopenssl>=0.15.1',
    'pyjwt>=1.0.1',
    'xmltodict>=0.9.2'
]

tests_require = [
    'pyflakes',
    'moto',
    'nose',
    'pytest',
    'pytest-flask'
]

docs_require = [
    'sphinx',
    'sphinxcontrib-httpdomain'
]

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

        log.info("running [gulp buld]")
        check_output([os.path.join(ROOT, 'node_modules', '.bin', 'gulp'), 'build'], cwd=ROOT)

setup(
    name='lemur',
    version='0.1',
    author='Kevin Glisson',
    author_email='kglisson@netflix.com',
    long_description=open('README.rst').read(),
    packages=['lemur'],
    include_package_data=True,
    zip_safe=False,
    install_requires=install_requires,
    extras_require={
        'tests': tests_require,
        'docs': docs_require
    },
    cmdclass={
        'build_static': BuildStatic,
        'develop': DevelopWithBuildStatic,
        'sdist': SdistWithBuildStatic
    },
    entry_points={
        'console_scripts': [
            'lemur = lemur.manage:main',
        ],
        'lemur.plugins': [
            'verisign_issuer = lemur.plugins.lemur_verisign.plugin:VerisignIssuerPlugin',
            'cloudca_issuer = lemur.plugins.lemur_cloudca.plugin:CloudCAIssuerPlugin',
            'cloudca_source = lemur.plugins.lemur_cloudca.plugin:CloudCASourcePlugin'
            'aws_destination = lemur.plugins.lemur_aws.plugin:AWSDestinationPlugin',
            'aws_source = lemur.plugins.lemur_aws.plugin:AWSSourcePlugin'
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
