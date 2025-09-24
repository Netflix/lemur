"""Basic package information"""

from __future__ import absolute_import
from setuptools import setup, find_packages

install_requires = ["lemur", "datadog"]

setup(
    name="lemur_statsd",
    version="1.0.0",
    author="Cloudflare Security Engineering",
    author_email="",
    include_package_data=True,
    packages=find_packages(),
    zip_safe=False,
    install_requires=install_requires,
    entry_points={"lemur.plugins": ["statsd = lemur_statsd.plugin:StatsdMetricPlugin"]},
)
