Doing a release
===============

Doing a release of ``lemur`` requires a few steps.

Bumping the version number
--------------------------

The next step in doing a release is bumping the version number in the
software.

* Update the version number in ``lemur/__about__.py``.
* Set the release date in the :doc:`/changelog`.
* Do a commit indicating this, and raise a pull request with this.
* Wait for it to be merged.

Performing the release
----------------------

The commit that merged the version number bump is now the official release
commit for this release. You need an `API key <https://pypi.org/manage/account/#api-tokens>`_,
which requires permissions to maintain the Lemur `project  <https://pypi.org/project/lemur/>`_.

For creating the release, follow these steps (more details `here <https://packaging.python.org/tutorials/packaging-projects/#generating-distribution-archives>`_)

* Make sure you have the latest versions of setuptools and wheel installed:

    ``python3 -m pip install --user --upgrade setuptools wheel``

* Now run this command from the same directory where setup.py is located:

    ``python3 setup.py sdist bdist_wheel``

* Once completed it should generate two files in the dist directory:

.. code-block:: pycon

    $ ls dist/
    lemur-0.8.0-py2.py3-none-any.whl	lemur-0.8.0.tar.gz


* In this step, the distribution will be uploaded. You’ll need to install Twine:

    ``python3 -m pip install --user --upgrade twine``

* Once installed, run Twine to upload all of the archives under dist. Once installed, run Twine to upload all of the archives under dist:

    ``python3 -m twine upload --repository pypi dist/*``

The release should now be available on `PyPI Lemur <https://pypi.org/project/lemur/>`_ and a tag should be available in
the repository.

Make sure to also make a github `release <https://github.com/Netflix/lemur/releases>`_ which will pick up the latest version.

Verifying the release
---------------------

You should verify that ``pip install lemur`` works correctly:

.. code-block:: pycon

    >>> import lemur
    >>> lemur.__version__
    '...'

Verify that this is the version you just released.

Post-release tasks
------------------

* Update the version number to the next major (e.g. ``0.5.dev1``) in
  ``lemur/__about__.py`` and
* Add new :doc:`/changelog` entry with next version and note that it is under
  active development
* Send a pull request with these items
* Check for any outstanding code undergoing a deprecation cycle by looking in
  ``lemur.utils`` for ``DeprecatedIn**`` definitions. If any exist open
  a ticket to increment them for the next release.
