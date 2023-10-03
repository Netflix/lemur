Security
========

We take the security of ``lemur`` seriously. The following are a set of
policies we have adopted to ensure that security issues are addressed in a
timely fashion.

Reporting a security issue
--------------------------

We ask that you do not report security issues to our normal GitHub issue
tracker.

If you believe you've identified a security issue with ``lemur``, please
report it using GitHub's `private vulnerability reporting process`_
in the [Lemur repository](https://github.com/Netflix/lemur/security/advisories/new).

Once you've submitted a report, you should receive an acknowledgment
within 48 hours, and depending on the action to be taken, you may receive
further follow-up.

Supported Versions
------------------

At any given time, we will provide security support for the `main`_ branch
as well as the most recent release.

Disclosure Process
------------------

Our process for taking a security issue from private discussion to public
disclosure involves multiple steps. Our standard process utilizes a GitHub Security Advisory.

The general process is as follows:

1. Receive a private report of a security issue via the `private vulnerability reporting process`_
2. Acknowledge receipt of the report
3. Post advance notice to the GitHub repo indicating that a security issue exists
4. Prepare a `GitHub Security Advisory`_
5. Merge code fix
6. Make Security Advisory public

**Private report**

After receiving a private report of a security issue, the reporter will receive notification
of the date on which we plan to make the issue public.

**Advance Notice**

Approximately one week before full public disclosure, we will provide advance notification that a security issue exists.
This will take the form of an issue posted to the Lemur repository.
The notification should contain the following, as appropriate
(details will only be shared to the extent that they do not highlight an unpatched vulnerability):

* A description of the potential impact
* The affected versions of ``lemur``
* The steps we will be taking to remedy the issue
* The date on which the ``lemur`` team will apply these patches, issue
  new releases, and publicly disclose the issue

If a reported issue is believed to be particularly time-sensitive – due to a
known exploit in the wild, for example – the time between advance notification
and public disclosure may be shortened considerably.

**GitHub Security Advisory**

During the (approximate) week between advance notice and public disclosure, we will prepare
a description of the security issue using a `GitHub Security Advisory`_.
The fix for the issue should also be prepared using the private fork provided by the security advisory.

**Day of Disclosure**

On the day of disclosure, we will take the following steps:

1. Merge relevant patches to the ``lemur`` repository (from the security advisory fork)
2. Issue an updated release
3. Make the security advisory public

.. _`master`: https://github.com/Netflix/lemur
.. _GitHub Security Advisory: https://docs.github.com/en/code-security/security-advisories/repository-security-advisories/about-repository-security-advisories
.. _private vulnerability reporting process: https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability