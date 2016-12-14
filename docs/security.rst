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
report it to ``cloudsecurity@netflix.com``.

Once you've submitted an issue via email, you should receive an acknowledgment
within 48 hours, and depending on the action to be taken, you may receive
further follow-up emails.

Supported Versions
------------------

At any given time, we will provide security support for the `master`_ branch
as well as the 2 most recent releases.

Disclosure Process
------------------

Our process for taking a security issue from private discussion to public
disclosure involves multiple steps.

Approximately one week before full public disclosure, we will send advance
notification of the issue to a list of people and organizations, primarily
composed of operating-system vendors and other distributors of
``lemur``.  This notification will consist of an email message
containing:

* A full description of the issue and the affected versions of
  ``lemur``.
* The steps we will be taking to remedy the issue.
* The patches, if any, that will be applied to ``lemur``.
* The date on which the ``lemur`` team will apply these patches, issue
  new releases, and publicly disclose the issue.

Simultaneously, the reporter of the issue will receive notification of the date
on which we plan to make the issue public.

On the day of disclosure, we will take the following steps:

* Apply the relevant patches to the ``lemur`` repository. The commit
  messages for these patches will indicate that they are for security issues,
  but will not describe the issue in any detail; instead, they will warn of
  upcoming disclosure.
* Issue the relevant releases.

If a reported issue is believed to be particularly time-sensitive – due to a
known exploit in the wild, for example – the time between advance notification
and public disclosure may be shortened considerably.

The list of people and organizations who receives advanced notification of
security issues is not, and will not, be made public. This list generally
consists of high-profile downstream distributors and is entirely at the
discretion of the ``lemur`` team.

.. _`master`: https://github.com/Netflix/lemur
