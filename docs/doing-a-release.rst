Doing a release
===============

Doing a release of ``lemur`` is now mostly automated and consists of the following steps:

* Raise a PR to add the release date and summary in the :doc:`/changelog`
* Merge above PR and create a new `Github release <https://github.com/Datadog/lemur/releases>`_: set the tag starting with v, e.g., v0.9.0
* Change the Helm chart to pick up the new version

Configuring Conductor/SDP to pick up the new version 
-----------------------------------

Once the CI/CD for Lemur succeedes and a new Github release is tagged then:

* Raise a PR and change `this line <https://github.com/DataDog/k8s-resources/blob/master/k8s/lemur/chart/values.yaml#L105>`_ to point to the new Githug tag
* Wait for Conductor to pick up the changes in the Helm chart (`schedule <https://github.com/DataDog/k8s-resources/blob/master/k8s/lemur/service.datadog.yaml#L27>`_)
* Check the status of the `deployment <https://sdp.ddbuild.io/#/services/details?name=lemur&service_tab=conductor&selectedTarget=staging>`_
