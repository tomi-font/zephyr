.. zephyr:code-sample:: psa_its
   :name: PSA ITS
   :relevant-api: psa_its

   Use the Platform Security Architecture (PSA) Internal Trusted Storage (ITS) API.

Overview
********

This sample demonstrates how to use the PSA ITS API to store and retrieve persistent data.

Requirements
************

An implementation of the PSA ITS API must be present for this sample to build.
It can be provided by:

* :ref:`tfm` (TF-M), for platforms supporting it.
* The :ref:`secure storage subsystem <secure_storage>`, for the other platforms.

Building
********

This sample is located in :zephyr_file:`samples/psa/its`.

Different configurations are defined in the :file:`sample.yaml` file.
You can use them to build the sample, depending on the platform to be built for, as follows:

.. tabs::

   .. tab:: TF-M

     For platforms with TF-M:

      .. zephyr-app-commands::
         :zephyr-app: samples/psa/its
         :tool: west
         :goals: build
         :board: <ns_platform>
         :west-args: -T sample.psa.its.tfm

   .. tab:: secure storage subsystem

      If the platform to be compiled for has an entropy driver (preferable):

      .. zephyr-app-commands::
         :zephyr-app: samples/psa/its
         :tool: west
         :goals: build
         :board: <platform>
         :west-args: -T sample.psa.its.secure_storage.entropy_driver

      Or, to use timer-based entropy (not secure):

      .. zephyr-app-commands::
         :zephyr-app: samples/psa/its
         :tool: west
         :goals: build
         :board: <platform>
         :west-args: -T sample.psa.its.secure_storage.entropy_not_secure

To flash it, see :ref:`west-flashing`.

References
**********

* `PSA Certified Internal Trusted Storage API reference <https://arm-software.github.io/psa-api/storage/1.0/api/api.html#internal-trusted-storage-api>`_
