.. zephyr:code-sample:: persistent_key
   :name: Persistent key

   Manage and use persistent keys via the Platform Security Architecture (PSA) Crypto API.

Overview
********

This sample demonstrates how to use the :ref:`PSA Crypto API <psa_crypto>` to generate and use persistent keys.

Requirements
************

In addition to the PSA Crypto API, an implementation of the PSA Internal Trusted Storage (ITS) API (for storage of the persistent keys) must be present for this sample to work.
It can be provided by:

* :ref:`tfm` (TF-M), for platforms supporting it.
* The :ref:`secure storage subsystem <secure_storage>`, for the other platforms.

Building
********

This sample is located in :zephyr_file:`samples/psa/persistent_key`.

Different configurations are defined in the :file:`sample.yaml` file.
You can use them to build the sample, depending on the platform to be built for, as follows:

.. tabs::

   .. tab:: TF-M

     For platforms with TF-M:

      .. zephyr-app-commands::
         :zephyr-app: samples/psa/persistent_key
         :tool: west
         :goals: build
         :board: <ns_platform>
         :west-args: -T sample.psa.persistent_key.tfm

   .. tab:: secure storage subsystem

      If the platform to be compiled for has an entropy driver (preferable):

      .. zephyr-app-commands::
         :zephyr-app: samples/psa/persistent_key
         :tool: west
         :goals: build
         :board: <platform>
         :west-args: -T sample.psa.persistent_key.secure_storage.entropy_driver

      Or, to use timer-based entropy (not secure):

      .. zephyr-app-commands::
         :zephyr-app: samples/psa/persistent_key
         :tool: west
         :goals: build
         :board: <platform>
         :west-args: -T sample.psa.persistent_key.secure_storage.entropy_not_secure

To flash it, see :ref:`west-flashing`.

References
**********

* `PSA Certified Crypto API <https://arm-software.github.io/psa-api/crypto/>`_

* `PSA Certified Internal Trusted Storage API reference <https://arm-software.github.io/psa-api/storage/1.0/api/api.html#internal-trusted-storage-api>`_
