README
======

caisopy-utils is a tool for CAISO

To install::

    $ sudo python setup.py install

Online documentation:

* http://caisopy-utils.readthedocs.org/en/latest/

Developers
----------
Bug report:

* https://bugs.launchpad.net/caisopy-utils

Repository:

* https://git.openstack.org/cgit/openstack/caisopy-utils

Cloning:

* git clone https://git.openstack.org/openstack/caisopy-utils

Patches are submitted via Gerrit at:

* https://review.openstack.org/

Please do not submit GitHub pull requests, they will be automatically closed.

More details on how you can contribute is available on our wiki at:

* http://docs.openstack.org/infra/manual/developers.html

Writing a patch
---------------

We ask that all code submissions be flake8_ clean.  The
easiest way to do that is to run tox_ before submitting code for
review in Gerrit.  It will run ``flake8`` in the same
manner as the automated test suite that will run on proposed
patchsets.

Installing without setup.py
---------------------------

Then install the required python packages using pip_::

    $ sudo pip install caisopy-utils

.. _flake8: https://pypi.python.org/pypi/flake8
   .. _tox: https://testrun.org/tox
      .. _pip: https://pypi.python.org/pypi/pip


.. rubric:: Footnotes

.. [#f1] The free `Cloudbees Folders Plugin
       <https://wiki.jenkins-ci.org/display/JENKINS/CloudBees+Folders+Plugin>`_
    provides support for a subset of the full folders functionality. For the
    complete capabilities you will need the paid for version of the plugin.

.. [#f2] The `Next Build Number Plugin
      <https://wiki.jenkins-ci.org/display/JENKINS/Next+Build+Number+Plugin>`_
   provides support for setting the next build number.
