kostal-RESTAPI
==========



Introduction
------------

This library provides a pure Python interface to access Kostal Inverters via currently undocumented RESTAPIs


Tested  with Python version 3.5, 3.6, 3.8, 3.10




Features
~~~~~~~~

* Read Events from Kostal Inverter
* Read DC, AC, Battery - and Statistics data 
* Write Battery MinSOC, MinHomeComsumption and DynamicSoc Parameters
* Write Shadow Management Parameters 
* Write Switched Output Parameters
* Accessible via commandline options


Tested with 
~~~~~~~~~~~~~~~~

* Raspberry & Windows
* Kostal Plenticore Plus 10 with connected BYD 6.4





Installation
------------
Clone / Download repo and use kostal-RESTAPI.py 


Getting started
---------------

To use ``kostal-RESTAPI`` in a project 
* take a look at the __main__ section in kostal-RESTAPI.py how to include it in your environment

* Command Line Usages:
	* python kostal-RESTAPI.py 
		This will set log on and read parameters
	* python kostal-RESTAPI.py -h 
		This will show you what commandline options are available



Disclaimer
----------

.. Warning::

   Please note that any incorrect or careless usage of this module as well as
   errors in the implementation may harm your Inverter !

   Therefore, the author does not provide any guarantee or warranty concerning
   to correctness, functionality or performance and does not accept any liability
   for damage caused by this module, examples or mentioned information.

   **Thus, use it on your own risk!**


License
-------

Distributed under the terms of the `GNU General Public License v3 <https://www.gnu.org/licenses/gpl-3.0.en.html>`_.
