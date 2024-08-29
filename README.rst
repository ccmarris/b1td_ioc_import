=======================
Infoblox Threat Defense
=======================

| Version: 0.0.1
| Author: Chris Marrison
| Email: chris@infoblox.com

Description
-----------

This is a demonstration script to show the ability to import IOC data from
either a CSV or JSON formatted file containing IOCs and either convert or
import this data for use in Infoblox products.

It allows you to take the source data, perform simple parsing of this data
and either:::

  - Create custom lists and apply these to an Infoblox Threat Defense security
    policy
  - Import into a TIDE data profile (TODO)
  - Output to a NIOS RPZ CSV import format (TODO)
  - Output to a simple CSV for use with your security ecosystem (TODO)


Prerequisites
-------------

Python 3.10 or above
bloxone module >= 0.8.10


Installing Python
~~~~~~~~~~~~~~~~~

You can install the latest version of Python 3.x by downloading the appropriate
installer for your system from `python.org <https://python.org>`_.

.. note::

  If you are running MacOS Catalina (or later) Python 3 comes pre-installed.
  Previous versions only come with Python 2.x by default and you will therefore
  need to install Python 3 as above or via Homebrew, Ports, etc.

  By default the python command points to Python 2.x, you can check this using 
  the command::

    $ python -V

  To specifically run Python 3, use the command::

    $ python3


.. important::

  Mac users will need the xcode command line utilities installed to use pip3,
  etc. If you need to install these use the command::

    $ xcode-select --install

.. note::

  If you are installing Python on Windows, be sure to check the box to have 
  Python added to your PATH if the installer offers such an option 
  (it's normally off by default).


Modules
~~~~~~~

Non-standard modules:

    - bloxone 0.8.10+

These are specified in the *requirements.txt* file.

The latest version of the bloxone module is available on PyPI and can simply be
installed using::

    pip3 install bloxone --user

To upgrade to the latest version::

    pip3 install bloxone --user --upgrade

Complete list of modules::

  import logging
  import bloxone
  import json
  import csv
  import os
  import shutil
  import argparse
  from importlib.metadata import version
  from packaging.version import Version, parse


Installation
------------

The simplest way to install and maintain the tools is to clone this 
repository::

    % git clone https://github.com/ccmarris/b1td_ioc_import


Alternative you can download as a Zip file.


Basic Configuration
-------------------

The script utilises a bloxone.ini file as used by the bloxone module.

bloxone.ini
~~~~~~~~~~~

The *bloxone.ini* file is used by the bloxone module to access the bloxone
API. A sample inifile for the bloxone module is shared as *bloxone.ini* and 
follows the following format provided below::

    [BloxOne]
    url = 'https://csp.infoblox.com'
    api_version = 'v1'
    api_key = '<you API Key here>'

Simply create and add your API Key, and this is ready for the bloxone
module used by the automation demo script. This inifile should be kept 
in a safe area of your filesystem. 

Use the --config/-c option to specify the ini file.


Usage
-----

In its current form the script uses either a CSV or JSON format file containing
IOC data. The aim is to provide a configurable field mapping to support greater
flexibility when importing data in to TIDE. However, in its current form a
simple IOC mapping is supported. 

There are two fields that can be configured from the CLI. The *datafield*
which allows you to define a simple JSON structure to locate the IOC data
using a dotted notation. The *iocfield* is then used to determine the field
name that contains the actual IOC in both CSV and JSON files.

For proof of concept the prime use of the IOC data is to take a sample dataset
and create appropriate Custom Lists within Infoblox Threat Defense Cloud 
and optionally automatically apply this to a security policy.

The data also be output to screen or file in either a simple CSV
file format or NIOS CSV import format to create an RPZ for use elsewhere 
in your security ecosystem, for instance import the RPZ CSV directly in to
NIOS.

This allows the script to be used for both demonstration purposes of the
automation capabilities provided by the Infoblox APIs.

The script supports -h or --help on the command line to access the options 
available::


  % ./b1td_ioc_import.py --help
  usage: b1td_ioc_import.py [-h] [-i INPUT] [-o OUTPUT] [-c CONFIG] [-D DATAFIELD] [-I IOCFIELD] [-p POLICY] [-d] -l CUSTOM_LIST

  

  options:
    -h, --help            show this help message and exit
    -i INPUT, --input INPUT
                          Input file <filename>
    -o OUTPUT, --output OUTPUT
                          Output to <filename>
    -c CONFIG, --config CONFIG
                          Overide Config file
    -D DATAFIELD, --datafield DATAFIELD
                          Json main datafield for IOCs
    -I IOCFIELD, --iocfield IOCFIELD
                          Fieldname for IOC data
    -p POLICY, --policy POLICY
                          Name of security policy to add custom lists
    -d, --debug           Enable debug messages
    -l CUSTOM_LIST, --custom_list CUSTOM_LIST
                          Base name for custom lists in BloxOne TD


Generate a simple CSV
~~~~~~~~~~~~~~~~~~~~~

Use this to generate a simple CSV of the transformed data this is a good test mode
to ensure script is working as expected with json data.

::

  % ./b1td_ioc_import.py --csv --input ioc-test.json


Generate NIOS RPZ CSV Import
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Use this to generate a CSV Import file for NIOS RPZ::

  % ./b1td_ioc_import.py --nios_csv --input ioc-test.csv


Create a Custom List in BloxOne Threat Defense
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This mode will automatically create a custom list in BloxOne Threat Defense
and optionally append the data to the specified security policy.  The script 
will automatically create the appropriate number of custom lists needed due 
to the 50,000 items per custom list and uses the base_name (-l/--custom_list) 
with a postfix of the format -N where N is a counter starting from 0. 
If there are less than 50k items then the base_name is used as is.

Examples::

  % ./b1td_ioc_import.py --config <path_to_ini> --custom_list <basename> --input ioc-test.csv
  % ./b1td_ioc_import.py --config <path_to_ini> --custom_list <basename> --policy <policy_name> --input ioc-test.csv


License
-------

This project, and the bloxone module are licensed under the 2-Clause BSD License
- please see LICENSE file for details.


Aknowledgements
---------------


