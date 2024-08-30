#!/usr/bin/env python3
# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
"""
------------------------------------------------------------------------

 Description:

 Take a source file containing IOCs and provide a mechanism to import
 or transform the data for use with Infoblox Products.

 Requirements:
  Requires bloxone >= 0.8.10

 Usage:
    Use b1td_country_ip_blocking.py --help for details on options

 Author: Chris Marrison

 Date Last Updated: 20240829

Copyright 2022 Chris Marrison / Infoblox

Redistribution and use in source and binary forms,
with or without modification, are permitted provided
that the following conditions are met:

1. Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

------------------------------------------------------------------------
"""
__version__ = '0.0.4'
__author__ = 'Chris Marrison'
__author_email__ = 'chris@infoblox.com'

import logging
import bloxone
import json
import csv
import os
import shutil
import argparse
from importlib.metadata import version
from packaging.version import Version, parse

# ** Global Variables **
log = logging.getLogger(__name__)

# Classes

class IOCReader():
    '''
    Read an input file in CSV or JSON format and make available as 
    object property self.iocs
    '''
    def __init__(self,
                 filename:str,
                 datafield:str = 'iocs',
                 iocfield:str = 'ioc',
                 mapping:str = 'field_map.yaml'):
        '''
        '''
        self.filename = filename
        self.datafield:str = datafield
        self.ioc_field:str = iocfield
        self.iocs:list = []

        self.read_file()

        return
    

    def read_file(self):
        '''
        Read JSON or CSV format file and return as property
        '''
        status = False
        data: list = []
        
        with open(self.filename) as f:
            try:
                data = json.load(f)
                log.info('Loaded JSON data')
                if self.datafield:
                    log.debug(f'Using datafield: {self.datafield}')
                    data = self.normalise_json(data)
            except json.decoder.JSONDecodeError:
                log.info('Reading CSV format')
                with open(self.filename, newline='') as f:
                    data = []
                    c = csv.DictReader(f)
                    for row in c:
                        data.append(row)
            except:
                raise
        if data:
            self.iocs = self.field_map(data)
            status = True
        
        return status


    def normalise_json(self, data:dict) -> list:
        '''
        Take json data and return the list of IOCs

        Parameters:
            data:dict = json data structure
        
        Returns:
            ioc_data:list = extracted list of ioc data or empty list
        '''
        ioc_data:list
        key_struct:list

        if '.' in self.datafield:
            key_struct = self.datafield.split('.')
            for k in key_struct:
                if k in data.keys():
                    log.debug(f'Key: {k} found in structure')
                    data = data.get(k)
                else:
                    log.error(f'Key: {k} not found in structure')
                    data = []
                    break
            ioc_data = data
        else:
            if self.datafield in data.keys():
                log.debug(f'Key: {self.datafield} found in structure')
                ioc_data = data.get(self.datafield)
            else:
                log.error(f'Key: {self.datafield} not found in structure')
                ioc_data = []
        
        return ioc_data
            
    
    def read_field_map(self):
        '''
        '''
        # with open(self.)
        return


    def field_map(self, data:list):
        '''
        Map the field containing the IOC to the correct type
        '''
        ioc_data:list = []
        mapped_ioc:dict = {}
        hostregex, urlregex = bloxone.utils.buildregex()

        for i in data:
            mapped_ioc = {}
            for k,v in i.items():
                if k == self.ioc_field:
                    # Check type
                    ioc_type = bloxone.utils.data_type(v,hostregex,urlregex)
                    if ioc_type == 'host':
                        mapped_ioc.update({'host': v})
                    elif ioc_type == 'ip':
                        mapped_ioc.update({'ip': v})
                    elif ioc_type == 'url':
                        mapped_ioc.update({'url': v})
                else:
                    mapped_ioc.update({k: v})                

            ioc_data.append(mapped_ioc)
        
        return ioc_data



class TDIMPORT():
    '''
    Create a Simple CSV, NIOS RPZ CSV or Custom List in Threat Defense

    TODO: TIDE Import
    '''

    def __init__(self,
                 ioc_data:list,
                 custom_list:str = '',
                 policy:str = '',
                 data_profile:str = '',
                 config:str = ''
                 ):
        '''
        Parameters:
            ioc_data (list): Parsed IOC data
            custom_list (str): base name of custom lists
            policy (str): Policy to add custom list to
            data_profile (str): TIDE data profile
            config (str): Full path for bloxone .ini file
        '''
        self.iocs:list = ioc_data
        self.custom_list:str = custom_list
        self.policy:str = policy
        self.data_profile:str = data_profile
        
        if config:
            self.b1 = bloxone.b1tdc(config)

        return

    def set_custom_list(self, name:str):
        '''
        Set custom_list property to name
        '''
        self.base_name = name
        return


    def set_policy_name(self, name:str):
        '''
        Set policy property to name
        '''
        self.policy = name
        return
    

    def set_data_profile(self, name:str):
        '''
        Set data profile property to name
        '''
        self.policy = name
        return


    def set_output_file(self, filename:str):
        '''
        Set output filename for CSV outputs
        '''
        self.filename = filename
        return


    def items_described(self):
        '''
        Create items_described list for TD custom list
        '''
        item:str =''
        description:list = []
        items_described:list = []

        for ioc in self.iocs:
            for k,v in ioc.items():
                if k in ['host', 'ip']:
                    item = v
                elif k == 'url':
                    log.warning(f'Ignoring URL: {v}')
                    item = None
                else:
                    description.append(f'{k}: {v}')

            if item:
                # Truncate to 255 chars if needed
                if len(description) > 255:
                    log.warning('Truncating fields for items_described')
                    description = description[:255]
                items_described.append({'item': item,
                                        'description': str(description) })
            
        return items_described


    def to_custom_lists(self, append=False):
        '''
        Create custom liss

        Parameters:
            append (bool): If list exists append data or not
        
        Returns:
            custom_lists (list): List containing custom list names created
        '''
        items_described = self.items_described()
        custom_lists = []
        failed_lists = []
        no_of_lists = 1
        item_count = 0
        max_items = 50000

        item_count = len(items_described)
        # Check number of items (limit of 50000 per custom list)
        if item_count > max_items:
            no_of_lists = (item_count // max_items)
            if (item_count % max_items) != 0:
                no_of_lists += 1
        else:
            no_of_lists = 1
        
        log.info(f'Creating {no_of_lists} custom lists - base name {self.base_name}')
        if no_of_lists == 1:
            if self.create_list(custom_list=self.base_name,
                                item_list=items_described):
                custom_lists.append(self.base_name)
            else:
                log.info(f'Failed to create custom list.')
                failed_lists.append(self.base_name)
        else:
            offset = 0
            items = max_items
            for n in range(no_of_lists):
                custom_list = f'{self.base_name}-{n}'
                if (n + 1) == no_of_lists:
                    items = item_count % max_items
                end = offset + items
                items_list = items_described[offset:end]
                if self.create_list(custom_list=custom_list, 
                               item_list=items_list):
                    custom_lists.append(custom_list)
                else:
                    failed_lists.append(custom_list)

                offset += max_items

        # Log summary
        no_created = len(custom_lists)
        log.info(f'Created {no_created} for {item_count} iocs.')
        if failed_lists:
            log.error(f'Failed to create {len(failed_lists)}')
        
        return custom_lists


    def create_list(self, custom_list='', item_list=[]):
        '''
        Create custom list

        Parameters:
            custom_list (str): name of custom list
            item_list (list): items_described structure
        
        Returns:
            status (bool): True if successful

        '''
        status = False
        id = self.b1.get_custom_list(name=custom_list)
        if not id:
            log.info(f'Creating custom list {custom_list} for {len(item_list)} items.')
            response = self.b1.create_custom_list(name=custom_list, 
                                                items_described=item_list)
            if response.status_code in self.b1.return_codes_ok:
                log.info(f'Successfully created custom list: {custom_list}')
                status = True
            else:
                log.error(f'Failed to create custom list: {custom_list}')
                log.error(f'HTTP Response Code: {response.status_code}')
                log.error(f'Content: {response.text}')
                status = False
        else:
            log.warning(f'Custom list {custom_list} exists')
            status = False

        return status


    def apply_custom_list(self):
        '''
        Add custom list to security policy

        Returns:
            Bool: True if successful
        '''
        status = False
        policy_id = self.b1.get_id('/security_policies', 
                                   key='name', value=self.policy)
        if policy_id:
            log.info(f'Retrieving security policy: {self.policy}')
            response = self.b1.get('/security_policies', id=policy_id)
            if response.status_code in self.b1.return_codes_ok:
                policy_data = response.json()['results']
                # Build rules for custom lists
                for custom_list in self.custom_lists:
                    policy_data['rules'].append({ "action": "action_block",
                                                "data": custom_list,
                                                "type": "custom_list" })
                # Update security policy
                log.info(f'Updating policy: {policy} with id {policy_id}')
                response = self.b1.put('/security_policies', 
                                    id=policy_id,
                                    body=json.dumps(policy_data))
                if response.status_code in self.b1.return_codes_ok:
                    log.info(f'Successfully updated security policy: {self.policy}')
                    status = True
                else:
                    log.error(f'Failed to update security policy: {self.policy}')
                    log.error(f'HTTP Response Code: {response.status_code}')
                    log.error(f'Content: {response.text}')
                    status = False
            else:
                log.error(f'Failed to retrieve security policy: {self.policy}')
                log.error(f'HTTP Response Code: {response.status_code}')
                log.error(f'Content: {response.text}')
                status = False
        else:
            log.error(f'Security policy {self.policy} not found')
            status = False

        return status
            

    def output_csv(self, filename:str = ''):
        '''
        Output IP list as CSV

        Parameters:
            outfile (obj): filehandler
        '''
        csvrow = ""
        csvheader = ""
        csvrow = ""

        if filename:
            outfile = self.open_file(filename=filename)
        else:
            outfile = None

        headers = self.iocs[0].keys()
        
        log.debug('Building CSV from dataset')
        # Build Header String
        for item in headers:
            csvheader += item + ','

        # Trim final comma
        csvheader = csvheader[:-1]

        # Output CSV Header
        if outfile:
            log.debug(f'Outputting header data to file: {outfile}')
            print(csvheader, file=outfile)
        else:
            log.debug(f'Outputting header data to stdout')
            print(csvheader)
        
        # Ootput CSV Data
        log.debug('Generating simple CSV rows')
        for ioc in self.iocs:
            csvrow = ""
            # Build CSV Row
            for column in headers:
                if column in ioc.keys():
                    csvrow += str(ioc[column]) + ','
                else:
                    csvrow += ','
            csvrow = csvrow[:-1]

            if outfile:
                print(csvrow, file=outfile)
            else:
                print(csvrow)
                
        return


    def output_nios_csv(self, 
                        zone='iocs.rpz.local', 
                        view='default',
                        filename=None):
        '''
        Create CSV in NIOS RPZ Import format

        Parameters:
            zone (str): rpz zone name
            rpz_parent (str): RPZ parent zone

        '''
        if filename:
            outfile = self.open_file(filename=filename)
        else:
            outfile = None

        reverse_labels = bloxone.utils.reverse_labels(zone)

        # Print CSV Header
        if outfile:
            print('header-responsepolicycnamerecord,fqdn*,_new_fqdn,canonical_name,' +
                'comment,disabled,parent_zone,ttl,view', file=outfile)
        else:
            print('header-responsepolicycnamerecord,fqdn*,_new_fqdn,canonical_name,' +
                'comment,disabled,parent_zone,ttl,view')

        # Process subnets and generate CSV lines
        for ioc in self.iocs:
            if 'host' in ioc.keys():
                host = ioc.get('host')
                line = ( f'responsepolicycnamerecord,{host}.{zone},,,,False,' +
                         f'{reverse_labels},,{view}' )
            elif 'ip' in ioc.keys():
                ip = bloxone.utils.reverse_labels(ioc.get('ip').replace('/', '.'))
                line = ( f'responsepolicycnamerecord,{ip}.{zone},,,,False,' +
                         f'{reverse_labels},,{view}' )
            else:
                log.warning(f'IOC is not a hostname: {ioc}')
            
            if outfile:
                print(line, file=outfile)
            else:
                print(line)

        return


    def open_file(self, filename):
        '''
        Attempt to open file for output

        Parameters:
            filename (str): Name of file to open.

        Returns:
            file handler object.

        '''
        if os.path.isfile(filename):
            backup = filename+".bak"
            try:
                shutil.move(filename, backup)
                log.info("Outfile exists moved to {}".format(backup))
                try:
                    handler = open(filename, mode='w')
                    log.info("Successfully opened output file {}.".format(filename))
                except IOError as err:
                    log.error("{}".format(err))
                    handler = False
            except shutil.Error:
                log.warning("Could not back up existing file {}, "
                            "exiting.".format(filename))
                handler = False
        else:
            try:
                handler = open(filename, mode='w')
                log.info("Successfully opened output file {}.".format(filename))
            except IOError as err:
                log.error("{}".format(err))
                handler = False

        return handler


# Demo script showing usage

# ** Functions **

def parseargs():
    '''
    Parse Arguments Using argparse

    Parameters:
        None

    Returns:
        Returns parsed arguments
    '''
    parse = argparse.ArgumentParser(description='B1TD IOC Data Import')
    exclusive = parse.add_mutually_exclusive_group(required=True)
    parse.add_argument('-i', '--input', type=str,
                       help="Input file <filename>", default="")
    parse.add_argument('-o', '--output', type=str,
                       help="Output to <filename>", default="")
    parse.add_argument('-c', '--config', type=str, default='',
                       help="Overide Config file")
    parse.add_argument('-D', '--datafield', type=str, default='iocs',
                       help="Json main datafield for IOCs")
    parse.add_argument('-I', '--iocfield', type=str, default='ioc',
                       help="Fieldname for IOC data")
    # parse.add_argument('-a', '--append', action='store_true',
                       # help="Append data to existing custom list")
    parse.add_argument('-p', '--policy', type=str,
                       help="Name of security policy to add custom lists")
    parse.add_argument('-d', '--debug', action='store_true',
                       help="Enable debug messages")
    exclusive.add_argument('-l', '--custom_list', type=str,
                       help="Base name for custom lists in BloxOne TD")
    exclusive.add_argument('-n', '--nios_csv', action='store_true',
                       help="Export NIOS RPZ CSV")
    exclusive.add_argument('-C', '--csv', action='store_true',
                       help="Export simple CSV")

    return parse.parse_args()


def setup_logging(debug:bool):
    '''
     Set up logging

     Parameters:
        debug (bool): True or False.

     Returns:
        None.

    '''
    # Set debug level
    if debug:
        logging.basicConfig(level=logging.DEBUG,
                            format='%(asctime)s %(levelname)s: %(message)s')
    else:
        logging.basicConfig(level=logging.INFO,
                            format='%(asctime)s %(levelname)s: %(message)s')

    return


def main():
    '''
    * Main *

    Core logic when running as script

    '''
    # Local variables
    exitcode = 0
    # Parse Arguments and configure
    args = parseargs()

    # Set up logging
    setup_logging(args.debug)

    I = IOCReader(filename=args.input,
                  datafield=args.datafield,
                  iocfield=args.iocfield)

    # Set up output file
    if args.output:
        outfile = open_file(args.output)
        if not outfile:
            log.error('Failed to open output file for CSV.')
    else:
        outfile = False


    TDI = TDIMPORT(ioc_data=I.iocs,
                   custom_list=args.custom_list,
                   policy=args.policy,
                   config=args.config)
    
    # Output selection
    if args.custom_list:
        TDI.to_custom_lists()
        if args.policy:
            TDI.apply_custom_list()
    elif args.csv:
        TDI.output_csv(filename=args.output)
    elif args.nios_csv:
        TDI.output_nios_csv(filename=args.output)
    else:
        log.error(f"Incompatible options specified try --help")
        exitcode = 1


    return exitcode


# ** Main **
if __name__ == '__main__':
    # Check bloxone module version
    b1_version = parse(version('bloxone'))
    required_version = Version('0.8.10')
    if b1_version >= required_version:
        exitcode = main()
    else:
        log.error(f'Requires bloxone module >=0.8.11 ' +
                      f'version {b1_version} installed')
        exitcode = 1
    raise SystemExit(exitcode)

# ** End Main **
