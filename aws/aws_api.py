#!/usr/bin/env python
#
import base64
import calendar
import copy
import datetime
import getpass
import json
import os
import pickle
import pprint
import readline
import socket
import stat
import sys
import time

from boto3.exceptions import *
import argparse
import boto3
import iso8601
import psycopg2
import requests


class awsInterface(object):
    """Class for working with statuspage.io
    """
    def __init__(self,cmdtype,aws_region_name='us-west-1'):
        """initialize framework here
        """
        self.cred = {}
        if 'debug' in globals() and debug > 0:
            print "cmdtype: %s" % str(cmdtype)
        if type(cmdtype) != str:
            cmdtype = "cmd"
        if cmdtype.find("cmd") >= 0:
            self.set_credentials()
        elif cmdtype.find("Input") >= 0:
            self.input_credentials()
        elif cmdtype.find('Stored') >= 0:
            self.load_credentials()
        elif cmdtype.find('Set') >= 0:
            self.input_credentials()
            self.store_credentials()
        else:
            self.load_credentials()
        self.session = boto3.Session(aws_access_key_id=self.cred['aws_access_key_id'],\
                                     aws_secret_access_key=base64.b64decode(self.cred['aws_secret_access_key']),\
                                     region_name=aws_region_name
                                     )
        self.client = {}
        self.network_acls = {}
        self.region_list = {}
        self.route_tables_index = {}
        self.vpc_index = {}
        self.vpn_connections_index = {}
        
        """Other API Describe Calls available for the future:
        describe_bundle_tasks()
        describe_classic_link_instances()
        describe_conversion_tasks()
        describe_customer_gateways()
        describe_egress_only_internet_gateways()
        describe_export_tasks()
        describe_flow_logs()
        describe_host_reservation_offerings()
        describe_host_reservations()
        describe_hosts()
        describe_iam_instance_profile_associations()
        describe_id_format()
        describe_identity_id_format()
        describe_image_attribute()
        describe_images()
        describe_import_image_tasks()
        describe_import_snapshot_tasks()
        describe_instance_attribute()
        describe_instance_status()
        describe_internet_gateways()
        describe_moving_addresses()
        describe_nat_gateways()
        describe_network_interface_attribute()
        describe_network_interfaces()
        describe_placement_groups()
        describe_prefix_lists()
        describe_regions()
        describe_reserved_instances()
        describe_reserved_instances_listings()
        describe_reserved_instances_modifications()
        describe_reserved_instances_offerings()
        describe_scheduled_instance_availability()
        describe_scheduled_instances()
        describe_security_group_references()
        describe_snapshot_attribute()
        describe_snapshots()
        describe_spot_datafeed_subscription()
        describe_spot_fleet_instances()
        describe_spot_fleet_request_history()
        describe_spot_fleet_requests()
        describe_spot_instance_requests()
        describe_spot_price_history()
        describe_stale_security_groups()
        describe_volume_attribute()
        describe_volume_status()
        describe_volumes_modifications()
        describe_vpc_attribute()
        describe_vpc_classic_link()
        describe_vpc_classic_link_dns_support()
        describe_vpc_endpoint_services()
        describe_vpc_endpoints()
        describe_vpc_peering_connections()
        describe_vpn_connections()
        describe_vpn_gateways()
        """
        return
    
    def set_credentials(self):
        """For self-contained script without password on file system
        """
        if 'debug' in globals() and debug > 0:
            print "In awsInterface.set_credentials"
        self.cred['aws_access_key_id'] = "insert_key_id_here"
        self.cred['aws_secret_access_key'] = "insert_secret_key_here"
        return
    
    def load_credentials(self):
        """Loads up the credentials and decodes them from
        the locally stored file .awsInterface  Note that
        passwords are not stored in plain text on disk
        nor in memory.
        """
        if 'debug' in globals() and debug > 0:
            print "Enter load credentials"
        if os.path.exists('.awsInterface'):
            infile = open('.awsInterface','rb')
            self.cred = pickle.load(infile)
            #self.p4_cred['Password'] = base64.b64decode(self.p4_cred['Password'])
            infile.close()
        else:
            self.set_credentials()
            self.store_credentials()
        infile.close()
        if 'debug' in globals() and debug > 0:
            print "Loaded credentials "
            print "aws_access_key_id: %s" % self.cred['aws_access_key_id']
            print "(Obfuscated) aws_secret_access_key: %s" % self.cred['aws_secret_access_key']
            #print "aws_secret_access_key: %s" % base64.b64decode(self.cred['aws_secret_access_key'])
        return
    
    def store_credentials(self):
        """Encodes and stores the current working credentials.
        Passwords are not stored in plain text on disk nor
        in memory.
        """
        if 'debug' in globals() and debug > 0:
            print "Enter store credentials"
        if 'aws_access_key_id' not in self.cred.keys():
            if 'debug' in globals() and debug > 0:
                print "No aws_access_key_id - storing default"
            self.cred['aws_access_key_id'] = "insert_aws_access_key_id_here"
        if 'aws_secret_access_key' not in self.cred.keys():
            if 'debug' in globals() and debug > 0:
                print "No aws_secret_access_key - storing default"
            self.cred['aws_secret_access_key'] = base64.b64encode("insert_aws_secret_access_key_here")
        outfile = open('.awsInterface','wb')
        pickle.dump(self.cred,outfile)
        outfile.close()
        os.chmod('.awsInterface', stat.S_IRWXU)
        if 'debug' in globals() and debug > 0:
            print "Storing:"
            print "aws_access_key_id: %s" % self.cred['aws_access_key_id']
            print "(obfuscated) aws_secret_access_key: %s" % self.cred['aws_secret_access_key']
            #print "aws_secret_access_key: %s" % base64.b64decode(self.cred['aws_secret_access_key'])
        return
    
    def input_credentials(self):
        """Provides you with a way to input the necessary
        credentials and then store them securely with store_credentials.
        """
        if 'debug' in globals() and debug > 0:
            print "In input_credentials"
        try:
            self.cred['aws_access_key_id'] = raw_input('aws_access_key_id: ')
        except EOFError:
            print "Error: PEBCAK - EOF received - using default aws_access_key_id of 'insert_aws_access_key_id_here'"
            self.cred['dbserver'] = "insert_aws_access_key_id_here"
        try:
            self.cred['aws_secret_access_key'] = base64.b64encode(getpass.getpass('aws_secret_access_key:'))
        except EOFError:
            print "Error: PEBCAK - EOF received - using default aws_secret_access_key of 'insert_aws_secret_access_key_here'"
            self.cred['aws_secret_access_key'] = base64.b64encode("insert_token_here")
        if 'debug' in globals() and debug > 0:
            print "Results:"
            print "aws_secret_access_key (obfuscated): %s" % self.cred['aws_secret_access_key']
            #print "aws_secret_access_key: %s" % base64.b64decode(self.cred['aws_secret_access_key'])
        return
    
    def print_all_dicts(self,depth=None):
        """Method to pprint out all of the dicts in our object
        """
        for key in self.__dict__.keys():
            print "\n%s:" % key
            eval('pprint.pprint(self.'+key+',depth='+str(depth)+')')
        return
    
    def create_client(self,aws_service_name='ec2',aws_region_name=''):
        """Method to create a low level client to access descriptions etc
        """
        if len(aws_region_name)<1:
            aws_region_name = self.session.region_name
        if 'debug' in globals() and debug > 0:
            print "in awsInterface.create_client with:"
            print "service: %s" % aws_service_name
            print "region: %s" % aws_region_name
        if aws_region_name not in self.client.keys():
            self.client[aws_region_name] = {}
        if aws_service_name not in self.client[aws_region_name].keys():
            if 'debug' in globals() and debug > 0:
                print 'service %s no open for region %s - creating client' % (aws_service_name,aws_region_name)
            self.client[aws_region_name][aws_service_name] = self.session.client(service_name=aws_service_name,\
                                                            region_name = aws_region_name)
        else:
            if 'debug' in globals() and debug > 0:
                print 'service %s already open for region %s - skipping create' % (aws_service_name,aws_region_name)
        return
    
    def get_regions(self):
        """Method to download the region list
        """
        if 'debug' in globals() and debug > 0:
            print "in awsInterface.get_regions"
        self.create_client()
        region = self.client.keys()[0]
        if 'ec2' not in self.client[region].keys():
            if 'debug' in globals() and debug > 0:
                print "Creating EC2 resource"
            self.create_client('ec2',region)
        results = self.client[region]['ec2'].describe_regions()
        if 'debug' in globals() and debug > 0:
                pprint.pprint(results)
        for index in range(len(results['Regions'])):
            if results['Regions'][index]['RegionName'] not in self.region_list.keys():
                self.region_list[results['Regions'][index]['RegionName']] = results['Regions'][index]
        return
    
    def get_availability_zones(self):
        """Method to download the availability zones for a existing clients
        """
        if 'debug' in globals() and debug > 0:
            print "in awsInterface.get_availability_zones"
        if len(self.client.keys()) > 0:
            if 'debug' in globals() and debug > 0:
                print "in self.client.keys() walk"
            for region in self.client.keys():
                if 'debug' in globals() and debug > 0:
                    print "in region %s" % region
                if 'ec2' not in self.client[region].keys():
                    self.create_client('ec2', region)
                if 'debug' in globals() and debug > 0:
                    print "region %s has ec2 client open:" % (region)
                azones = self.client[region]['ec2'].describe_availability_zones()
                if 'availability_zones' not in self.client[region].keys():
                    self.client[region]['availability_zones'] = {}
                if 'debug' in globals() and debug > 0:
                    pprint.pprint(azones)
                for index in range(len(azones['AvailabilityZones'])):
                    if 'debug' in globals() and debug > 0:
                        print "Adding zone %s" % azones['AvailabilityZones'][index]['ZoneName']
                    self.client[region]['availability_zones'][azones['AvailabilityZones'][index]['ZoneName']]=\
                                                              azones['AvailabilityZones'][index]
        return
    
    def get_all_availability_zones(self):
        """Method to iterate list of region names and get all availability zones
        """
        if 'debug' in globals() and debug > 0:
            print "in awsInterface.get_all_availability_zones"
        if len(self.region_list) < 1:
            self.get_regions()
        for region in self.region_list.keys():
            self.create_client('s3',region)
        self.get_availability_zones()
        return
    
    def get_vpcs(self):
        """Method to download the availability zones for a existing clients
        """
        if 'debug' in globals() and debug > 0:
            print "in awsInterface.get_vpcs"
        if len(self.client.keys()) > 0:
            if 'debug' in globals() and debug > 0:
                print "in self.client.keys() walk"
            for region in self.client.keys():
                if 'debug' in globals() and debug > 0:
                    print "in region %s" % region
                if 'ec2' not in self.client[region].keys():
                    self.create_client('ec2', region)
                if 'debug' in globals() and debug > 0:
                    print "region %s has ec2 client open:" % (region)
                vpcs = self.client[region]['ec2'].describe_vpcs()
                if 'vpcs' not in self.client[region].keys():
                    self.client[region]['vpcs'] = {}
                if 'debug' in globals() and debug > 0:
                    pprint.pprint(vpcs)
                for index in range(len(vpcs['Vpcs'])):
                    vpcid = vpcs['Vpcs'][index]['VpcId']
                    if 'debug' in globals() and debug > 0:
                        print "Adding vpc %s" % vpcid
                    self.client[region]['vpcs'][vpcid] = vpcs['Vpcs'][index]
                    if vpcid not in self.vpc_index.keys():
                        self.vpc_index[vpcid] = {}
                        self.vpc_index[vpcid]['name'] = ''
                        if 'Tags' in vpcs['Vpcs'][index].keys():
                            self.vpc_index[vpcid]['tags'] = vpcs['Vpcs'][index]['Tags']
                            for index2 in range(len(vpcs['Vpcs'][index]['Tags'])):
                                if vpcs['Vpcs'][index]['Tags'][index2]['Key'].find('Name') == 0:
                                    self.vpc_index[vpcid]['name'] = vpcs['Vpcs'][index]['Tags'][index2]['Value']
                        else:
                            self.vpc_index[vpcid]['tags'] = {}
                        if 'CidrBlock' in vpcs['Vpcs'][index].keys():
                            self.vpc_index[vpcid]['cidr'] = vpcs['Vpcs'][index]['CidrBlock']
                        else:
                            self.vpc_index[vpcid]['cidr'] = {}
                        self.vpc_index[vpcid]['region'] = region
                    else:
                        print "** Error: vpcid already found once"
        return
    
    def get_all_vpcs(self):
        """Method to iterate list of region names and get all availability zones
        """
        if 'debug' in globals() and debug > 0:
            print "in awsInterface.get_all_vpcs"
        if len(self.region_list) < 1:
            self.get_regions()
        for region in self.region_list.keys():
            self.create_client('s3',region)
        self.get_vpcs()
        return
        
    def get_vpn_connections(self):
        """Method to download the availability zones for a existing clients
        """
        if 'debug' in globals() and debug > 0:
            print "in awsInterface.get_vpn_connections"
        if len(self.client.keys()) > 0:
            if 'debug' in globals() and debug > 0:
                print "in self.client.keys() walk"
            for region in self.client.keys():
                if 'debug' in globals() and debug > 0:
                    print "in region %s" % region
                if 'ec2' not in self.client[region].keys():
                    self.create_client('ec2', region)
                if 'debug' in globals() and debug > 0:
                    print "region %s has ec2 client open:" % (region)
                vpn_connections = self.client[region]['ec2'].describe_vpn_connections()
                if 'vpn_connections' not in self.client[region].keys():
                    self.client[region]['vpn_connections'] = {}
                if 'debug' in globals() and debug > 0:
                    pprint.pprint(vpn_connections)
                for index in range(len(vpn_connections['VpnConnections'])):
                    vpnid = vpn_connections['VpnConnections'][index]['VpnConnectionId']
                    if 'debug' in globals() and debug > 0:
                        print "Adding vpn %s" % vpnid
                    self.client[region]['vpn_connections'][vpnid] = vpn_connections['VpnConnections'][index]
                    if 'CustomerGatewayConfiguration' in self.client[region]['vpn_connections'][vpnid].keys():
                        self.client[region]['vpn_connections'][vpnid]['CustomerGatewayConfiguration'] = 'redacted'
                    if vpnid not in self.vpn_connections_index.keys():
                        self.vpn_connections_index[vpnid] = {}
                        self.vpn_connections_index[vpnid]['name'] = ''
                        if 'Tags' in vpn_connections['VpnConnections'][index].keys():
                            self.vpn_connections_index[vpnid]['tags'] = vpn_connections['VpnConnections'][index]['Tags']
                            for index2 in range(len(vpn_connections['VpnConnections'][index]['Tags'])):
                                if vpn_connections['VpnConnections'][index]['Tags'][index2]['Key'].find('Name') == 0:
                                    self.vpn_connections_index[vpnid]['name'] = vpn_connections['VpnConnections'][index]['Tags'][index2]['Value']
                        else:
                            self.vpn_connections_index[vpnid]['tags'] = {}
                        if 'VpnGatewayId' in vpn_connections['VpnConnections'][index].keys():
                            self.vpn_connections_index[vpnid]['vpn_gateway_id'] = \
                                 vpn_connections['VpnConnections'][index]['VpnGatewayId']
                        else:
                            self.vpn_connections_index[vpnid]['vpn_gateway_id'] = {}
                        if 'CustomerGatewayId' in vpn_connections['VpnConnections'][index].keys():
                            self.vpn_connections_index[vpnid]['customer_gateway_id'] = \
                                 vpn_connections['VpnConnections'][index]['CustomerGatewayId']
                        else:
                            self.vpn_connections_index[vpnid]['customer_gateway_id'] = {}
                        if 'VgwTelemetry' in vpn_connections['VpnConnections'][index].keys():
                            self.vpn_connections_index[vpnid]['peering'] = \
                                 vpn_connections['VpnConnections'][index]['VgwTelemetry']
                        else:
                            self.vpn_connections_index[vpnid]['peering'] = {}
                        if 'State' in vpn_connections['VpnConnections'][index].keys():
                            self.vpn_connections_index[vpnid]['state'] = \
                                 vpn_connections['VpnConnections'][index]['State']
                        else:
                            self.vpn_connections_index[vpnid]['state'] = {}
                        if 'Type' in vpn_connections['VpnConnections'][index].keys():
                            self.vpn_connections_index[vpnid]['type'] = \
                                 vpn_connections['VpnConnections'][index]['Type']
                        else:
                            self.vpn_connections_index[vpnid]['type'] = {}
                        
                        self.vpn_connections_index[vpnid]['region'] = region
                    else:
                        print "** Error: vpnid already found once"
        return
    
    def get_all_vpn_connections(self):
        """Method to iterate list of region names and get all availability zones
        """
        if 'debug' in globals() and debug > 0:
            print "in awsInterface.get_all_vpn_connections"
        if len(self.region_list) < 1:
            self.get_regions()
        for region in self.region_list.keys():
            self.create_client('s3',region)
        self.get_vpn_connections()
        return
        
    
    def get_instances(self):
        """Method to download the instances for existing clients
        """
        if 'debug' in globals() and debug > 0:
            print "in awsInterface.get_instances"
        if len(self.client.keys()) > 0:
            if 'debug' in globals() and debug > 0:
                print "in self.client.keys() walk"
            for region in self.client.keys():
                if 'debug' in globals() and debug > 0:
                    print "in region %s" % region
                if 'ec2' not in self.client[region].keys():
                    self.create_client('ec2', region)
                if 'debug' in globals() and debug > 0:
                    print "region %s has ec2 client open:" % (region)
                results = self.client[region]['ec2'].describe_instances()
                if 'instances' not in self.client[region].keys():
                    self.client[region]['instances'] = {}
                if 'debug' in globals() and debug > 0:
                    pprint.pprint(results)
                for index in range(len(results['Reservations'])):
                    if 'Instances' in results['Reservations'][index].keys():
                        instances = results['Reservations'][index]['Instances']
                    else:
                        instances = []
                    if 'debug' in globals() and debug > 0:
                        print "Instance count is %d" % len(instances)
                    for index2 in range(len(instances)):
                        if 'debug' in globals() and debug > 0:
                            print "Processing instance %d" % index2
                            if debug > 1:
                                pprint.pprint(instances[index2])
                        iname = instances[index2]['InstanceId']
                        self.client[region]['instances'][iname] = instances[index2]
        return
    
    def get_all_instances(self):
        """Method to iterate list of region names and get all instances
        """
        if 'debug' in globals() and debug > 0:
            print "in awsInterface.get_all_instancess"
        if len(self.region_list) < 1:
            self.get_regions()
        for region in self.region_list.keys():
            self.create_client('s3',region)
        self.get_instances()
        return
        
    def get_network_acls(self):
        """Method to download the network acls for existing regions
        """
        if 'debug' in globals() and debug > 0:
            print "in awsInterface.get_network_acls"
        if len(self.client.keys()) > 0:
            if 'debug' in globals() and debug > 0:
                print "in self.client.keys() walk"
            for region in self.client.keys():
                if 'debug' in globals() and debug > 0:
                    print "in region %s" % region
                if 'ec2' not in self.client[region].keys():
                    self.create_client('ec2', region)
                if 'debug' in globals() and debug > 0:
                    print "region %s has ec2 client open:" % (region)
                results = self.client[region]['ec2'].describe_network_acls()
                if 'acls' not in self.client[region].keys():
                    self.client[region]['acls']={}
                if 'debug' in globals() and debug > 0:
                    pprint.pprint(results)
                if region not in self.network_acls.keys():
                    self.network_acls[region] = {}
                for index in range(len(results['NetworkAcls'])):
                    if 'NetworkAclId' in results['NetworkAcls'][index].keys():
                        networkaclid = results['NetworkAcls'][index]['NetworkAclId']
                        self.client[region]['acls'][networkaclid] = results['NetworkAcls'][index]
                        self.network_acls[region][networkaclid] = {}
                        self.network_acls[region][networkaclid]['associations'] = \
                                          results['NetworkAcls'][index]['Associations']
                        self.network_acls[region][networkaclid]['entries'] = {}
                        self.network_acls[region][networkaclid]['entries']['in'] = {}
                        self.network_acls[region][networkaclid]['entries']['out'] = {}
                    else:
                        self.network_acls[region] = []
                    if 'debug' in globals() and debug > 0:
                        print "entry count is %d" % len(results['NetworkAcls'][index]['Entries'])
                    for index2 in range(len(results['NetworkAcls'][index]['Entries'])):
                        if 'debug' in globals() and debug > 0:
                            print "Processing entry %d" % index2
                            if debug > 1:
                                pprint.pprint(acl[index2])
                        entryno = int(results['NetworkAcls'][index]['Entries'][index2]['RuleNumber'])
                        if results['NetworkAcls'][index]['Entries'][index2]['Egress']:
                            direction = 'out'
                        else:
                            direction = 'in'
                        if direction not in self.network_acls[region][networkaclid]['entries'].keys():
                            self.network_acls[region][networkaclid]['entries'][direction] = {}
                        self.network_acls[region][networkaclid]['entries'][direction][entryno] = \
                                        results['NetworkAcls'][index]['Entries'][index2]
        return
        
    def get_all_network_acls(self):
        """Method to iterate list of region names and get all network acls
        """
        if 'debug' in globals() and debug > 0:
            print "in awsInterface.get_all_network_acls"
        if len(self.region_list) < 1:
            self.get_regions()
        for region in self.region_list.keys():
            self.create_client('s3',region)
        self.get_network_acls()
        return
        
    def get_subnets(self):
        """Method to download the subnets for existing clients
        """
        if 'debug' in globals() and debug > 0:
            print "in awsInterface.get_subnets"
        if len(self.client.keys()) > 0:
            if 'debug' in globals() and debug > 0:
                print "in self.client.keys() walk"
            for region in self.client.keys():
                if 'debug' in globals() and debug > 0:
                    print "in region %s" % region
                if 'ec2' not in self.client[region].keys():
                    self.create_client('ec2', region)
                if 'debug' in globals() and debug > 0:
                    print "region %s has ec2 client open:" % (region)
                results = self.client[region]['ec2'].describe_subnets()
                if 'subnets' not in self.client[region].keys():
                    self.client[region]['subnets'] = {}
                if 'debug' in globals() and debug > 0:
                    pprint.pprint(results)
                subnets = results['Subnets']
                if 'debug' in globals() and debug > 0:
                    print "Subnet count is %d" % len(subnets)
                for index in range(len(subnets)):
                    if 'debug' in globals() and debug > 0:
                        print "Processing subnet %d" % index
                        if debug > 1:
                            pprint.pprint(subnets[index])
                    subnetname = subnets[index]['SubnetId']
                    self.client[region]['subnets'][subnetname] = subnets[index]
        return
    
    def get_all_subnets(self):
        """Method to iterate list of region names and get all subnets
        """
        if 'debug' in globals() and debug > 0:
            print "in awsInterface.get_all_subnets"
        if len(self.region_list) < 1:
            self.get_regions()
        for region in self.region_list.keys():
            self.create_client('s3',region)
        self.get_subnets()
        return
    
    def get_volumes(self):
        """Method to download the volumes for existing clients
        """
        if 'debug' in globals() and debug > 0:
            print "in awsInterface.get_volumes"
        if len(self.client.keys()) > 0:
            if 'debug' in globals() and debug > 0:
                print "in self.client.keys() walk"
            for region in self.client.keys():
                if 'debug' in globals() and debug > 0:
                    print "in region %s" % region
                if 'ec2' not in self.client[region].keys():
                    self.create_client('ec2', region)
                if 'debug' in globals() and debug > 0:
                    print "region %s has ec2 client open:" % (region)
                results = self.client[region]['ec2'].describe_volumes()
                if 'volumes' not in self.client[region].keys():
                    self.client[region]['volumes'] = {}
                if 'debug' in globals() and debug > 0:
                    pprint.pprint(results)
                volumes = results['Volumes']
                if 'debug' in globals() and debug > 0:
                    print "Volume count is %d" % len(volumes)
                for index in range(len(volumes)):
                    if 'debug' in globals() and debug > 0:
                        print "Processing volume %d" % index
                        if debug > 1:
                            pprint.pprint(volumes[index])
                    volumename = volumes[index]['VolumeId']
                    self.client[region]['volumes'][volumename] = volumes[index]
        return
    
    def get_all_volumes(self):
        """Method to iterate list of region names and get all volumes
        """
        if 'debug' in globals() and debug > 0:
            print "in awsInterface.get_all_volumes"
        if len(self.region_list) < 1:
            self.get_regions()
        for region in self.region_list.keys():
            self.create_client('s3',region)
        self.get_volumes()
        return
    
    def get_addresses(self):
        """Method to download the addresses for existing clients
        """
        if 'debug' in globals() and debug > 0:
            print "in awsInterface.get_addresses"
        if len(self.client.keys()) > 0:
            if 'debug' in globals() and debug > 0:
                print "in self.client.keys() walk"
            for region in self.client.keys():
                if 'debug' in globals() and debug > 0:
                    print "in region %s" % region
                if 'ec2' not in self.client[region].keys():
                    self.create_client('ec2', region)
                if 'debug' in globals() and debug > 0:
                    print "region %s has ec2 client open:" % (region)
                results = self.client[region]['ec2'].describe_addresses()
                if 'addresses' not in self.client[region].keys():
                    self.client[region]['addresses'] = {}
                if 'debug' in globals() and debug > 0:
                    pprint.pprint(results)
                addresses = results['Addresses']
                if 'debug' in globals() and debug > 0:
                    print "address count is %d" % len(addresses)
                for index in range(len(addresses)):
                    if 'debug' in globals() and debug > 0:
                        print "Processing address %d" % index
                        if debug > 1:
                            pprint.pprint(addresses[index])
                    addressname = addresses[index]['AllocationId']
                    self.client[region]['addresses'][addressname] = addresses[index]
        return
    
    def get_all_addresses(self):
        """Method to iterate list of region names and get all addresses
        """
        if 'debug' in globals() and debug > 0:
            print "in awsInterface.get_all_addresses"
        if len(self.region_list) < 1:
            self.get_regions()
        for region in self.region_list.keys():
            self.create_client('s3',region)
        self.get_addresses()
        return
    
    def get_dhcp_options(self):
        """Method to download the dhcp_options for existing clients
        """
        if 'debug' in globals() and debug > 0:
            print "in awsInterface.get_dhcp_options"
        if len(self.client.keys()) > 0:
            if 'debug' in globals() and debug > 0:
                print "in self.client.keys() walk"
            for region in self.client.keys():
                if 'debug' in globals() and debug > 0:
                    print "in region %s" % region
                if 'ec2' not in self.client[region].keys():
                    self.create_client('ec2', region)
                if 'debug' in globals() and debug > 0:
                    print "region %s has ec2 client open:" % (region)
                results = self.client[region]['ec2'].describe_dhcp_options()
                if 'dhcp_options' not in self.client[region].keys():
                    self.client[region]['dhcp_options'] = {}
                if 'debug' in globals() and debug > 0:
                    pprint.pprint(results)
                dhcp_options = results['DhcpOptions']
                if 'debug' in globals() and debug > 0:
                    print "dhcp options count is %d" % len(dhcp_options)
                for index in range(len(dhcp_options)):
                    if 'debug' in globals() and debug > 0:
                        print "Processing dhcp options %d" % index
                        if debug > 1:
                            pprint.pprint(dhcp_options[index])
                    dhcp_options_name = dhcp_options[index]['DhcpOptionsId']
                    self.client[region]['dhcp_options'][dhcp_options_name] = dhcp_options[index]
        return
    
    def get_all_dhcp_options(self):
        """Method to iterate list of region names and get all dhcp_options
        """
        if 'debug' in globals() and debug > 0:
            print "in awsInterface.get_all_dhcp_options"
        if len(self.region_list) < 1:
            self.get_regions()
        for region in self.region_list.keys():
            self.create_client('s3',region)
        self.get_dhcp_options()
        return
    
    def get_key_pairs(self):
        """Method to download the key_pairs for existing clients
        """
        if 'debug' in globals() and debug > 0:
            print "in awsInterface.get_key_pairs"
        if len(self.client.keys()) > 0:
            if 'debug' in globals() and debug > 0:
                print "in self.client.keys() walk"
            for region in self.client.keys():
                if 'debug' in globals() and debug > 0:
                    print "in region %s" % region
                if 'ec2' not in self.client[region].keys():
                    self.create_client('ec2', region)
                if 'debug' in globals() and debug > 0:
                    print "region %s has ec2 client open:" % (region)
                results = self.client[region]['ec2'].describe_key_pairs()
                if 'key_pairs' not in self.client[region].keys():
                    self.client[region]['key_pairs'] = {}
                if 'debug' in globals() and debug > 0:
                    pprint.pprint(results)
                key_pairs = results['KeyPairs']
                if 'debug' in globals() and debug > 0:
                    print "Key Pair count is %d" % len(key_pairs)
                for index in range(len(key_pairs)):
                    if 'debug' in globals() and debug > 0:
                        print "Processing key pair %d" % index
                        if debug > 1:
                            pprint.pprint(key_pairs[index])
                    key_pairs_name = key_pairs[index]['KeyName']
                    self.client[region]['key_pairs'][key_pairs_name] = key_pairs[index]
        return
    
    def get_all_key_pairs(self):
        """Method to iterate list of region names and get all key_pairs
        """
        if 'debug' in globals() and debug > 0:
            print "in awsInterface.get_all_key_pairs"
        if len(self.region_list) < 1:
            self.get_regions()
        for region in self.region_list.keys():
            self.create_client('s3',region)
        self.get_key_pairs()
        return
    
    def get_route_tables(self):
        """Method to download the route_tables for existing clients
        """
        if 'debug' in globals() and debug > 0:
            print "in awsInterface.get_route_tables"
        if len(self.client.keys()) > 0:
            if 'debug' in globals() and debug > 0:
                print "in self.client.keys() walk"
            for region in self.client.keys():
                if 'debug' in globals() and debug > 0:
                    print "in region %s" % region
                if 'ec2' not in self.client[region].keys():
                    self.create_client('ec2', region)
                if 'debug' in globals() and debug > 0:
                    print "region %s has ec2 client open:" % (region)
                results = self.client[region]['ec2'].describe_route_tables()
                if 'route_tables' not in self.client[region].keys():
                    self.client[region]['route_tables'] = {}
                if 'route_tables_cidr' not in self.client[region].keys():
                    self.client[region]['route_tables_cidr'] = {}
                if 'debug' in globals() and debug > 0:
                    pprint.pprint(results)
                route_tables = results['RouteTables']
                if 'debug' in globals() and debug > 0:
                    print "Route table count is %d" % len(route_tables)
                for index in range(len(route_tables)):
                    if 'debug' in globals() and debug > 0:
                        print "Processing route table %d" % index
                        if debug > 1:
                            pprint.pprint(route_tables[index])
                    route_tables_name = route_tables[index]['RouteTableId']
                    if route_tables_name not in self.route_tables_index.keys():
                        self.route_tables_index[route_tables_name] = {}
                        self.route_tables_index[route_tables_name]['tags'] = {}
                        self.route_tables_index[route_tables_name]['name'] = {}
                        self.route_tables_index[route_tables_name]['vpcid'] = {}
                        if 'VpcId' in route_tables[index].keys():
                            self.route_tables_index[route_tables_name]['vpcid'] = \
                                                   route_tables[index]['VpcId']
                        if 'Tags' in route_tables[index].keys():
                            self.route_tables_index[route_tables_name]['tags'] = route_tables[index]['Tags']
                            for index2 in range(len(route_tables[index]['Tags'])):
                                if route_tables[index]['Tags'][index2]['Key'].find('Name') == 0:
                                    if 'name' not in self.route_tables_index.keys():
                                        self.route_tables_index[route_tables_name]['name'] = \
                                            route_tables[index]['Tags'][index2]['Value']
                                    else:
                                        print "** Error: route table name already found"
                    self.client[region]['route_tables'][route_tables_name] = route_tables[index]
                    if route_tables_name not in self.client[region]['route_tables'].keys():
                        self.client[region]['route_tables'][route_tables_name] = {}
                    if route_tables_name not in self.client[region]['route_tables_cidr'].keys():
                        self.client[region]['route_tables_cidr'][route_tables_name] = {}
                    for index2 in range(len(route_tables[index]['Routes'])):
                        if 'DestinationCidrBlock' in route_tables[index]['Routes'][index2].keys():
                            if 'debug' in globals() and debug > 0:
                                print "Processing IPv4 CIDR Block"
                            cidr = route_tables[index]['Routes'][index2]['DestinationCidrBlock']
                            cidrlen = int(cidr.split('/')[1])
                            if cidrlen < 10:
                                slen='0'+str(cidrlen)
                            else:
                                slen = str(cidrlen)
                            quads = cidr.split('/')[0].split('.')
                            ips = ['{0:03d}'.format(int(quads[0])),\
                                   '{0:03d}'.format(int(quads[1])),\
                                   '{0:03d}'.format(int(quads[2])),\
                                   '{0:03d}'.format(int(quads[3]))]
                            ipaddr=ips[0]+'.'+ips[1]+'.'+ips[2]+'.'+ips[3]
                            destcidr=ipaddr+'/'+slen
                        elif 'DestinationIpv6CidrBlock' in route_tables[index]['Routes'][index2].keys():
                            cidr = route_tables[index]['Routes'][index2]['DestinationIpv6CidrBlock']
                            destcidr = cidr
                        else:
                            destcidr = 'unknown'
                            cidr = 'unknown'
                        if destcidr not in self.client[region]['route_tables_cidr'][route_tables_name].keys():
                            self.client[region]['route_tables_cidr'][route_tables_name][destcidr] = {}
                        self.client[region]['route_tables_cidr'][route_tables_name][destcidr]['gateway']=\
                                route_tables[index]['Routes'][index2]['GatewayId']
                        self.client[region]['route_tables_cidr'][route_tables_name][destcidr]['origin']=\
                                route_tables[index]['Routes'][index2]['Origin']
                        self.client[region]['route_tables_cidr'][route_tables_name][destcidr]['state']=\
                                route_tables[index]['Routes'][index2]['State']
                        self.client[region]['route_tables_cidr'][route_tables_name][destcidr]['cidr']=cidr
        return
    
    def get_all_route_tables(self):
        """Method to iterate list of region names and get all route_tables
        """
        if 'debug' in globals() and debug > 0:
            print "in awsInterface.get_all_route_tables"
        if len(self.region_list) < 1:
            self.get_regions()
        for region in self.region_list.keys():
            self.create_client('s3',region)
        self.get_route_tables()
        return
    
    def get_security_groups(self):
        """Method to download the security_groups for existing clients
        """
        if 'debug' in globals() and debug > 0:
            print "in awsInterface.get_security_groups"
        if len(self.client.keys()) > 0:
            if 'debug' in globals() and debug > 0:
                print "in self.client.keys() walk"
            for region in self.client.keys():
                if 'debug' in globals() and debug > 0:
                    print "in region %s" % region
                if 'ec2' not in self.client[region].keys():
                    self.create_client('ec2', region)
                if 'debug' in globals() and debug > 0:
                    print "region %s has ec2 client open:" % (region)
                results = self.client[region]['ec2'].describe_security_groups()
                if 'security_groups' not in self.client[region].keys():
                    self.client[region]['security_groups'] = {}
                if 'debug' in globals() and debug > 0:
                    pprint.pprint(results)
                security_groups = results['SecurityGroups']
                if 'debug' in globals() and debug > 0:
                    print "Security Group count is %d" % len(security_groups)
                for index in range(len(security_groups)):
                    if 'debug' in globals() and debug > 0:
                        print "Processing security group %d" % index
                        if debug > 1:
                            pprint.pprint(security_groups[index])
                    security_groups_name = security_groups[index]['GroupName']
                    self.client[region]['security_groups'][security_groups_name] = security_groups[index]
        return
    
    def get_all_security_groups(self):
        """Method to iterate list of region names and get all security_groups
        """
        if 'debug' in globals() and debug > 0:
            print "in awsInterface.get_all_security_groups"
        if len(self.region_list) < 1:
            self.get_regions()
        for region in self.region_list.keys():
            self.create_client('s3',region)
        self.get_security_groups()
        return
    
    def get_resource_id_tags(self):
        """Method to download the resource_id_tags for existing clients
        """
        if 'debug' in globals() and debug > 0:
            print "in awsInterface.get_resource_id_tags"
        if len(self.client.keys()) > 0:
            if 'debug' in globals() and debug > 0:
                print "in self.client.keys() walk"
            for region in self.client.keys():
                if 'debug' in globals() and debug > 0:
                    print "in region %s" % region
                if 'ec2' not in self.client[region].keys():
                    self.create_client('ec2', region)
                if 'debug' in globals() and debug > 0:
                    print "region %s has ec2 client open:" % (region)
                results = self.client[region]['ec2'].describe_tags()
                if 'resource_id_tags' not in self.client[region].keys():
                    self.client[region]['resource_id_tags'] = {}
                if 'debug' in globals() and debug > 0:
                    pprint.pprint(results)
                resource_id_tags = results['Tags']
                if 'debug' in globals() and debug > 0:
                    print "Tags count is %d" % len(resource_id_tags)
                for index in range(len(resource_id_tags)):
                    if 'debug' in globals() and debug > 0:
                        print "Processing resource id tag %d" % index
                        if debug > 1:
                            pprint.pprint(resource_id_tags[index])
                    resource_id_name = resource_id_tags[index]['ResourceId']
                    tagname = resource_id_tags[index]['Key']
                    if resource_id_name not in self.client[region]['resource_id_tags'].keys():
                        self.client[region]['resource_id_tags'][resource_id_name] = {}
                    if tagname not in self.client[region]['resource_id_tags'][resource_id_name].keys():
                        self.client[region]['resource_id_tags'][resource_id_name][tagname] = {}
                    self.client[region]['resource_id_tags'][resource_id_name][tagname] = \
                                        resource_id_tags[index]
        return
    
    def get_all_resource_id_tags(self):
        """Method to iterate list of region names and get all resource_id_tags
        """
        if 'debug' in globals() and debug > 0:
            print "in awsInterface.get_all_resource_id_tags"
        if len(self.region_list) < 1:
            self.get_regions()
        for region in self.region_list.keys():
            self.create_client('s3',region)
        self.get_resource_id_tags()
        return
    
    def get_all(self):
        """Method to call each of the get_all_ methods
        """
        if 'debug' in globals() and debug > 0:
            print "in awsInterface.get_all"
        self.get_regions()
        self.get_all_vpcs()
        self.get_vpn_connections()
        self.get_addresses()
        self.get_availability_zones()
        self.get_dhcp_options()
        self.get_instances()
        self.get_key_pairs()
        self.get_network_acls()
        self.get_resource_id_tags()
        self.get_route_tables()
        self.get_security_groups()
        self.get_subnets()
        self.get_volumes()
        return
    

def cmd_shell(args):
    global debug
    debug = int(args['debug'])
    return None

def main():
    
    parser = argparse.ArgumentParser(description=\
             'Manage statuspage.io services')
    
    metavar='{test'
    metavar = metavar + ',shell' # uncomment to enable clean python -i shell access
    metavar = metavar + '}'
    subparsers = parser.add_subparsers(metavar=metavar)
    
    """  Comment out this shell section to restrict easy interactive access"""
    #"""
    shell_parser = subparsers.add_parser('shell', help = 'Shell')
    shell_parser.set_defaults(func=cmd_shell)
    shell_parser.add_argument('-debug', action='store', type = int, default=0,
                    dest='debug', help='Debug level 0-9')
    #"""
    cl = {}
    results = {}
    args = {}
    try:
        cl=parser.parse_args()
        for x in cl.__dict__:
            if 'debug' in globals() and debug > 0:
                print "checking argument [%s] = %s" % (x,str(cl.__dict__[x]))
            if "func" not in str(cl.__dict__[x]) or \
               len(str(cl.__dict__[x])) != 4:
                if (('dict' in repr(type(cl.__dict__[x]))) or 
                   ('list' in repr(type(cl.__dict__[x])))):
                    args[str(x)]=str(cl.__dict__[x][0])
                else:
                    args[str(x)]=str(cl.__dict__[x])
        results = cl.func(args)
    except SystemExit:
        pass
    finally:
        pass
    return {'parser': parser,'cl': cl,'args': args,'results': results}

if __name__ == "__main__":
    session = main()
