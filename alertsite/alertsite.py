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

import argparse
import iso8601
import requests


class alertSite(object):
    """Class for managing and accessing AlertSite
    """
    def __init__(self,environment,cmdtype="cmd"):
        """Initialize the cred dictionary and environment properties
        """
        self.cred = {}
        self.environment = environment[:]
        self.session = ''
        self.issued = ''
        self.expires = ''
        self.default_column = 40
        self.monitors = {}
        self.monitor_keys = []
        self.locations = {}
        if 'debug' in globals() and debug > 0:
            print "Environment: %s" % environment
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
        self.get_token()
        return
    
    def set_credentials(self):
        """For self-contained script without password on file system
        """
        if 'debug' in globals() and debug > 0:
            print "In alertSite.set_credentials"
        self.cred['Login'] = "login"
        self.cred['Password'] = base64.b64encode("password")
        self.cred['Production'] = "https://www.alertsite.com/alertsite-restapi"
        return
    
    def load_credentials(self):
        """Loads up the credentials and decodes them from
        the locally stored file .alertsite  Note that
        passwords are not stored in plain text on disk
        nor in memory.
        """
        if 'debug' in globals() and debug > 0:
            print "Enter load credentials"
        if os.path.exists('.alertsite'):
            infile = open('.alertsite','rb')
            self.cred = pickle.load(infile)
            #self.p4_cred['Password'] = base64.b64decode(self.p4_cred['Password'])
            infile.close()
        else:
            self.set_credentials()
            self.store_credentials()
        if 'debug' in globals() and debug > 0:
            print "Loaded obfuscated password ,%s>" % self.cred['Password']
        #self.cred['Password'] = base64.b64decode(self.cred['Password'])
        infile.close()
        if 'debug' in globals() and debug > 0:
            print "Loaded credentials "
            print "Login: %s" % self.cred['Login']
            #print "Password: %s" % self.cred['Password']
        return
    
    def store_credentials(self):
        """Encodes and stores the current working credentials.
        Passwords are not stored in plain text on disk nor
        in memory.
        """
        if 'debug' in globals() and debug > 0:
            print "Enter store credentials"
        if 'Login' not in self.cred.keys():
            if 'debug' in globals() and debug > 0:
                print "No Login Key - storing default"
            self.cred['Login'] = "login"
        if 'Password' not in self.cred.keys():
            if 'debug' in globals() and debug > 0:
                print "No Password Key - storing default"
            self.cred['Password'] = base64.b64encode("password")
        if 'Production' not in self.cred.keys():
            if 'debug' in globals() and debug > 0:
                print "No Production Key - storing default"
            self.cred['Production'] = "https://www.alertsite.com/alertsite-restapi"
        outfile = open('.alertsite','wb')
        #self.cred['Password'] = base64.b64encode(self.cred['Password'])
        pickle.dump(self.cred,outfile)
        outfile.close()
        os.chmod('.alertsite', stat.S_IRWXU)
        if 'debug' in globals() and debug > 0:
            print "Storing:"
            print "Login: %s" % self.cred['Login']
            #print "Password: %s" % self.cred['Password']
            print "Production: %s" % self.cred['Production']
        return
    
    def input_credentials(self):
        """Provides you with a way to input the necessary
        credentials and then store them securely with store_credentials.
        """
        if 'debug' in globals() and debug > 0:
            print "In input_credentials"
        try:
            self.cred['Login'] = raw_input('Login: ')
        except EOFError:
            print "Error: PEBCAK - EOF received - using default Login of 'login'"
            self.cred['Login'] = "login"
        try:
            self.cred['Password'] = base64.b64encode(getpass.getpass('Password:'))
        except EOFError:
            print "Error: PEBCAK - EOF received - using default Password of 'password'"
            self.cred['Password'] = base64.b64encode("password")
        self.cred['Production'] = "https://www.alertsite.com/alertsite-restapi"
        if 'debug' in globals() and debug > 0:
            print "Results:"
            print "Login: %s" % self.cred['Login']
            #print "Password: %s" % self.cred['Password']
            print "Production: %s" % self.cred['Production']
        return
    
    def palign(self,title,col,text):
        """Internal method to format an output line
        set self.default_column to the column you want to use
        """
        print title+"."*(col-len(title))+text
        return
    
    def print_login(self):
        """Print the Login from the credentials
        """
        self.palign("Login:",self.default_column,self.cred['Login'])
        return
    
    def print_password(self):
        """Print the Password from the credentials
        """
        self.palign("Password:",self.default_column,self.cred['Password'])
        return
    
    def print_production(self):
        """Print the Production URL from the credentials
        """
        self.palign("Production:",self.default_column,self.cred['Production'])
        return
    
    def print_environment(self):
        """Print the current working Environment
        """
        self.palign("Environment:",self.default_column,self.environment)
        return
    
    def print_session(self):
        """Print the current Access Token
        """
        self.palign("Access Token:",self.default_column, self.session)
        return
    
    def print_issued(self):
        """Print the Issued datetime for the Access Token
        """
        if type(self.issued) == datetime.datetime:
            self.palign("Issued:",self.default_column,self.issued.strftime("%m/%d/%y %H:%M:%S UTC"))
        else:
            self.palign("Issued:",self.default_column,str(self.issued))
        return
    
    def print_expires(self):
        """Print the expires datetime for the Access Token
        """
        if type(self.expires) == datetime.datetime:
            self.palign("Expires:",self.default_column,self.expires.strftime("%m/%d/%y %H:%M:%S UTC"))
        else:
            self.palign("Expires:",self.default_column,str(self.expires))
        return
    
    def print_cred(self):
        """Method to print the current credentials
        """
        if 'debug' in globals() and debug > 0:
            print "enter print_cred"
        self.print_login()
        #self.print_password()
        self.print_production()
        self.print_environment()
        self.print_session()
        self.print_issued()
        self.print_expires()
        return
    
    def get_token(self):
        """Performs the initial authentication with AlertSite
        and gets a working token and refresh token
        """
        headers = {
            'Content-type': 'application/json',
        }
        jheaders = json.dumps(headers)
        payload = {
          "login":      str(self.cred['Login']),
          "password":   str(base64.b64decode(self.cred['Password']))
        }
        jpayload = str('{"login":"'+self.cred['Login']+'"'+\
                      ',"password":"'+ base64.b64decode(self.cred['Password'])+'"'+\
                      '}')
        if 'debug' in globals() and debug > 0:
            print "headers:"
            pprint.pprint(headers)
            print "json of headers:"
            print jheaders
            print "payload:"
            pprint.pprint(payload)
            print "jpayload:"
            print jpayload
            print "json of payload:"
            print json.dumps(payload)
        authok=0
        while authok<1:
            if 'debug' in globals() and debug > 0:
                print "About to perform token request with AlertSite"
            s = requests.post(self.cred[self.environment]+'/login', headers=headers, data=json.dumps(payload))
            response=s.json()
            if 'debug' in globals() and debug > 0:
                pprint.pprint(response)
            if int(response['metadata']['status']) != 0:
                message = response['metadata']['message']
                raise Exception('Error - bad AlertSite Authentication ['+message+']')
            else:
                payload['password'] = self.cred['Password']
                jpayload = json.dumps(payload)
                if 'debug' in globals() and debug > 0:
                    print "Authentication succeeded - continuing"
                authok=1
                self.issued = datetime.datetime.utcnow()
                issued_tstamp = utc_to_timestamp(self.issued)
                if 'debug' in globals() and debug > 0:
                    print "Issued timestamp is %f" % issued_tstamp
                self.expires = datetime.datetime.utcfromtimestamp(utc_to_timestamp(self.issued) + 900)
                self.session = response['metadata']['session']
                if 'debug' in globals() and debug > 0:
                    self.print_issued()
                    self.print_expires()
                    self.print_session()
        return
    
    def check_token(self):
        """Checks and if needed, updates the token
        """
        if utc_to_timestamp(self.expires) < utc_to_timestamp(datetime.datetime.utcnow()):
            self.get_token()
        return
    
    def add_location(self,location,monitor_name):
        """Method to take the location(s) sent with a monitor
        and store them for reference by ID.
        """
        if 'xref' not in self.locations.keys():
            self.locations['xref'] = {}
        if location['id'] not in self.locations.keys():
            self.locations[str(location['id'])] = {}
            self.locations[str(location['id'])]['name'] = location['name']
            self.locations[str(location['id'])]['id'] = location['id']
            self.locations[str(location['id'])]['monitors'] = []
            self.locations[str(location['id'])]['monitors'].append(monitor_name)
            if location['name'] not in self.locations['xref'].keys():
                self.locations['xref'][location['name']] = {}
                self.locations['xref'][location['name']]['id'] = location['id']
                self.locations['xref'][location['name']]['name'] = location['name']
                self.locations['xref'][location['name']]['monitors'] = [] 
            self.locations['xref'][location['name']]['monitors'].append(monitor_name)
        else:
            if monitor_name not in self.locations[str(location['id'])]['monitors']:
                self.locations[str(location['id'])]['monitors'].append(monitor_name)
            if location['name'] not in self.locations['xref'].keys():
                self.locations['xref'][location['name']] = {}
                self.locations['xref'][location['name']]['id'] = location['id']
                self.locations['xref'][location['name']]['name'] = location['name']
                self.locations['xref'][location['name']]['monitors'] = [] 
            self.locations['xref'][location['name']]['monitors'].append(monitor_name)
        return
    
    def print_location_by_id(self,location_id):
        """Method to print out the properties of a location indexed by id number
        """
        print
        if location_id in self.locations.keys():
            print 'Location ID: '+location_id+' ('+\
                  self.locations[location_id]['name']+')'
            if len(self.locations[location_id]['monitors']) > 0:
                for index2 in range(0,len(self.locations[location_id]['monitors'])):
                    self.palign('monitor',self.default_column,\
                                self.locations[location_id]['monitors'][index2])
        else:
            print 'Location ID not found'
        print
        return
    
    def print_location_by_name(self,location_name):
        """Method to print out the monitors using a particular location.
        """
        print
        if location_name in self.locations['xref'].keys():
            print 'Location Name: '+location_name+' ('+\
                  self.locations['xref'][location_name]['id']+')'
            for index2 in range(0,len(self.locations['xref'][location_name]['monitors'])):
                self.palign('monitor',self.default_column,\
                            self.locations['xref'][location_name]['monitors'][index2])
        else:
            print 'Location Name not found'
        print
        return
    
    def print_all_locations(self):
        """Method to print out all monitors.
        """
        print
        for location in sorted(self.locations['xref'].keys()):
            self.print_location_by_name(location)
            print
        print
        return
    
    def add_monitor(self,monitor,force=False):
        """Method to take a monitor returned from AlertSite and store it locally.
        """
        for keyname in sorted(monitor.keys()):
            if len(self.monitor_keys) < 1 or keyname not in self.monitor_keys:
                self.monitor_keys.append(str(keyname))
        if (monitor['name'] not in self.monitors.keys()) or force:
            self.monitors[monitor['name']] = copy.deepcopy(monitor)
            if 'debug' in globals() and debug > 0:
                print "locations = %s" % type(self.monitors[monitor['name']]['locations'])
            if len(self.monitors[monitor['name']]['locations']) > 0:
                for index in range(0,len(self.monitors[monitor['name']]['locations'])):
                    self.add_location(self.monitors[monitor['name']]['locations'][index],\
                                      monitor['name'])
                    if 'debug' in globals() and debug > 0:
                        print "Added location %s" % self.monitors[monitor['name']]\
                                                     ['locations'][index]['name']
            if 'debug' in globals() and debug > 0:
                print "added/updated monitor %s" % monitor['name']
        else:
            if 'debug' in globals() and debug > 0:
                print 'Skipping %s - monitor already exists' % monitor['name']
        return
    
    def print_monitor(self,monitor_name):
        """Method to print out the properties of a monitor.
        """
        print 'Monitor Name: '+monitor_name+' ('+self.monitors[monitor_name]['id']+')'
        for keyname in sorted(self.monitor_keys):
            if keyname.find('locations') < 0 and \
               keyname.find('name') < 0 and \
               keyname.find('id') < 0:
                self.palign(keyname,self.default_column,self.monitors[monitor_name][keyname])
            elif keyname.find('locations') >= 0:
                for index2 in range(0,len(self.monitors[monitor_name]['locations'])):
                    self.palign('location',self.default_column,\
                                self.monitors[monitor_name][keyname][index2]['name'])
        return
    
    def print_all_monitors(self):
        """Method to print out all monitors.
        """
        print
        print
        for monitor in sorted(self.monitors.keys()):
            self.print_monitor(monitor)
            print
        print
        return
    
    def load_monitors(self):
        """Gets a list of all monitors
        from AlertSite.  
        """
        if 'debug' in globals() and debug > 0:
            print "enter load_monitors"
        headers = {
            'Content-type': 'application/json',
            'Authorization': 'Bearer '+base64.b64encode(self.cred['Login']+':'+self.session)
        }
        payload = { 'show_scripts': 1 }
        if 'debug' in globals() and debug > 0:
            print "in load_monitors"
        s = requests.get(self.cred[self.environment]+'/devices', params = payload, headers=headers)
        response=s.json()
        if 'debug' in globals() and debug > 1:
            print "Received the following response from our first request:"
            pprint.pprint(response)
        errcount = 0
        while (int(response['metadata']['status']) > 0 and errcount < 5):
            errcount += 1
            if 'debug' in globals() and debug > 0:
                print "Error received - retrying:"
                pprint.pprint(response)
            self.get_token()
            s = requests.get(self.cred[self.environment]+'/devices', params = payload, headers=headers)
            response=s.json()
            if 'debug' in globals() and debug > 1:
                print "Received the following response from request #%d:" % (errcount+1)
                pprint.pprint(response)
        if errcount > 4:
            raise NameError('Fatal error downloading monitors')
        if 'debug' in globals() and debug > 0:
            print "monitor download request successful"
            print "type of results: %s" % type(response['results'])
        for monitor in response['results']:
            self.add_monitor(monitor)
        return { 'asite': self }
    

def utc_to_timestamp(dt, epoch=datetime.datetime(1970,1,1)):
    """used when calculating exactly when a token will expire
    thereby allowing us to check the datetime against the clock
    and decide if we need to get a token refresh.  Python datetime
    lets us go from timestamps to datetime objects but not vice
    versa.  Probably because of the issue of UTC vs. local time.
    In my case I only deal with UTC to make it simple.
    """
    td = dt - epoch
    timediff = (td.microseconds + ((td.seconds + (td.days * (24 * 3600))) * 10**6)) / 1e6
    if 'debug' in globals() and debug > 0:
        print "dt = %s" % dt.strftime("%m/%d/%y %H:%M:%S %z")
        print "epoch = %s" % epoch.strftime("%m/%d/%y %H:%M:%S %z")
        print "td = %d days %d seconds %d microseconds" % (td.days,td.seconds,td.microseconds)
        print "timediff = %f" % timediff
        print "Check: %s" % datetime.datetime.utcfromtimestamp(timediff).strftime("%m/%d/%y %H:%M:%S %z")
    return timediff

def cmd_print_all_locations(args):
    """Option to print out all locations
    """
    global debug
    debug = int(args['debug'])
    cmdtype = 'Stored'
    asite = alertSite('Production',cmdtype)
    asite.load_monitors()
    asite.print_all_locations()
    return { 'asite': asite}

def cmd_print_all_monitors(args):
    """Option to print out all monitors
    """
    global debug
    debug = int(args['debug'])
    cmdtype = 'Stored'
    asite = alertSite('Production',cmdtype)
    asite.load_monitors()
    asite.print_all_monitors()
    return { 'asite': asite}


def cmd_set_alertSite(args):
    """Set and store credentials
    """
    global debug
    debug = int(args['debug'])
    cmdtype = 'Set'
    asite = alertSite('Production',cmdtype)
    del asite
    print "AlertSite credentials securely stored"
    return { 'asite': asite}

def cmd_shell(args):
    global debug
    debug = int(args['debug'])
    return None

def main():
    parser = argparse.ArgumentParser(description=\
             'Manage AlertSite')
    
    metavar='{pal,pam,sals'
    metavar = metavar + ',shell' # uncomment to enable clean python -i shell access
    metavar = metavar + '}'
    subparsers = parser.add_subparsers(metavar=metavar)
    
    pal_parser = subparsers.add_parser('pal',\
                    help = 'Print All AlertSite Testing Locations')
    pal_parser.set_defaults(func=cmd_print_all_locations)
    pal_parser.add_argument('-debug', action='store', type = int, default=0,\
                    dest='debug', help='Debug level 0-9')
    pal_parser.add_argument('-i', action='store_true', default = False,\
                    dest='askpass', help='Prompt for credentials to use')
    pal_parser.add_argument('-s', action='store_true', default = False,\
                    dest='stored', help='Use stored credentials')
    
    pam_parser = subparsers.add_parser('pam',\
                    help = 'Print All AlertSite Monitors')
    pam_parser.set_defaults(func=cmd_print_all_monitors)
    pam_parser.add_argument('-debug', action='store', type = int, default=0,\
                    dest='debug', help='Debug level 0-9')
    pam_parser.add_argument('-i', action='store_true', default = False,\
                    dest='askpass', help='Prompt for credentials to use')
    pam_parser.add_argument('-s', action='store_true', default = False,\
                    dest='stored', help='Use stored credentials')
    
    sals_parser = subparsers.add_parser('sals',\
                    help = 'Set/Store AlertSite Credentials')
    sals_parser.set_defaults(func=cmd_set_alertSite)
    sals_parser.add_argument('-debug', action='store', type = int, default=0,\
                    dest='debug', help='Debug level 0-9')
    
    #  Comment out this section for those we do not want to have access to the shell
    shell_parser = subparsers.add_parser('shell', help = 'Shell')
    shell_parser.set_defaults(func=cmd_shell)
    shell_parser.add_argument('-debug', action='store', type = int, default=0,
                    dest='debug', help='Debug level 0-9')
    
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
