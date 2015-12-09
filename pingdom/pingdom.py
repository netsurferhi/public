#!/usr/bin/env python

from email.mime.text import MIMEText
from urllib import urlopen
from xml.etree.ElementTree import parse
from xml.sax import saxutils, handler, make_parser
import ast
import base64
import copy
import csv
import datetime
import email.utils
import getpass
import os
import pickle
import pprint
import re
import readline
import smtplib
import stat
import sys
import time

import argparse
import numpy
import pingdomlib


__doc__ = """
pingdom.py

Script to use to enable and disable pingdom checks,
get information about the account and settings, and
perform other pingdom actions such as traceroute as
they are made available.  Also includes an ARIN
whois mechanism for fast lookups of IP address
owners from the command line.  Will probably integrate
it into the traceroute function later on.  Am also
considering adding plotting of traceroute results over
time using matplotlib for path analysis.
"""

class ASCII_Chart(object):
    '''Class to init, load, store
    an ASCII chart for whatever use you have.
    Will include code to count instances of
    a particular character.
    '''
    
    def __init__(self):
        '''Initialize self.ascii_chart
        '''
        self.ascii_chart = {}
        self.count = numpy.zeros(256,dtype=int)
        self.position = {}
        for i in range(256):
            self.position[i] = []
        self.load_ascii('ascii.pkl')
        
    
    def __len__(self):
        '''allow a check of length for
        logic testing to see if a variable
        points to an ascii class object.
        '''
        return 1
    
    def zero_count(self):
        self.count = numpy.zeros(256,dtype=int)
        self.position = {}
        for i in range(256):
            self.position[i] = []
        
    
    def create_ascii_from_csv(self,filename):
        '''Load in a csv file of ascii
        characters into a dictionary
        '''
        if 'debug' in globals() and debug > 0:
            print "Enter create ascii"
        self.ascii_chart = {}
        header = []
        first = 1
        f = open('ascii.csv','rb')
        try:
            reader = csv.reader(f)
            for row in reader:
                if 'debug' in globals() and debug > 0:
                    print row
                if first > 0:
                    header = deepcopy(row)
                    first = 0
                else:
                    rnum = int(row[0])
                    self.ascii_chart[rnum] = {}
                    self.ascii_chart[rnum]['int'] = rnum
                    self.ascii_chart[rnum]['symbol'] = str(row[4])
                    self.ascii_chart[rnum]['html_num'] = str(row[5])
                    self.ascii_chart[rnum]['html_name'] = str(row[6]).strip()
                    self.ascii_chart[rnum]['desc'] = str(row[7])
        finally:
            f.close()
    
    def load_ascii(self,filename = 'ascii.pkl'):
        """Loads a pickled ascii chart
        """
        if 'debug' in globals() and debug > 0:
            print "Enter load ascii"
        if os.path.exists(filename):
            infile = open(filename,'rb')
            self.ascii_chart = pickle.load(infile)
            infile.close()
        else:
            print "Error: file %s not found" % filename
    
    def store_ascii(self,filename):
        """Stores a pickled ascii chart
        """
        if 'debug' in globals() and debug > 0:
            print "Enter store ascii"
            outfile = open(filename,'wb')
            pickle.dump(self.ascii_chart,outfile)
            outfile.close()
            os.chmod(filename, stat.S_IRWXU)
    
    def create_ascii_python(self):
        '''Create python definition code for class
        '''
        print "self.ascii_chart = {}"
        for key in self.ascii_chart.keys():
            print "self.ascii_chart[%d] = {}" % int(key)
            for key2 in self.ascii_chart[int(key)].keys():
                if key2.find('int') == 0:
                    value = self.ascii_chart[key][key2]
                    print "self.ascii_chart[%d][%s] = %d" % (int(key),repr(key2),value)
                else:
                    value = self.ascii_chart[key][key2]
                    print "self.ascii_chart[%d][%s] = %s" % (int(key),repr(key2),repr(value))
    
    def init_ascii_chart(self):
        '''Manually initialize the ascii_chart
        '''
    
    def count_chars(self,input_string):
        '''Method to increment the counters in
        self.count for each character found
        '''
        for index in range(len(input_string)):
            self.count[ord(input_string[index])] += 1
            self.position[ord(input_string[index])].append(int(index))
    
    def return_found(self):
        '''Method to return dictionary
        of characters found and their count
        '''
        found_dict = {}
        for charnum in self.count.nonzero()[0]:
            found_dict[self.ascii_chart[charnum]['symbol']] = {}
            found_dict[self.ascii_chart[charnum]['symbol']]['count'] = self.count[charnum]
            found_dict[self.ascii_chart[charnum]['symbol']]['location'] = copy.deepcopy(self.position[charnum])
        return found_dict
    
    def is_ip_address(self,input_string):
        '''Method to basic sanity check if a string is
        an IP address by looking for four periods and only
        the numbers zero through 9
        '''
        ip_str = '^([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]'+\
                 '?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d'+\
                 '?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]'+\
                 '\\d|25[0-5])$'
        pattern = re.compile(ip_str)
        x = pattern.match(input_string)
        if repr(x) == 'None':
            return False
        else:
            return True
    
    def is_ip_addr_w_paren(self,input_string):
        '''Method to basic sanity check if a string is
        an IP address by looking for four periods and only
        the numbers zero through 9
        '''
        ip_str = '^\\(?([01]?\\d\\d?|2[0-4]\\d|25[0-5])'+\
                 '\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'+\
                 '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'+\
                 '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\)?$'
        pattern = re.compile(ip_str)
        x = pattern.match(input_string)
        if repr(x) == 'None':
            return False
        else:
            return True
        
    def ip_to_acl(self,input_string):
        '''Method to take an IP address string/mask
        and turn it into a Cisco ACL inverted string
        '''
        if self.is_ip_address(input_string):
            q1,q2,q3,q4 = input_string.split('.')
            return '.'.join([255-int(q1),255-int(q2),255-int(q3),255-int(q4)])
        else:
            print "Invalid IP Address/Mask [%s] specified" % input_string
        return ''


class Pingdom(object):
    """Class to manage a pingdom account
    """
    def __init__(self):
        self.cred = {}
        self.probes = {}
        self.server = None
        self.results = ''
        self.probe = ''
        self.target = ''
        self.hops_dict = {}
        self.hops = 0
        self.plot_dict = {}
        self.tr_date = ''
        self.checks = {}
        self.check_count = 0
        self.paused = 0
        self.enabled = 0
        self.check_xref = {}
        self.actions = {}
        self.alert_policy = {}
        self.alert_xref = {}
        self.load_credentials()
        return
    
    def set_credentials(self):
        """For self-contained script without password on file system
        """
        if 'debug' in globals() and debug > 0:
            print "In pingdom.set_credentials"
        self.cred['Username'] = "username"
        self.cred['Password'] = base64.b64encode("password")
        self.cred['apikey'] = "apikey"
        return
    
    def load_credentials(self):
        """Loads up the credentials and decodes them from
        the locally stored file .pingdom  Note that
        passwords are not stored in plain text on disk
        nor in memory.
        """
        if 'debug' in globals() and debug > 0:
            print "Enter load credentials"
        if os.path.exists('.pingdom'):
            infile = open('.pingdom','rb')
            self.cred = pickle.load(infile)
            #self.p4_cred['Password'] = base64.b64decode(self.p4_cred['Password'])
            infile.close()
        else:
            self.set_credentials()
            self.store_credentials()
        if 'debug' in globals() and debug > 0:
            print "Loaded obfuscated password ,%s>" % self.cred['Password']
        #self.cred['Password'] = base64.b64decode(self.cred['Password'])
        if 'debug' in globals() and debug > 0:
            print "Loaded credentials "
            print "Username: %s" % self.cred['Username']
            #print "Password: %s" % self.cred['Password']
        return
    
    def store_credentials(self):
        """Encodes and stores the current working credentials.
        Passwords are not stored in plain text on disk nor
        in memory.
        """
        if 'debug' in globals() and debug > 0:
            print "Enter store credentials"
        if 'Username' not in self.cred.keys():
            if 'debug' in globals() and debug > 0:
                print "No Username Key - storing default"
            self.cred['Username'] = "username"
        if 'Password' not in self.cred.keys():
            if 'debug' in globals() and debug > 0:
                print "No Password Key - storing default"
            self.cred['Password'] = base64.b64encode("password")
        if 'apikey' not in self.cred.keys():
            if 'debug' in globals() and debug > 0:
                print "No API Key - storing default"
            self.cred['apikey'] = "apikey"
        outfile = open('.pingdom','wb')
        #self.cred['Password'] = base64.b64encode(self.cred['Password'])
        pickle.dump(self.cred,outfile)
        outfile.close()
        os.chmod('.pingdom', stat.S_IRWXU)
        if 'debug' in globals() and debug > 0:
            print "Storing:"
            print "Username: %s" % self.cred['Username']
            #print "Password: %s" % self.cred['Password']
            print "apikey: %s" % self.cred['apikey']
        return
    
    def input_credentials(self):
        """Provides you with a way to input the necessary
        credentials and then store them securely with store_credentials.
        """
        if 'debug' in globals() and debug > 0:
            print "In input_credentials"
        try:
            self.cred['Username'] = raw_input('Username: ')
            if 'debug' in globals() and debug > 0:
                print "Input: %s" % self.cred['Username']
        except EOFError:
            print "Error: PEBCAK - EOF received - using default Username of 'Username'"
            self.cred['Username'] = "username"
        try:
            self.cred['Password'] = base64.b64encode(getpass.getpass('Password:'))
        except EOFError:
            print "Error: PEBCAK - EOF received - using default Password of 'password'"
            self.cred['Password'] = base64.b64encode("password")
        try:
            self.cred['apikey'] = raw_input('API Key: ')
        except EOFError:
            print "Error: PEBCAK - EOF received - using default API Key of 'apikey'"
            self.cred['apikey'] = "apikey"
        if 'debug' in globals() and debug > 0:
            print "Results:"
            print "Username: %s" % self.cred['Username']
            #print "Password: %s" % self.cred['Password']
            print "API Key: %s" % self.cred['apikey']
        return
    
    def get_probes(self):
        """Method to build dictionary of the various probes
        used by Pingdom
        """
        probelist = self.server.probes()
        self.probe_by_country = {}
        for num in range(len(probelist)):
            if bool(probelist[num]['active']):
                ciso = str(probelist[num]['countryiso'])
                cid = int(probelist[num]['id'])
                self.probes[cid] = {}
                self.probes[cid]['id'] = cid
                self.probes[cid]['active'] =  bool(probelist[num]['active'])
                self.probes[cid]['city'] =  str(probelist[num]['city'])
                self.probes[cid]['country'] =  str(probelist[num]['country'])
                self.probes[cid]['countryiso'] = ciso
                if ciso not in self.probe_by_country.keys():
                    self.probe_by_country[ciso] = {}
                if cid not in self.probe_by_country[ciso].keys():
                    self.probe_by_country[ciso][cid] = cid
                self.probes[cid]['hostname'] =  str(probelist[num]['hostname'])
                self.probes[cid]['ip'] =  str(probelist[num]['ip'])
                self.probes[cid]['name'] =  str(probelist[num]['name'])
        return
    
    def print_probes(self):
        '''Method to output the current active probe list
        '''
        if len(self.probes) < 1:
            self.get_probes()
        print
        for probenum in sorted(self.probes.keys()):
            if self.probes[probenum]['active']:
                print " [%02d] (%s) %s %s %s" % (probenum,self.probes[probenum]['countryiso'],\
                                                        self.probes[probenum]['name'],\
                                                         self.probes[probenum]['hostname'],\
                                                         self.probes[probenum]['ip'])
        print
        print "Probes by Country:"
        print
        for ciso in sorted(self.probe_by_country.keys()):
            print " [%02s]" % ciso,
            for probe in sorted(self.probe_by_country[ciso].keys()):
                print "(%02d) %s" % (probe,self.probes[probe]['name']),
            print
        print
        return
    
    def get_us_probe(self):
        """
        Method to yield probe(s) located in the US
        """
        usprobes = list(self.probe_by_country['US'])
        if len(usprobes) > 0:
            return usprobes[0]
        else:
            return None
    
    def get_checks(self):
        """
        Method to get a list of all checks
        """
        self.checks = {}
        self.enabled = 0
        self.paused = 0
        self.check_count = 0
        checklist = self.server.getChecks()
        for check in range(len(checklist)):
            self.check_count += 1
            if 'debug' in globals() and debug > 0:
                print "Processing check [%03d][%03d P %03d E] %d (%s)" % (self.check_count,\
                                                            self.paused, self.enabled,\
                                                            checklist[check].id,\
                                                            checklist[check].name)
            self.checks[checklist[check].id] = {}
            self.check_xref[checklist[check].name] = checklist[check].id
            policynum = 0
            policyname = ''
            if 'debug' in globals() and debug > 0:
                print "Processing keys"
            for key in checklist[check].__dict__.keys():
                if 'debug' in globals() and debug > 1:
                    print "processing key %s" % str(key)
                if 'debug' in globals() and debug > 1:
                    print "Key is ",
                    print type(checklist[check].__dict__[key])
                    print "Value is ",
                    print repr(checklist[check].__dict__[key])
                if key.find('delete') == 0:
                    if 'debug' in globals() and debug > 0:
                        print "skipping delete instance"
                    continue ## We don't want to pass on the delete method for now
                self.checks[checklist[check].id][str(key)] = checklist[check].__dict__[key]
                if key.find('alert_policy_name') == 0:
                    policyname = checklist[check].__dict__[key]
                    if 'debug' in globals() and debug > 0:
                        print "processing alert_policy_name"
                    if policynum > 0:
                        if policynum not in self.alert_policy.keys():
                            self.alert_policy[policynum] = {}
                            self.alert_policy[policynum]['members'] = {}
                        self.alert_policy[policynum]['name'] = policyname
                        self.alert_policy[policynum]['members'][checklist[check].id] = checklist[check].id
                        self.alert_xref[policyname] = policynum
                        if 'debug' in globals() and debug > 0:
                            print "setting policy %d to %s" % (policynum,policyname)
                elif key.find('alert_policy') == 0 and len(key) == 12:
                    policynum = int(checklist[check].__dict__[key])
                    if len(policyname) < 1:
                        if 'debug' in globals() and debug > 0:
                            print "key is alert_policy - saving number %d as No Name" % policynum
                        if policynum not in self.alert_policy.keys():
                            self.alert_policy[policynum] = {}
                            self.alert_policy[policynum]['members'] = {}
                        self.alert_policy[policynum]['name'] = 'No Name'
                        self.alert_policy[policynum]['members'][checklist[check].id] = checklist[check].id
                    else:
                        if 'debug' in globals() and debug > 0:
                            print "saving %d as %s" % ()
                        if policynum not in self.alert_policy.keys():
                            self.alert_policy[policynum] = {}
                            self.alert_policy[policynum]['members'] = {}
                        self.alert_policy[policynum]['name'] = policyname
                        self.alert_policy[policynum]['members'][checklist[check].id] = checklist[check].id
            if 'paused' in checklist[check].__dict__.keys():
                if checklist[check].paused:
                    self.paused += 1
                    if 'debug' in globals() and debug > 0:
                        print "check is paused = self.paused = %01d" % self.paused
                else:
                    self.enabled += 1
                    if 'debug' in globals() and debug > 0:
                        print 'paused found but is false - self.enabled = %01d' % self.enabled
            else:
                self.enabled += 1
                if 'debug' in globals() and debug > 0:
                    print 'paused not found - self.enabled = %01d' % self.enabled
            ## This was the individual setting of values - decided to do it via __dict__
            ## but saving this as a reference to all of the current values
            #checklist[check].name # ucode str
            #checklist[check].acktimeout # int
            #checklist[check].alert_policy # int
            #checklist[check].alert_policy_name # ucode str
            #checklist[check].autoresolve # int
            #checklist[check].averages # instance
            #checklist[check].created # int unixtime?
            #checklist[check].delete # instance - DANGER!!!
            #checklist[check].getAnalyses # instance
            #checklist[check].getDetails # instance returns dict of details
            #checklist[check].hostname # ucode str
            #checklist[check].hoursofday # instance
            #checklist[check].id # int
            #checklist[check].ipv6 # bool
            #checklist[check].lasterrortime # int unixdate?
            #checklist[check].lastresponsetime # int unixdate?
            #checklist[check].lasttesttime # int unixdate?
            #checklist[check].modify # instance
            #checklist[check].notifyagainevery # int
            #checklist[check].notifywhenbackup # bool
            #checklist[check].outages # instance
            #checklist[check].paused # bool
            #checklist[check].performance # 
            #checklist[check].pingdom # instance
            #checklist[check].probe_filters # list
            #checklist[check].probes # instance
            #checklist[check].publishPublicReport # instance MODIFYS!
            #checklist[check].removePublicReport # instance MODIFYS!
            #checklist[check].resolution # int
            #checklist[check].results # instance
            #checklist[check].sendnotificationwhendown # int
            #checklist[check].sendtoemail # bool
            #checklist[check].sendtoiphone # bool
            #checklist[check].sendtosms # bool
            #checklist[check].sendtotwitter # bool
            #checklist[check].status # ucode str
            #checklist[check].type # ucode str
            #checklist[check].use_legacy_notifications # bool
        if 'debug' in globals() and debug > 0:
            print "Enabled checks: %03d   Paused checks: %03d   Total checks: %03d" % \
                                          (self.enabled, self.paused, self.check_count)
    
    def traceroute(self,probe,target,printout = True):
        '''Method to perform the traceroute and return the results
        By default prints out results unless printout = False is sent.
        '''
        self.server = pingdomlib.Pingdom(self.cred['Username'],\
                                              base64.b64decode(self.cred['Password']),\
                                              self.cred['apikey'])
        self.get_probes()
        self.probe = probe
        self.target = target
        scandate = datetime.datetime.now()
        if self.probe in self.probes.keys():
            if printout:
                print "\nTracing path to %s from Pingdom Probe Server #%d (%s)\n" % \
                      (self.target,self.probe,self.probes[self.probe]['name'])
            self.tr_date = str(scandate.month)+'/'+\
                str(scandate.day)+'/'+\
                str(scandate.year)+' '+\
                str(scandate.hour)+":"+\
                str(scandate.minute)+':'+\
                str(scandate.second)
            self.results = self.server.traceroute(self.target,self.probe)
            if printout:
                print self.results['result']
                print
            return
        else:
            probenum = self.get_us_probe()
            if probenum is not None:
                if printout:
                    print "Probe #%d not found - using #%d (%s)" % \
                          (self.probe,probenum,self.probes[probenum]['name'])
                    print "\nTracing path to %s from Pingdom Probe Server #%d (%s)\n" % \
                          (self.target,probenum,self.probes[probenum]['name'])
                self.tr_date = str(scandate.month)+'/'+\
                    str(scandate.day)+'/'+\
                    str(scandate.year)+' '+\
                    str(scandate.hour)+":"+\
                    str(scandate.minute)+':'+\
                    str(scandate.second)
                self.probe = probenum
                self.results = self.server.traceroute(self.target,self.probe)
                if printout:
                    print self.results['result']
                    print
                return
            else:
                if printout:
                    print "probe %d not found and no active US probe found"
        return
    
    def count_chars(self,inline,ascii = ''):
        '''Method to determine and return a count of asterisks in a line
        '''
        if len(ascii) < 1:
            ascii = ASCII_Chart()
        ascii.count_chars(inline)
        char_dict = ascii.return_found()
        return char_dict
    
    def reduce_spaces(self,inline):
        '''replace any multiple space
        instances with one space.
        '''
        if type(inline) is not str:
            inline = str(inline)
        return re.sub('(?:\ ){2,99}',' ',inline).strip().rstrip()
    
    def parse_hops(self):
        '''Method to parse the results lines and return
        three strings with either the hop results
        or a zero length string for hop failure.
        '''
        if 'debug' in globals() and debug > 1:
            print "in parse_hops"
        if 'result' in self.results.keys() and len(self.results['result']) > 0:
            if 'debug' in globals() and debug > 1:
                print "in parse_hops"
                print "inline = <%s>" % inline
            hopnum,inline = self.reduce_spaces(inline).split(' ',1)
            hopnum = int(hopnum)
            if 'debug' in globals() and debug > 1:
                print "Now:"
                print "inline = <%s>" % inline
                print "hopnum = %d" % hopnum
            char_dict = self.count_chars(inline)
            if len(self.hops_dict) < 1:
                for i in range(1,31):
                    self.hops_dict[i] = {}
                    for j in range(1,4):
                        self.hops_dict[i][j] = {}
                        self.hops_dict[i][j]['hostname'] = ''
                        self.hops_dict[i][j]['hostip'] = ''
                        self.hops_dict[i][j]['time'] = 0
            if '*' in char_dict.keys():
                if char_dict['*']['count'] > 2:
                    try1 = ''
                    try2 = ''
                    try3 = ''
                elif char_dict['*']['count'] > 1:
                    inlinelen = len(inline)
                    if 0 in char_dict['*']['location'] and \
                       (inlinelen-1) in char_dict['*']['location']: # value in middle
                        try1 = ''
                        try3 = ''
                        try2 = inline.split('*')[1].strip().rstrip()
                    elif 0 in char_dict['*']['location']: # value at end
                        try1 = ''
                        try2 = ''
                        try3 = inline.split('*')[2].strip().rstrip()
                    else: # value at beginning
                        try2 = ''
                        try3 = ''
                        try1 = inline.split('*')[0].strip().rstrip()
                else:
                    inlinelen = len(inline)
                    if 0 in char_dict['*']['location']: # star at beginning
                        inline = inline.split('*')[1].strip().rstrip()
                        ms = inline.find('ms ')
                        try1 = ''
                        try2 = inline[0:ms+2]
                        try3 = inline[ms+3:]
                    elif (inlinelen-1) in char_dict['*']['location']: # star at end
                        inline = inline.split('*')[0].strip().rstrip()
                        ms = inline.find('ms ')
                        try3 = ''
                        try1 = inline[0:ms+2]
                        try2 = inline[ms+3:]
                    else: # star in middle
                        try2 = ''
                        try1 = inline.split('*')[0].strip().rstrip()
                        try3 = inline.split('*')[1].strip().rstrip()
            else: # no stars - now find out how many different ips in hop and process
                if char_dict['(']['count'] > 2: # three different hop ip's
                    try1 = inline.split(' ms')[0].strip().rstrip()+' ms'
                    try2 = inline.split(' ms')[1].strip().rstrip()+' ms'
                    try3 = inline.split(' ms')[2].strip().rstrip()+' ms'
                elif char_dict['(']['count'] > 1: # two hop ips one with two values
                    if inline.split(' ms')[1].find('(') > 0: # second ip has two values
                        try1 = inline.split(' ms')[0].strip().rstrip()+' ms'
                        try2 = inline.split(' ms')[1].strip().rstrip()+' ms'
                        try2hostname = inline.split(' ms')[1].strip().rstrip().split(' ')[0]
                        try2hostip = inline.split(' ms')[1].strip().rstrip().split(' ')[1]
                        try3time = inline.split(' ms')[2].strip().rstrip()
                        try3 = try2hostname + ' ' + try2hostip + ' ' + try3time + ' ms'
                    else: # first IP has two values
                        try1 = inline.split(' ms')[0].strip().rstrip()+' ms'
                        try1hostname = inline.split(' ms')[0].strip().rstrip().split(' ')[0]
                        try1hostip = inline.split(' ms')[0].strip().rstrip().split(' ')[1]
                        try2time = inline.split(' ms')[1].strip().rstrip()
                        try2 = try1hostname + ' ' + try1hostip + ' ' + try2time + ' ms'
                        try3 = inline.split(' ms')[2].strip().rstrip()+' ms'
                else: # one hop three values
                    try1 = inline.split(' ms')[0].strip().rstrip()+' ms'
                    hostname = inline.split(' ms')[0].split(' ')[0].strip().rstrip()
                    hostip = inline.split(' ms')[0].split(' ')[1].strip().rstrip()
                    try2time = inline.split(' ms')[1].strip().rstrip()
                    try3time = inline.split(' ms')[2].strip().rstrip()
                    try2 = hostname + ' ' + hostip + ' ' + try2time + ' ms'
                    try3 = hostname + ' ' + hostip + ' ' + try3time + ' ms'
            
            hops = {}
            hops[1] = {}
            hops[2] = {}
            hops[3] = {}
            
            if len(try1) < 1:
                hops[1]['hostname'] = ''
                hops[1]['hostip'] = ''
                hops[1]['time'] = 0
            else:
                hops[1]['hostname'] = try1.split(' ')[0]
                hops[1]['hostip']   = try1.split(' ')[1].replace('(','').replace(')','')
                hops[1]['time'] = int(round(float(try1.split(' ')[2])))
            
            if len(try2) < 1:
                hops[2]['hostname'] = ''
                hops[2]['hostip'] = ''
                hops[2]['time'] = 0
            else:
                hops[2]['hostname'] = try2.split(' ')[0]
                hops[2]['hostip']   = try2.split(' ')[1].replace('(','').replace(')','')
                hops[2]['time'] = int(round(float(try2.split(' ')[2])))
            
            if len(try3) < 1:
                hops[3]['hostname'] = ''
                hops[3]['hostip'] = ''
                hops[3]['time'] = 0
            else:
                hops[3]['hostname'] = try3.split(' ')[0]
                hops[3]['hostip']   = try3.split(' ')[1].replace('(','').replace(')','')
                hops[3]['time'] = int(round(float(try3.split(' ')[2])))
            if 'debug' in globals() and debug > 2:
                print "hops dict:"
                pprint.pprint(hops)
            for i in range(1,4):
                if 'debug' in globals() and debug > 2:
                    print "i = %d" % i
                    print "hopnum = %d" % hopnum
                    print "self.hops_dict[hopnum]:"
                    pprint.pprint(self.hops_dict[hopnum])
                    print "hops[i]:"
                    pprint.pprint(hops[i])
                hostname = hops[i]['hostname'][:]
                if 'debug' in globals() and debug > 2:
                    print "hostname copy = <%s>" % hostname
                self.hops_dict[hopnum][i]['hostname'] = hostname
                if 'debug' in globals() and debug > 2:
                    print "hops_dict[%d][%d][hostname] = <%s>" % (hopnum,i,self.hops_dict[hopnum][i]['hostname'])
                hostip = hops[i]['hostip'][:]
                self.hops_dict[hopnum][i]['hostip'] = hostip
                if 'debug' in globals() and debug > 2:
                    print "hops_dict[%d][%d][hostip] = <%s>" % (hopnum,i,self.hops_dict[hopnum][i]['hostip'])
                hoptime = int(hops[i]['time'])
                self.hops_dict[hopnum][i]['time'] = hoptime
                if 'debug' in globals() and debug > 2:
                    print "hops_dict[%d][%d][time] = <%d>" % (hopnum,i,self.hops_dict[hopnum][i]['time'])
                    print "hops_dict[hopnum] now:"
                    pprint.pprint(self.hops_dict[hopnum])
        self.hops = len(self.hops_dict)
        return
    
    def trim_hops_dict(self):
        '''Method to find the last successful hop in a traceroute
        and set the number of hops to that value and truncate dict
        to the last good hop
        '''
        maxhops = len(self.hops_dict)
        good_hop = 0
        for i in range(maxhops,0,-1):
            for j in range(3,0,-1):
                if good_hop == 0 and len(self.hops_dict[i][j]['hostname']) > 0:
                    good_hop = int(i)
            if good_hop == 0:
                del self.hops_dict[i]
        self.hops = len(self.hops_dict)
        return
    
    def make_plot_dict(self,option='max'):
        '''Method to take hops_dict and turn into single hop
        records for zoho selecting the max, min, or average
        of the three hops
        '''
        
        self.plot_dict = {}
        req_date = self.tr_date
        plotname = self.target + '-P' + str(self.probe)
        self.plot_dict[req_date] = {}
        self.plot_dict[req_date]['Hops'] = int(self.hops)
        self.plot_dict[req_date]['Src'] = self.probes[self.probe]['ip']
        self.plot_dict[req_date]['Dst'] = self.target
        self.plot_dict[req_date]['Data'] = []
        self.plot_dict[req_date]['Hopname'] = []
        self.plot_dict[req_date]['HopIP'] = []
        for hopnum in range(1,self.hops+1):
            hopmin = -1
            hopmax = 0
            hopavg = 0
            hopmed = 0
            hopcount = 0
            hopttl = 0
            hoptimelist = list(self.hops_dict[hopnum][1]['time'],\
                               self.hops_dict[hopnum][2]['time'],\
                               self.hops_dict[hopnum][3]['time'])
            hopnamelist = list(self.hops_dict[hopnum][1]['hostname'],\
                               self.hops_dict[hopnum][2]['hostname'],\
                               self.hops_dict[hopnum][3]['hostname'])
            hopiplist = list(self.hops_dict[hopnum][1]['hostip'],\
                               self.hops_dict[hopnum][2]['hostip'],\
                               self.hops_dict[hopnum][3]['hostip'])
            hopmin = int(numpy.min(numpy.array(hoptimelist)))
            hopmax = int(numpy.max(numpy.array(hoptimelist)))
            hopavg = int(numpy.average(numpy.array(hoptimelist)))
            hopmed = int(numpy.median(numpy.array(hoptimelist)))
            if options.find('max') >= 0:
                self.plot_dict[req_date]['Data'].append(int(hopmax))
            self.plot_dict[req_date]['Hopname'].append(str(self.hops_dict[hopnum][i]['hostname']))
            self.plot_dict[req_date]['HopIP'].append(str(self.hops_dict[hopnum][i]['hostip']))
        return


def getnetowner(subnet):
    """method to call whois.arin.net for a network reference
    in non-cidr notation.  Returns a dictionary similar to this:
    
    {   'cidrLength': '24',
        'description': 'Reallocated',
        'endAddress': '8.8.8.255',
        'handle': 'NET-8-8-8-0-1',
        'limitExceeded': {   'limit': '256', 'text': 'false'},
        'name': 'LVLT-GOGL-8-8-8',
        'net': {   'inaccuracyReportUrl': 'http://www.arin.net/public/whoisinaccuracy/index.xhtml',
                   'termsOfUse': 'https://www.arin.net/whois_tou.html'},
        'netBlock': '',
        'netBlocks': '',
        'orgRef': {   'handle': 'GOGL',
                      'name': 'Google Inc.',
                      'text': 'http://whois.arin.net/rest/org/GOGL'},
        'parentNetRef': {   'handle': 'NET-8-0-0-0-1',
                            'name': 'LVLT-ORG-8-8',
                            'text': 'http://whois.arin.net/rest/net/NET-8-0-0-0-1'},
        'ref': 'http://whois.arin.net/rest/net/NET-8-8-8-0-1',
        'registrationDate': '2014-03-14T16:52:05-04:00',
        'resources': {   'inaccuracyReportUrl': 'http://www.arin.net/public/whoisinaccuracy/index.xhtml',
                         'termsOfUse': 'https://www.arin.net/whois_tou.html'},
        'startAddress': '8.8.8.0',
        'type': 'A',
        'updateDate': '2014-03-14T16:52:05-04:00',
        'version': '4'
    }
    """
    u=urlopen('http://whois.arin.net/rest/ip/'+subnet)
    root=parse(u)
    owner_recs = {}
    for elem in root.getiterator():
        items = elem.items()
        tag = str(elem.tag)
        if len(elem.attrib) > 0 and type(elem.attrib) is dict:
            att = copy.deepcopy(elem.attrib)
        elif len(elem.attrib) > 0:
            att = str(elem.attrib)
        else:
            att = ''
        txt = str(elem.text)
        if txt.lstrip().find('None') == 0:
            txt = ''
        tal = str(elem.tail)
        name = re.sub(r'.*}','',tag)
        if len(txt) > 0:
            if type(att) is dict:
                att['text'] = str(txt)
            else:
                att = att + txt
        values = {}
        values[str(name)] = att
        if 'debug' in globals() and debug > 0:
            print "Items:",
            pprint.pprint(items)
            print "Tag: %s" % tag
            print "Att: %s" % att
            print "Txt: %s" % txt
            print "Tal: %s" % tal
            print "Values:",
            pprint.pprint(values)
        owner_recs[str(name)] = att
    return owner_recs


def parse_trace_result(result):
    '''Method to take the single string 
    traceroute output and turn it into a list we can work with.
    '''
    if len(result) > 0 and result.find('\n') > 0:
        hops = []
        rawlist = result.split('\n')
        for hopnum in range(1,len(rawlist)):
            pass
    pass

def cmd_modify_single_check(args):
    '''Called from main() to enable or disable one or all check(s)
    '''
    global debug
    debug = int(args['debug'])
    name = str(args['name'])
    number = int(args['number'])
    disable = bool(args['disable'].find('True') == 0)
    enable = bool(args['enable'].find('True') == 0)
    askpass = bool(args['askpass'].find('True') == 0)
    allchecks = bool(args['allchecks'].find('True') == 0)
    if 'debug' in globals() and debug > 0:
        print "Enter cmd_modify_single_check"
        print "Name: <%s>" % name
        print "Number: <%01d>" % number
        print "Disable: %s" % repr(disable)
        print "Enable:  %s" % repr(enable)
        print "Askpass: %s" % repr(askpass)
        print "Allchecks: %s" % repr(allchecks)
    if (len(name) < 1 and number < 1) and not allchecks:
        print "Error: no check name or check ID number provided"
        return {'args': args}
    elif len(name) > 0 and number > 0:
        print "Error: Both check name and check ID number provided"
        return {'args': args}
    elif enable and disable:
        print "Error: both -ena (enable) and -dis (disable) specified"
        return {'args': args}
    elif (not enable) and (not disable):
        print "Error: neither -ena (enable) nor -dis (disable) specified"
        return {'args': args}
    mypingdom = Pingdom()
    if askpass:
        mypingdom.input_credentials()
    else:
        mypingdom.load_credentials()
    mypingdom.server = pingdomlib.Pingdom(mypingdom.cred['Username'],\
                                          base64.b64decode(mypingdom.cred['Password']),\
                                          mypingdom.cred['apikey'])
    mypingdom.get_checks()
    resultmsg = ''
    if number > 0:
        if 'debug' in globals() and debug > 0:
            print "number = %d - verifying it exists" % number
        if number in mypingdom.checks.keys():
            name = mypingdom.checks[number]['name']
            if 'debug' in globals() and debug > 0:
                print "number %02d [%s] exists" % (number, name)
            if enable:
                if 'debug' in globals() and debug > 0:
                    print "Enabling check ID %01d (%s)" % (number, name)
                resultmsg = mypingdom.checks[number]['pingdom'].modifyChecks(paused = False,\
                                                                              checkids = str(number))
                print "%s" % resultmsg
            elif disable:
                if 'debug' in globals() and debug > 0:
                    print "Disabling check ID %01d (%s)" % (number, name)
                resultmsg = mypingdom.checks[number]['pingdom'].modifyChecks(paused = True, \
                                                                             checkids = str(number))
                print "%s" % resultmsg
        else:
            print "Error: Check ID %01d not found" % number
            return {'args': args,'pingdom': mypingdom}
    elif len(name) > 0:
        if 'debug' in globals() and debug > 0:
            print "name = %s - verifying it exists" % name
        if name in mypingdom.check_xref.keys():
            number = mypingdom.check_xref[name]
            if 'debug' in globals() and debug > 0:
                print "name %s [%01d] exists" % (name, number)
            if enable:
                if 'debug' in globals() and debug > 0:
                    print "Enabling check ID %01d (%s)" % (number, name)
                resultmsg = mypingdom.checks[number]['pingdom'].modifyChecks(paused = False, \
                                                                             checkids = str(number))
                print "%s" % resultmsg
            elif disable:
                if 'debug' in globals() and debug > 0:
                    print "Disabling check ID %01d (%s)" % (number, name)
                resultmsg = mypingdom.checks[number]['pingdom'].modifyChecks(paused = True, \
                                                                             checkids = str(number))
                print "%s" % resultmsg
        else:
            print "Error: Check [%s] not found" % name
            return {'args': args,'pingdom': mypingdom}
    elif allchecks:
        number = mypingdom.checks.keys()[0]
        if 'debug' in globals() and debug > 0:
            print "all checks specified"
        if enable:
            if 'debug' in globals() and debug > 0:
                print "Enabling all checks"
            resultmsg = mypingdom.checks[number]['pingdom'].modifyChecks(paused = False)
            print "%s" % resultmsg
        elif disable:
            if 'debug' in globals() and debug > 0:
                print "Disabling all checks"
            resultmsg = mypingdom.checks[number]['pingdom'].modifyChecks(paused = True)
            print "%s" % resultmsg
    if enable:
        cmdtype = "-Pingdom Enable- "
    else:
        cmdtype = "-Pingdom Disable- "
    command='./sendtoirc Average: '+cmdtype+str(resultmsg)
    os.system(command)
    return {'args': args, 'pingdom': mypingdom, 'resultmsg': resultmsg}

def cmd_modify_group_checks(args):
    '''Called from main() to enable or disable all members of
    a specified alert policy.
    '''
    global debug
    debug = int(args['debug'])
    name = str(args['name'])
    number = int(args['number'])
    disable = bool(args['disable'].find('True') == 0)
    enable = bool(args['enable'].find('True') == 0)
    askpass = bool(args['askpass'].find('True') == 0)
    if 'debug' in globals() and debug > 0:
        print "Enter cmd_modify_single_check"
        print "Name: <%s>" % name
        print "Number: <%01d>" % number
        print "Disable: %s" % repr(disable)
        print "Enable:  %s" % repr(enable)
        print "Askpass: %s" % repr(askpass)
    if len(name) < 1 and number < 1:
        print "Error: no Alert Policy name nor Alert Policy ID number provided"
        return {'args': args}
    elif len(name) > 0 and number > 0:
        print "Error: Both Alert Policy name and Alert Policy ID number provided"
        return {'args': args}
    elif enable and disable:
        print "Error: both -ena (enable) and -dis (disable) specified"
        return {'args': args}
    elif (not enable) and (not disable):
        print "Error: neither -ena (enable) nor -dis (disable) specified"
        return {'args': args}
    mypingdom = Pingdom()
    if askpass:
        mypingdom.input_credentials()
    else:
        mypingdom.load_credentials()
    mypingdom.server = pingdomlib.Pingdom(mypingdom.cred['Username'],\
                                          base64.b64decode(mypingdom.cred['Password']),\
                                          mypingdom.cred['apikey'])
    mypingdom.get_checks()
    resultmsg = ''
    if number > 0:
        if 'debug' in globals() and debug > 0:
            print "number = %d - verifying it exists" % number
        if number in mypingdom.alert_policy.keys():
            name = mypingdom.alert_policy[number]['name']
            if 'debug' in globals() and debug > 0:
                print "number %02d [%s] exists" % (number, name)
            if enable:
                checkids = str(mypingdom.alert_policy[number]['members'].keys()).\
                                                    replace('[','').replace(']','')
                print "Enabling Alert Policy ID %01d (%s)" % (number, name)
                print "Members: %s" % checkids
                anumber = int(checkids.split(",",1)[0])
                # expand member list here for checkids
                resultmsg = mypingdom.checks[anumber]['pingdom'].modifyChecks(paused = False, \
                                                                              checkids = checkids)
                print "%s" % resultmsg
            elif disable:
                checkids = str(mypingdom.alert_policy[number]['members'].keys()).\
                                                    replace('[','').replace(']','')
                print "Members: %s" % checkids
                anumber = int(checkids.split(",",1)[0])
                print "Disabling Alert Policy ID %01d (%s)" % (number, name)
                resultmsg = mypingdom.checks[anumber]['pingdom'].modifyChecks(paused = True, \
                                                                              checkids = checkids)
                print "%s" % resultmsg
        else:
            print "Error: Alert Policy ID %01d not found" % number
            return {'args': args,'pingdom': mypingdom}
    else:
        if 'debug' in globals() and debug > 0:
            print "name = %s - verifying it exists" % name
        if name in mypingdom.alert_xref.keys():
            number = mypingdom.alert_xref[name]
            if 'debug' in globals() and debug > 0:
                print "name %s [%01d] exists" % (name, number)
            if enable:
                checkids = str(mypingdom.alert_policy[number]['members'].keys()).\
                                                    replace('[','').replace(']','')
                print "Enabling Alert Policy ID %01d (%s)" % (number, name)
                print "Members: %s" % checkids
                anumber = int(checkids.split(",",1)[0])
                # expand member list here for checkids
                resultmsg = mypingdom.checks[anumber]['pingdom'].modifyChecks(paused = False, \
                                                                              checkids = checkids)
                print "%s" % resultmsg
            elif disable:
                checkids = str(mypingdom.alert_policy[number]['members'].keys()).\
                                                    replace('[','').replace(']','')
                print "Members: %s" % checkids
                anumber = int(checkids.split(",",1)[0])
                print "Disabling Alert Policy ID %01d (%s)" % (number, name)
                resultmsg = mypingdom.checks[anumber]['pingdom'].modifyChecks(paused = True, \
                                                                              checkids = checkids)
                print "%s" % resultmsg
        else:
            print "Error: Alert Policy [%s] not found" % name
            return {'args': args,'pingdom': mypingdom}
    if enable:
        cmdtype = "-Pingdom Enable- "
    else:
        cmdtype = "-Pingdom Disable- "
    command='./sendtoirc Average: '+cmdtype+str(resultmsg)
    os.system(command)
    return {'args': args, 'pingdom': mypingdom, 'resultmsg': resultmsg}

def median(lst):
    return numpy.median(numpy.array(lst))

def cmd_netwhois(args):
    '''Called from main() to perform an ARIN whois
    lookup on a specified IP address
    '''
    global debug
    debug = int(args['debug'])
    address = str(args['address'])
    if 'debug' in globals() and debug > 0:
        print "Enter cmd_netwhois"
    if len(address) > 0:
        whois = getnetowner(address)
        print
        pprint.pprint(whois,indent=4)
        print
    else:
        print "Error: no address provided"
    return None

def cmd_traceroute(args):
    '''Called from main() to perform a 
    Pingdom traceroute from a specified
    probe location.
    '''
    global debug
    debug = int(args['debug'])
    target = str(args['target'])
    probe = int(args['probe'])
    askpass = bool(args['askpass'].find('True') >= 0)
    if 'debug' in globals() and debug > 0:
        print "Enter cmd_traceroute"
        print "Target: %s" % target
        print "Probe: %d" % probe
    mypingdom = Pingdom()
    if askpass:
        mypingdom.input_credentials()
    mypingdom.traceroute(probe,target)
    return { 'pingdom': mypingdom, 'probe': probe,'target': target}

def cmd_list_probes(args):
    '''Called from main() to list probe locations.
    '''
    global debug
    debug = int(args['debug'])
    askpass = bool(args['askpass'].find('True') >= 0)
    if 'debug' in globals() and debug > 0:
        print "Enter cmd_list_probes"
    mypingdom = Pingdom()
    if askpass:
        mypingdom.input_credentials()
    mypingdom.server = pingdomlib.Pingdom(mypingdom.cred['Username'],\
                                          base64.b64decode(mypingdom.cred['Password']),\
                                          mypingdom.cred['apikey'])
    mypingdom.get_probes()
    mypingdom.print_probes()
    return { 'pingdom': mypingdom}

def cmd_check_paused(args):
    '''Called from main() to check and make sure
    we are aware of how many (if any) Pingdom
    checks are currently disabled (paused) and to
    alert by IRC and email if it is 50 or more.
    '''
    global debug
    debug = int(args['debug'])
    askpass = bool(args['askpass'].find('True') >= 0)
    if 'debug' in globals() and debug > 0:
        print "Enter cmd_check_paused"
    mypingdom = Pingdom()
    if askpass:
        mypingdom.input_credentials()
    else:
        mypingdom.load_credentials()
    mypingdom.server = pingdomlib.Pingdom(mypingdom.cred['Username'],\
                                          base64.b64decode(mypingdom.cred['Password']),\
                                          mypingdom.cred['apikey'])
    mypingdom.get_checks()
    if 'debug' in globals() and debug > 0:
        print "Paused: %03d Enabled: %03d Total: %03d" % \
              (mypingdom.paused,mypingdom.enabled,mypingdom.check_count)
    if mypingdom.paused > 0 and mypingdom.paused < 50:
        command='./sendtoirc Average: '+str(mypingdom.paused)+'/'+\
                str(mypingdom.enabled)+'/'+str(mypingdom.check_count)+\
                ' Pingdom check\(s\) paused/enabled/total'
        os.system(command)
    elif mypingdom.paused > 49:
        command='./sendtoirc High: '+str(mypingdom.paused)+\
                ' Pingdom checks paused - if not expected, run pingdom.py check -ena -a'
        os.system(command)
        msg = MIMEText('''
            Alert: There are '''+str(paused)+''' Pingdom checks paused.
            If this is not intentional, run this command as myuser 
            on myhost.mydomain.com:
            
            pingdom.py -ena -a
            
            We may be missing valid alerts until you fix this.
            ''')
        msg['To']=email.utils.formataddr(('Some User','someuser@somedomain.com'))
        msg['From']=email.utils.formataddr(('My User','myuser@mydomain.com'))
        msg['Subject']='Warning: '+str(paused)+' Pingdom Alerts are paused - please fix - see below'
        server=smtplib.SMTP('mail')
        try:
          server.sendmail('myuser@mydomain.com',\
                          ['someuser@somedomain.com'],msg.as_string())
        finally:
          server.quit()
    return {'pingdom': mypingdom}


def main():
    """Main entry point to host the command line parser and
    call the necessary method to perform the scans etc.
    """
    parser = argparse.ArgumentParser(description=\
             'Manage Pingdom Alerts and Services')
    metavar='{check,group,netwhois,paused,trace}'
    subparsers = parser.add_subparsers(metavar=metavar)
    
    
    check_parser = subparsers.add_parser('check',\
                    help = 'Modify checks')
    check_parser.set_defaults(func=cmd_modify_single_check)
    check_parser.add_argument('-N', action='store', type = int, default = 0,\
                    dest='number', help='Check ID #')
    check_parser.add_argument('-n', action='store', default = '',\
                    dest='name', help='Check name')
    check_parser.add_argument('-a', action='store_true', default = False,\
                    dest='allchecks', help='Modify all checks for this account')
    check_parser.add_argument('-dis', action='store_true', default = False,\
                    dest='disable', help='Disable checks')
    check_parser.add_argument('-ena', action='store_true', default = False,\
                    dest='enable', help='Enable checks')
    check_parser.add_argument('-debug', action='store', type = int, default=0,\
                    dest='debug', help='Debug level 0-9')
    check_parser.add_argument('-i', action='store_true', default = False,\
                    dest='askpass', help='Prompt for credentials to use')
    
    
    group_parser = subparsers.add_parser('group',\
                    help = 'Modify alert policy group members')
    group_parser.set_defaults(func=cmd_modify_group_checks)
    group_parser.add_argument('-N', action='store', type = int, default = 0,\
                    dest='number', help='Alert Policy ID #')
    group_parser.add_argument('-n', action='store', default = '',\
                    dest='name', help='Alert Policy name')
    group_parser.add_argument('-dis', action='store_true', default = False,\
                    dest='disable', help='Disable policy')
    group_parser.add_argument('-ena', action='store_true', default = False,\
                    dest='enable', help='Enable policy')
    group_parser.add_argument('-debug', action='store', type = int, default=0,\
                    dest='debug', help='Debug level 0-9')
    group_parser.add_argument('-i', action='store_true', default = False,\
                    dest='askpass', help='Prompt for credentials to use')
    
    
    netwhois_parser = subparsers.add_parser('netwhois',\
                    help = 'Perform ARIN network whois')
    netwhois_parser.set_defaults(func=cmd_netwhois)
    netwhois_parser.add_argument('address',action='store',\
                    help='IP Address to look up')
    netwhois_parser.add_argument('-debug', action='store', type = int, default=0,\
                    dest='debug', help='Debug level 0-9')
    
    
    trace_parser = subparsers.add_parser('trace',\
                    help = 'Perform traceroute')
    trace_parser.set_defaults(func=cmd_traceroute)
    trace_parser.add_argument('target',action='store',\
                    nargs=1, help='Traceroute destination')
    trace_parser.add_argument('-probe', action='store', type = int, default=44,\
                    dest='probe', help='Probe number to use')
    trace_parser.add_argument('-debug', action='store', type = int, default=0,\
                    dest='debug', help='Debug level 0-9')
    trace_parser.add_argument('-i', action='store_true', default = False,\
                    dest='askpass', help='Prompt for credentials to use')
    
    
    paused_parser = subparsers.add_parser('paused',\
                    help = 'Check number of paused checks')
    paused_parser.set_defaults(func=cmd_check_paused)
    paused_parser.add_argument('-debug', action='store', type = int, default=0,\
                    dest='debug', help='Debug level 0-9')
    paused_parser.add_argument('-i', action='store_true', default = False,\
                    dest='askpass', help='Prompt for credentials to use')
    
    probe_parser = subparsers.add_parser('probes',\
                    help = 'List pingdom probe sites')
    probe_parser.set_defaults(func=cmd_list_probes)
    probe_parser.add_argument('-debug', action='store', type = int, default=0,\
                    dest='debug', help='Debug level 0-9')
    probe_parser.add_argument('-i', action='store_true', default = False,\
                    dest='askpass', help='Prompt for credentials to use')
    
    cl = {}
    args = {}
    results = {}
    try:
        cl=parser.parse_args()
        for x in cl.__dict__:
            if "func" not in str(cl.__dict__[x]):
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
