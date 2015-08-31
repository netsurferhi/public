#!/usr/bin/env python

from email.mime.text import MIMEText
from urllib import urlopen
from xml.etree.ElementTree import parse
from xml.sax import saxutils, handler, make_parser
import base64
import copy
import email.utils
import getpass
import os
import pickle
import pprint
import re
import readline
import smtplib
import stat
import time

import argparse
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

class Pingdom(object):
    """Class to manage a pingdom account
    """
    def __init__(self):
        self.cred = {}
        self.probes = {}
        self.server = None
        self.checks = {}
        self.check_count = 0
        self.paused = 0
        self.enabled = 0
        self.check_xref = {}
        self.actions = {}
        self.alert_policy = {}
        self.alert_xref = {}
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
        for num in range(len(probelist)):
            self.probes[int(probelist[num]['id'])] = {}
            self.probes[int(probelist[num]['id'])]['id'] = int(probelist[num]['id'])
            self.probes[int(probelist[num]['id'])]['active'] =  bool(probelist[num]['active'])
            self.probes[int(probelist[num]['id'])]['city'] =  str(probelist[num]['city'])
            self.probes[int(probelist[num]['id'])]['country'] =  str(probelist[num]['country'])
            self.probes[int(probelist[num]['id'])]['countryiso'] =  str(probelist[num]['countryiso'])
            self.probes[int(probelist[num]['id'])]['hostname'] =  str(probelist[num]['hostname'])
            self.probes[int(probelist[num]['id'])]['ip'] =  str(probelist[num]['ip'])
            self.probes[int(probelist[num]['id'])]['name'] =  str(probelist[num]['name'])
        return
    
    def get_us_probe(self):
        """
        Method to yield probe(s) located in the US
        """
        for probe in sorted(self.probes.keys()):
            if self.probes[probe]['countryiso'].find('US') == 0 and\
               bool(self.probes[probe]['active']):
                return probe
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
    command='/home/myuser/pingdom/sendtoirc Average: '+cmdtype+str(resultmsg)
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
    command='/home/myuser/pingdom/sendtoirc Average: '+cmdtype+str(resultmsg)
    os.system(command)
    return {'args': args, 'pingdom': mypingdom, 'resultmsg': resultmsg}

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
    else:
        mypingdom.load_credentials()
    mypingdom.server = pingdomlib.Pingdom(mypingdom.cred['Username'],\
                                          base64.b64decode(mypingdom.cred['Password']),\
                                          mypingdom.cred['apikey'])
    mypingdom.get_probes()
    if probe in mypingdom.probes.keys() and \
                bool(mypingdom.probes[probe]['active']):
        print "\nTracing path to %s from Pingdom Probe Server #%d (%s)\n" % \
              (target,probe,mypingdom.probes[probe]['name'])
        results = mypingdom.server.traceroute(target,probe)
        print results['result']
        print
        return {'pingdom': mypingdom, 'results': results }
    else:
        probenum = mypingdom.get_us_probe()
        if probenum is not None:
            print "Probe #%d not found - using #%d (%s)" % \
                  (probe,probenum,mypingdom.probes[probenum]['name'])
            print "\nTracing path to %s from Pingdom Probe Server #%d (%s)\n" % \
                  (target,probenum,mypingdom.probes[probenum]['name'])
            results = mypingdom.server.traceroute(target,probenum)
            print results['result']
            print
            return {'pingdom': mypingdom, 'results': results }
            
        else:
            print "probe %d not found and no active US probe found"
    return {}

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
        command='/home/myuser/pingdom/sendtoirc Average: '+str(mypingdom.paused)+'/'+\
                str(mypingdom.enabled)+'/'+str(mypingdom.check_count)+\
                ' Pingdom check\(s\) paused/enabled/total'
        os.system(command)
    elif mypingdom.paused > 49:
        command='/home/myuser/pingdom/sendtoirc High: '+str(mypingdom.paused)+\
                ' Pingdom checks paused - if not expected, run myuser@myhost'+\
                '-01:/home/myuser/pingdom/pingdom.py check -ena -a'
        os.system(command)
        msg = MIMEText('''
            Alert: There are '''+str(paused)+''' Pingdom checks paused.
            If this is not intentional, run this command as myuser 
            on myhost-01.mydomain.com:
            
            /home/myuser/pingdom/pingdom.py -ena -a
            
            We may be missing valid alerts until you fix this.
            ''')
        msg['To']=email.utils.formataddr(('Some User','someuser@mydomain.com'))
        msg['From']=email.utils.formataddr(('My User','myuser@myhost-01.mydomain.com'))
        msg['Subject']='Warning: '+str(paused)+' Pingdom Alerts are paused - please fix - see below'
        server=smtplib.SMTP('mail')
        try:
          server.sendmail('myuser@myhost-01.mydomain.com',\
                          ['someuser@mydomain.com'],msg.as_string())
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
                    dest='probe', help='Debug level 0-9')
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
