#!/usr/bin/env python

import ast
import base64
import calendar
import copy
import datetime
import getpass
import json
import os
import pickle
import pprint
import re
import readline
import socket
import stat
import string
import sys
import time

from requests.exceptions import ConnectionError
import argparse
import iso8601
import requests


def fixcomma(strobj):
    """
    Replace all commas with semicolons
    """
    newstr=string.join(string.split(strobj,","),";")
    return newstr

def iso2unix(timestamp):
    """
    Convert a UTC timestamp formatted in ISO 8601 into a UNIX timestamp
    """
    # use iso8601.parse_date to convert the timestamp into a datetime object.
    parsed = iso8601.parse_date(timestamp)
    # now grab a time tuple that we can feed mktime
    timetuple = parsed.timetuple()
    # return a unix timestamp
    return calendar.timegm(timetuple)

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

def request_scans():
    """This method queues up the scans with SSL Labs, to be retrieved later.
    """
    udns = ultraDNS('Production','Stored')
    udns.get_token()
    udns.load_all_zones()
    scanlist = {}
    badscanlist = {}
    scans = {}
    errorcount = 0
    requestcount = 0
    completedcount = 0
    domaincount = 0
    arecordcount = 0
    nosslcount = 0
    nossllist = {}
    scannedip = set()
    duplicateip = 0
    duplicateiplist = {}
    duplicatehost = 0
    duplicatehostlist = {}
    if 'debug' in globals() and debug > 0:
        print " "
        print "Total domain count: %d" % len(udns.zone.keys())
    tempcount = 0
    for zonename in sorted(udns.zone.keys()):
        tempcount += len(udns.zone[zonename].rr_a.keys())
    if 'debug' in globals() and debug > 0:
        print "Total A record count: %d" % tempcount
        print " "
        print "Beginning to scan domains and hosts at ",
        print datetime.datetime.now()
        print " "
    for zonename in sorted(udns.zone.keys()):
        if zonename.find('.bak.') == (len(zonename)-5):
            if 'debug' in globals() and debug > 0:
                print "skipping %s" % zonename
            continue
        if zonename.find('.bkp.') == (len(zonename)-5):
            if 'debug' in globals() and debug > 0:
                print "skipping %s" % zonename
            continue
        domaincount += 1
        if 'debug' in globals() and debug > 0:
            print " "
            print datetime.datetime.now()
            print "\nProcessing zone [%d] %s:\n" % (domaincount,zonename)
            print "A record count for domain: %d" % (len(udns.zone[zonename].rr_a.keys()))
            print "Cumulative A record count: %d" % arecordcount
            print "Cumulative No SSL count: %d" % nosslcount
            print "Cumulative request count: %d" % requestcount
            print "Cumulative error count: %d" % errorcount
            print "Cumulative duplicate IP: %d" % duplicateip
            print "Cumulative duplicate host name: %d" % duplicatehost
            print " "
        tempcount = 0
        if len(udns.zone[zonename].rr_a.keys()) > 0:
            for hostname in sorted(udns.zone[zonename].rr_a.keys()):
                if hostname[0] == '6':
                    if 'debug' in globals() and debug > 0:
                        print 'skipping host %s' % hostname
                    continue
                if hostname.find('.bak.') == len(hostname)-5:
                    if 'debug' in globals() and debug > 0:
                        print 'skipping host %s' % hostname
                    continue
                if hostname.find('.bkp.') == len(hostname)-5:
                    if 'debug' in globals() and debug > 0:
                        print 'skipping host %s' % hostname
                    continue
                tempcount += 1
                if 'debug' in globals() and debug > 0:
                    print "Processing host [%d] %s" % (tempcount,hostname)
                hostaddr = udns.zone[zonename].rr_a[hostname]
                if 'debug' in globals() and debug > 0:
                    print "There are %d address(es)" % len(hostaddr[0])
                arecordcount += len(hostaddr[0])
                for x in range(len(hostaddr[0])):
                    if 'debug' in globals() and debug > 0:
                        print "  %s" % hostaddr[0][x]
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    result = sock.connect_ex((hostaddr[0][x],443))
                    if result == 0:
                        if 'debug' in globals() and debug > 0:
                            print "Port 443 is open"
                        testip = []
                        testip.append(hostaddr[0][x])
                        if hostname not in scanlist.keys(): 
                            if not (scannedip.issuperset(testip)):
                                scannedip.add(str(hostaddr[0][x]))
                                if 'debug' in globals() and debug > 0:
                                    print "Requesting SSL Labs scan of host"
                                ssllabs = SSL_Labs()
                                conn_ok = 1
                                while conn_ok == 1:
                                    try:
                                        ssllabs.get_info()
                                        conn_ok = 0
                                    except ConnectionError:
                                        if 'debug' in globals() and debug > 0:
                                            print "Socket error - retrying"
                                        time.sleep(1)
                                if 'debug' in globals() and debug > 0:
                                    ssllabs.print_info()
                                while (ssllabs.currentAssessments >= ssllabs.maxAssessments) or \
                                      (ssllabs.maxAssessments < 2):
                                    if 'debug' in globals() and debug > 0:
                                        print "Maximum scans requested - sleeping for one minute"
                                    time.sleep(60)
                                    conn_ok = 1
                                    while conn_ok == 1:
                                        try:
                                            ssllabs.get_info()
                                            conn_ok = 0
                                        except ConnectionError:
                                            if 'debug' in globals() and debug > 0:
                                                print "Socket error - retrying"
                                            time.sleep(1)
                                conn_ok = 1
                                while conn_ok == 1:
                                    try:
                                        response_code, results = ssllabs.analyze_host(hostname)
                                        conn_ok = 0
                                    except ConnectionError:
                                        if 'debug' in globals() and debug > 0:
                                            print "Socket error - retrying"
                                        time.sleep(1)
                                if 'debug' in globals() and debug > 0:
                                    pprint.pprint(response_code)
                                    print type(response_code)
                                    pprint.pprint(results)
                                    print type(results)
                                if response_code.status_code == 200 and \
                                   'status' in results.keys() and \
                                   results['status'].find('ERROR') < 0:
                                    scanlist[hostname] = {'status' : str(results['status']), \
                                                          'IP': str(hostaddr[0][x]), \
                                                          'Response': str(response_code)}
                                    requestcount += 1
                                    if 'debug' in globals() and debug > 0:
                                        print "Scan requested %s/%s" % \
                                          (str(hostname),str(hostaddr[0][x]))
                                elif response_code.status_code == 429:
                                    if 'debug' in globals() and debug > 0:
                                        print "Response code 429 - newAssessmentCoolOff = %d" % self.newAssessmentCoolOff
                                    time.sleep(int(newAssessmentCoolOff/1000))
                                    time.sleep(1)
                                else:
                                    badscanlist[hostname] = {'status': str(results['status']), \
                                                             'IP': str(hostaddr[0][x]), \
                                                             'Response': str(response_code.status_code)}
                                    errorcount += 1
                                    if 'debug' in globals() and debug > 0:
                                        print "Bad scan %s/%s" % \
                                         (str(hostaddr[0][x]),str(hostname))
                            else:
                                duplicateip += 1
                                duplicateiplist[str(hostaddr[0][x])+"_"+str(hostname)] = str(hostname)
                                if 'debug' in globals() and debug > 0:
                                    print "Skipping duplicate ip %s/%s" % \
                                          (str(hostaddr[0][x]),str(hostname))
                        else:
                            duplicatehost += 1
                            duplicatehostlist[str(hostname)+"_"+str(hostaddr[0][x])] = \
                                                               str(hostaddr[0][x])
                            if 'debug' in globals() and debug > 0:
                                print "Skipping duplicate hostname %s/%s" % \
                                (str(hostname),str(hostaddr[0][x]))
                    else:
                        if 'debug' in globals() and debug > 0:
                            print "Port 443 is closed"
                            print "%s/%s" % (str(hostname),str(hostaddr[0][x]))
                        nosslcount += 1
                        nossllist[str(hostname)+"_"+str(hostaddr[0][x])] = str(hostaddr[0][x])
                    sock.close()
    results = {}
    results['scanlist'] = copy.deepcopy(scanlist)
    results['badscanlist'] = copy.deepcopy(badscanlist)
    results['scans'] = copy.deepcopy(scans)
    results['A_Record'] = arecordcount
    results['No_SSL'] = nosslcount
    results['No_SSL_List'] = copy.deepcopy(nossllist)
    results['Request'] = requestcount
    results['Error'] = errorcount
    results['Dup_IP_Count'] = duplicateip
    results['Dup_IP_List'] = copy.deepcopy(duplicateiplist)
    results['Dup_Host'] = duplicatehost
    results['Dup_Host_List'] = copy.deepcopy(duplicatehostlist)
    if 'debug' in globals() and debug > 0:
        pprint.pprint(results)
        filename='scanrequest_'+datetime.datetime.isoformat((datetime.datetime.now()))
        outfile = open(filename,'wb')
        pickle.dump(results,outfile)
        outfile.close()
    return(results)

def request_results(ssl_scan):
    """This method goes back and requests the final results from
    SSL Labs.  You don't want to use this to request the scans as
    it does not queue but rather processes one host at a time.
    """
    if 'debug' in globals() and debug > 0:
        print "Enter request_results(ssl_scan)"
    ssllabs = SSL_Labs()
    sleepcount = 0
    sleephost = {}
    hostcount = 0
    if 'scanlist' in ssl_scan.keys():
        if 'debug' in globals() and debug > 0:
            print "scanlist found in ssl_scan.keys()"
        if len(ssl_scan['scanlist'].keys()) > 0:
            if 'debug' in globals() and debug > 0:
                print "found %d keys in scanlist" % len(ssl_scan['scanlist'].keys())
            for hostname in sorted(ssl_scan['scanlist'].keys()):
                if hostname[0] == '6':
                    if 'debug' in globals() and debug > 0:
                        print 'skipping host %s' % hostname
                    continue
                if hostname.find('.bak') == (len(hostname)-4):
                    if 'debug' in globals() and debug > 0:
                        print "skipping %s" % hostname
                    continue
                if hostname.find('.bkp') == (len(hostname)-4):
                    if 'debug' in globals() and debug > 0:
                        print "skipping %s" % hostname
                    continue
                hostcount += 1
                if 'debug' in globals() and debug > 0:
                    print "*"*40
                    print "top of for loop for host %s" % hostname
                conn_ok = 1
                while conn_ok == 1:
                    try:
                        response, results = ssllabs.check_status(hostname)
                        if 'debug' in globals() and debug > 0:
                            print "Headers:"
                            pprint.pprint(response.headers)
                        conn_ok = 0
                    except ConnectionError:
                        if 'debug' in globals() and debug > 0:
                            print "Socket error - retrying"
                        time.sleep(1)
                status = ''
                while int(response.status_code) != 200:
                    if 'debug' in globals() and debug > 0:
                        print "Headers:"
                        pprint.pprint(response.headers)
                    sleepcount += 1
                    if hostname not in sleephost.keys():
                        sleephost[hostname] = 0
                    sleephost[hostname] += 1
                    if 'debug' in globals() and debug > 0:
                        print "got response code %d - sleeping 15 seconds [1]" % \
                               int(response.status_code)
                        print "Sleepcount: %d/%d" % (sleepcount,hostcount)
                        print "host %s sleepcount: %d" % (hostname,sleephost[hostname])
                    time.sleep(15)
                    conn_ok = 1
                    while conn_ok == 1:
                        try:
                            response, results = ssllabs.check_status(hostname)
                            if 'debug' in globals() and debug > 0:
                                print "Headers:"
                                pprint.pprint(response.headers)
                                conn_ok = 0
                        except ConnectionError:
                            if 'debug' in globals() and debug > 0:
                                print "Socket error - retrying"
                            time.sleep(1)
                if 'status' in results.keys():
                    status = str(results['status'])
                    if 'debug' in globals() and debug > 0:
                        print "status is %s [1]" % status
                    while ((status.find('READY') < 0) and \
                           (status.find('ERROR') < 0)) or \
                          (int(response.headers['x-current-assessments']) >= \
                           int(response.headers['x-clientmaxassessments'])) or \
                           (int(response.status_code) != 200): 
                        sleepcount += 1
                        if hostname not in sleephost.keys():
                            sleephost[hostname] = 0
                        sleephost[hostname] += 1
                        if 'debug' in globals() and debug > 0:
                            print "response code %d" % int(response.status_code)
                            print "current vs max %d/%d" % \
                              (int(response.headers['x-current-assessments']),
                               int(response.headers['x-clientmaxassessments']))
                            print "scan pending - sleeping 15 seconds [2]"
                            print "Sleepcount: %d/%d" % (sleepcount,hostcount)
                            print "host %s sleepcount: %d" % (hostname,sleephost[hostname])
                        time.sleep(15)
                        conn_ok = 1
                        while conn_ok == 1:
                            try:
                                response, results = ssllabs.check_status(hostname)
                                if 'debug' in globals() and debug > 0:
                                    print "Headers:"
                                    pprint.pprint(response.headers)
                                conn_ok = 0
                            except ConnectionError:
                                if 'debug' in globals() and debug > 0:
                                    print "Socket error - retrying"
                                time.sleep(1)
                        if 'status' in results.keys():
                            status = str(results['status'])
                            if 'debug' in globals() and debug > 0:
                                print "status is now %s [2]" % status
                        else:
                            status = 'ERROR'
                            if 'debug' in globals() and debug > 0:
                                print "status not in results.keys() [1]"
                        if 'debug' in globals() and debug > 0:
                            print "bottom of while loop"
                    if 'debug' in globals() and debug > 0:
                        print "after while loop"
                else:
                    status = 'ERROR'
                    if 'debug' in globals() and debug > 0:
                        print "status not in results.keys() [2]"
                ssl_scan['scans'][hostname] = {}
                ssl_scan['scans'][hostname]['status'] = str(status)
                if 'debug' in globals() and debug > 0:
                    print "status now %s" % status
                if status.find('READY') >= 0:
                    if 'debug' in globals() and debug > 0:
                        print "status READY - storing endpoints"
                        pprint.pprint(response)
                        pprint.pprint(results)
                    ssl_scan['scans'][hostname]['results'] = copy.deepcopy(results)
            if 'debug' in globals() and debug > 0:
                print "moving results from scanlist to scans"
            for hostname in sorted(ssl_scan['scans'].keys()):
                if 'debug' in globals() and debug > 0:
                    print "checking %s" % hostname
                if hostname in ssl_scan['scanlist'].keys():
                    if 'debug' in globals() and debug > 0:
                        print "deleting %s" % hostname
                    del ssl_scan['scanlist'][hostname]
    if 'debug' in globals() and debug > 0:
        print "Done."
        filename='scanresult_'+datetime.datetime.isoformat((datetime.datetime.now()))
        outfile = open(filename,'wb')
        pickle.dump(ssl_scan,outfile)
        outfile.close()
    ssl_scan['sleepcount'] = int(sleepcount)
    ssl_scan['sleephost'] = copy.deepcopy(sleephost)
    return(ssl_scan)

def create_dict(ssl_scan):
    """This method takes the results returned from SSL Labs and puts it into
    the data_dict in a format that matches the Zoho database
    """
    data_dict = {}
    if 'debug' in globals() and debug > 0:
        print "In create_dict"
    for hostname in sorted(ssl_scan['scans'].keys()):
        if 'debug' in globals() and debug > 0:
            print "Processing %s" % hostname
            if 'debug' in globals() and debug > 1:
                pprint.pprint(ssl_scan['scans'][hostname],depth=5)
        if 'results' in ssl_scan['scans'][hostname].keys():
            if 'endpoints' in ssl_scan['scans'][hostname]['results'].keys():
                for endpt in range(len(ssl_scan['scans'][hostname]['results']['endpoints'])):
                    rec_key = str(hostname)+'_'+\
                              str(ssl_scan['scans'][hostname]['results']['endpoints'][endpt]['ipAddress'])
                    data_dict[rec_key] = {}
                    data_dict[rec_key]['Rec_Key'] = rec_key
                    data_dict[rec_key]['Host_Name'] = str(hostname)
                    data_dict[rec_key]['IP_Address'] = \
                      str(ssl_scan['scans'][hostname]['results']['endpoints'][endpt]['ipAddress'])
                    data_dict[rec_key]['Grade'] = ''
                    if 'grade' in ssl_scan['scans'][hostname]['results']['endpoints'][endpt].keys():
                        if (ssl_scan['scans'][hostname]['results']['endpoints'][endpt]['grade'].find('T') >= 0) or \
                           (ssl_scan['scans'][hostname]['results']['endpoints'][endpt]['grade'].find('M') >= 0):
                            data_dict[rec_key]['Grade'] = \
                              str(ssl_scan['scans'][hostname]['results']['endpoints'][endpt]['gradeTrustIgnored'])
                        else:
                            data_dict[rec_key]['Grade'] = \
                              str(ssl_scan['scans'][hostname]['results']['endpoints'][endpt]['grade'])
                    data_dict[rec_key]['Scan_Date'] = ''
                    if 'testTime' in ssl_scan['scans'][hostname]['results'].keys():
                        data_dict[rec_key]['Scan_Date'] = \
                          str(iso2zoho(datetime.datetime.isoformat(\
                                datetime.datetime.utcfromtimestamp(\
                                  ssl_scan['scans'][hostname]\
                                    ['results']['testTime']/1000))))
                    data_dict[rec_key]['Key_Size'] = 0
                    data_dict[rec_key]['Sig_Alg'] = ''
                    if 'details' in ssl_scan['scans'][hostname]['results']['endpoints']\
                       [endpt].keys() and \
                       'chain' in ssl_scan['scans'][hostname]['results']['endpoints'][endpt]\
                       ['details'].keys() and \
                       'certs' in ssl_scan['scans'][hostname]['results']['endpoints'][endpt]\
                       ['details']['chain'].keys() and \
                       'sigAlg' in ssl_scan['scans'][hostname]['results']['endpoints'][endpt]\
                       ['details']['chain']['certs'][0].keys():
                        data_dict[rec_key]['Sig_Alg'] = \
                          str(ssl_scan['scans'][hostname]['results']\
                            ['endpoints'][endpt]['details']['chain']\
                            ['certs'][0]['sigAlg'])
                    if 'details' in ssl_scan['scans'][hostname]['results']['endpoints']\
                       [endpt].keys() and \
                       'chain' in ssl_scan['scans'][hostname]['results']['endpoints'][endpt]\
                       ['details'].keys() and \
                       'certs' in ssl_scan['scans'][hostname]['results']['endpoints'][endpt]\
                       ['details']['chain'].keys() and \
                       'keySize' in ssl_scan['scans'][hostname]['results']['endpoints'][endpt]\
                       ['details']['chain']['certs'][0].keys():
                        data_dict[rec_key]['Key_Size'] = \
                          ssl_scan['scans'][hostname]['results']\
                            ['endpoints'][endpt]['details']['chain']\
                            ['certs'][0]['keySize']
                    data_dict[rec_key]['Warnings'] = 'No'
                    if 'hasWarnings' in ssl_scan['scans'][hostname]['results']['endpoints'][endpt].keys() and \
                        str(ssl_scan['scans'][hostname]['results']['endpoints'][endpt]['hasWarnings']).find('True') == 0:
                        data_dict[rec_key]['Warnings'] = 'Yes'
                    data_dict[rec_key]['Weak_Protos'] = 'No'
                    data_dict[rec_key]['SSLv1'] = 'No'
                    data_dict[rec_key]['SSLv2'] = 'No'
                    data_dict[rec_key]['SSLv3'] = 'No'
                    data_dict[rec_key]['TLSv1'] = 'No'
                    data_dict[rec_key]['TLSv1.1'] = 'No'
                    data_dict[rec_key]['TLSv1.2'] = 'No'
                    data_dict[rec_key]['TLSv1.3'] = 'No'
                    if 'details' in ssl_scan['scans'][hostname]['results']['endpoints'][endpt].keys() and \
                       'protocols' in ssl_scan['scans'][hostname]['results']['endpoints'][endpt]['details'].keys():
                        for proto in range(len(ssl_scan['scans'][hostname]\
                            ['results']['endpoints'][endpt]['details']['protocols'])):
                            if 'q' in ssl_scan['scans'][hostname]['results']\
                              ['endpoints'][endpt]['details']['protocols'][proto].keys():
                                data_dict[rec_key]['Weak_Protos'] = 'Yes'
                            if ssl_scan['scans'][hostname]['results']\
                              ['endpoints'][endpt]['details']['protocols'][proto]['name'].find('SSL') == 0:
                                if ssl_scan['scans'][hostname]['results']\
                                  ['endpoints'][endpt]['details']['protocols'][proto]['version'].find('3.0') == 0:
                                    data_dict[rec_key]['SSLv3'] = 'Yes'
                                elif ssl_scan['scans'][hostname]['results']\
                                  ['endpoints'][endpt]['details']['protocols'][proto]['version'].find('2.0') == 0:
                                    data_dict[rec_key]['SSLv2'] = 'Yes'
                                elif ssl_scan['scans'][hostname]['results']\
                                  ['endpoints'][endpt]['details']['protocols'][proto]['version'].find('1.0') == 0:
                                    data_dict[rec_key]['SSLv1'] = 'Yes'
                            elif ssl_scan['scans'][hostname]['results']\
                              ['endpoints'][endpt]['details']['protocols'][proto]['name'].find('TLS') == 0:
                                if ssl_scan['scans'][hostname]['results']\
                                  ['endpoints'][endpt]['details']['protocols'][proto]['version'].find('1.0') == 0:
                                    data_dict[rec_key]['TLSv1'] = 'Yes'
                                elif ssl_scan['scans'][hostname]['results']\
                                  ['endpoints'][endpt]['details']['protocols'][proto]['version'].find('1.1') == 0:
                                    data_dict[rec_key]['TLSv1.1'] = 'Yes'
                                elif ssl_scan['scans'][hostname]['results']\
                                  ['endpoints'][endpt]['details']['protocols'][proto]['version'].find('1.2') == 0:
                                    data_dict[rec_key]['TLSv1.2'] = 'Yes'
                                elif ssl_scan['scans'][hostname]['results']\
                                  ['endpoints'][endpt]['details']['protocols'][proto]['version'].find('1.3') == 0:
                                    data_dict[rec_key]['TLSv1.3'] = 'Yes'
                    data_dict[rec_key]['Weak_Ciphers'] = 'No'
                    if 'details' in ssl_scan['scans'][hostname]['results']['endpoints'][endpt].keys() and \
                       'suites' in ssl_scan['scans'][hostname]['results']['endpoints'][endpt]['details'].keys() and \
                       'list' in ssl_scan['scans'][hostname]['results']['endpoints'][endpt]['details']['suites'].keys():
                        if 'debug' in globals() and debug > 0:
                            print "Checking Cipher Suites"
                        for cipher in range(len(ssl_scan['scans'][hostname]\
                            ['results']['endpoints'][endpt]['details']['suites']['list'])):
                            if 'debug' in globals() and debug > 0:
                                print "checking %s cipher" % cipher
                            if 'q' in ssl_scan['scans'][hostname]['results']\
                              ['endpoints'][endpt]['details']['suites']['list'][cipher].keys():
                                if 'debug' in globals() and debug > 0:
                                    print "weak flag found - setting Weak_Ciphers true"
                                data_dict[rec_key]['Weak_Ciphers'] = 'Yes'
                    data_dict[rec_key]['Other_Issues'] = ''
                    if ssl_scan['scans'][hostname]['results']\
                          ['endpoints'][endpt]['statusMessage'].find('Ready') < 0:
                        data_dict[rec_key]['Other_Issues'] =  str(ssl_scan['scans'][hostname]['results']\
                          ['endpoints'][endpt]['statusMessage'])
        if ssl_scan['scans'][hostname]['status'].find('READY') < 0:
            data_dict[rec_key]['Other_Issues'] =  str(ssl_scan['scans'][hostname]['status'])
    if 'debug' in globals() and debug > 0:
        filename='data_dict_'+datetime.datetime.isoformat((datetime.datetime.now()))
        outfile = open(filename,'wb')
        pickle.dump(data_dict,outfile)
        outfile.close()
    return(ssl_scan,data_dict)

def upload_dict(data_dict,token):
    """This method takes the results of the scans which are stored in the data_dict
    and uploads it to Zoho Reports
    """
    if 'debug' in globals() and debug > 0:
        print "Enter upload_dict"
    headers = {'content-type': 'application/json'}
    url='https://reportsapi.zoho.com/api/USER@DOMAIN.COM/DATABASE/Certificates'
    for reckey in sorted(data_dict.keys()):
        if 'debug' in globals() and debug > 0:
            print "Top of for loop processing data_dict key = %s" % reckey
        payload={'ZOHO_ACTION': 'UPDATE','ZOHO_OUTPUT_FORMAT': 'JSON','ZOHO_ERROR_FORMAT': 'JSON', \
                 'authtoken': str(base64.b64decode(token)), 'ZOHO_API_VERSION': '1.0',\
                 'ZOHO_CRITERIA': '(\"Rec_Key\" = \''+reckey+'\')',\
                 'Grade': data_dict[reckey]['Grade'], \
                 'Host_Name': data_dict[reckey]['Host_Name'], \
                 'IP_Address': data_dict[reckey]['IP_Address'], \
                 'Key_Size': data_dict[reckey]['Key_Size'],\
                 'Other_Issues': data_dict[reckey]['Other_Issues'],\
                 'Rec_Key': reckey,\
                 'SSLv1': data_dict[reckey]['SSLv1'],\
                 'SSLv2': data_dict[reckey]['SSLv2'],\
                 'SSLv3': data_dict[reckey]['SSLv3'],\
                 'Scan_Date': data_dict[reckey]['Scan_Date'],\
                 'Sig_Alg': data_dict[reckey]['Sig_Alg'],\
                 'TLSv1': data_dict[reckey]['TLSv1'],\
                 'TLSv1.1': data_dict[reckey]['TLSv1.1'],\
                 'TLSv1.2': data_dict[reckey]['TLSv1.2'],\
                 'TLSv1.3': data_dict[reckey]['TLSv1.3'],\
                 'Warnings': data_dict[reckey]['Warnings'],\
                 'Weak_Ciphers': data_dict[reckey]['Weak_Ciphers'],\
                 'Weak_Protos': data_dict[reckey]['Weak_Protos']}
        conn_ok = 1
        while conn_ok == 1:
            try:
                if 'debug' in globals() and debug > 0:
                    print "in top try: request (update)"
                r = requests.post(url, headers=headers, params=payload)
                if 'debug' in globals() and debug > 0:
                    print "Got this response:"
                    print r.text
                rows = -1
                rtext = ast.literal_eval(r.text)
                if 'response' in rtext.keys() and \
                   'result' in rtext['response'].keys() and \
                   'updatedRows' in rtext['response']['result']:
                    rows = int(rtext['response']['result']['updatedRows'])
                    if 'debug' in globals() and debug > 0:
                        print "got %d rows" % int(rows)
                else:
                    if 'debug' in globals() and debug > 0:
                        print "compound if not met"
                    rows = -1
                if rows < 0:
                    if 'debug' in globals() and debug > 0:
                        print "Zoho request error - retrying"
                    time.sleep(1)
                else:
                    conn_ok = 0
                    if 'debug' in globals() and debug > 0:
                        print "got good response - got %d rows" % int(rows)
            except ConnectionError:
                if 'debug' in globals() and debug > 0:
                    print "Socket error - retrying"
                time.sleep(1)
        if 'debug' in globals() and debug > 0:
            print "rows is now:"
            print type(rows)
        if rows == 0:
            if 'debug' in globals() and debug > 0:
                print "Row not matched, proceeding to add"
            payload={'ZOHO_ACTION': 'ADDROW','ZOHO_OUTPUT_FORMAT': 'JSON','ZOHO_ERROR_FORMAT': 'JSON', \
               'authtoken': str(base64.b64decode(token)), 'ZOHO_API_VERSION': '1.0',\
               'Grade': data_dict[reckey]['Grade'], \
               'Host_Name': data_dict[reckey]['Host_Name'], \
               'IP_Address': data_dict[reckey]['IP_Address'], \
               'Key_Size': data_dict[reckey]['Key_Size'],\
               'Other_Issues': data_dict[reckey]['Other_Issues'],\
               'Rec_Key': reckey,\
               'SSLv1': data_dict[reckey]['SSLv1'],\
               'SSLv2': data_dict[reckey]['SSLv2'],\
               'SSLv3': data_dict[reckey]['SSLv3'],\
               'Scan_Date': data_dict[reckey]['Scan_Date'],\
               'Sig_Alg': data_dict[reckey]['Sig_Alg'],\
               'TLSv1': data_dict[reckey]['TLSv1'],\
               'TLSv1.1': data_dict[reckey]['TLSv1.1'],\
               'TLSv1.2': data_dict[reckey]['TLSv1.2'],\
               'TLSv1.3': data_dict[reckey]['TLSv1.3'],\
               'Warnings': data_dict[reckey]['Warnings'],\
               'Weak_Ciphers': data_dict[reckey]['Weak_Ciphers'],\
               'Weak_Protos': data_dict[reckey]['Weak_Protos']}
            conn_ok = 1
            while conn_ok == 1:
                if 'debug' in globals() and debug > 0:
                    print "top of while conn (add) loop with reckey = %s" % reckey
                try:
                    if 'debug' in globals() and debug > 0:
                        print "top of try (add) for request"
                    r = requests.post(url, headers=headers, params=payload)
                    if 'debug' in globals() and debug > 0:
                        print "no exception on request"
                    rows = -1
                    rtext = ast.literal_eval(r.text)
                    if 'debug' in globals() and debug > 0:
                        print "response was:"
                        pprint.pprint(rtext)
                    if 'response' in rtext.keys() and \
                       'result' in rtext['response'].keys() and \
                       'rows' in rtext['response']['result']:
                        rows = len(rtext['response']['result']['rows'])
                        if 'debug' in globals() and debug > 0:
                            print "got row count of %d" % int(rows)
                    else:
                        rows = -1
                        if 'debug' in globals() and debug > 0:
                            print "conditions not met"
                    if rows < 0:
                        if 'debug' in globals() and debug > 0:
                            print "Zoho request error - retrying"
                        time.sleep(1)
                    else:
                        conn_ok = 0
                        if 'debug' in globals() and debug > 0:
                            print "got good response - dropping out of loop"
                except ConnectionError:
                    if 'debug' in globals() and debug > 0:
                        print "Socket error - retrying"
                    time.sleep(1)
            if debug>0:
                print "Added record:\n"
                print r.text
        else: 
            if debug>0: 
                print "Updated record:\n"
                print r.text
    return data_dict

def cmd_scan_and_upload(args):
    """method to call the necessary methods and:
    1.  Submit scans to SSL Labs queue
    2.  Request the results
    3.  Create a dictionary in record format
    4.  Upload the dictionary to Zoho Reports
    """
    global debug
    debug = int(args['debug'])
    askpass = str(args['askpass'])
    token = ''
    if askpass.find('True') >= 0:
        token = input_zoho_credentials(token)
        store_zoho_credentials(token)
    token = load_zoho_credentials(token)
    ssl_scan = request_scans()
    ssl_scan = request_results(ssl_scan)
    ssl_scan,data_dict = create_dict(ssl_scan)
    data_dict = upload_dict(data_dict,token)
    return ssl_scan,data_dict

def set_zoho_credentials(token=''):
    """For self-contained script without password on file system
    """
    if 'debug' in globals() and debug > 0:
        print "In ultraDNS.set_credentials"
    token = "token"
    return token

def load_zoho_credentials(token):
    """Loads up the token and decodes them from
    the locally stored file .zoho  Note that
    passwords are not stored in plain text on disk
    nor in memory.
    """
    if 'debug' in globals() and debug > 0:
        print "Enter load credentials"
    if os.path.exists('.zoho'):
        infile = open('.zoho','rb')
        token = pickle.load(infile)
        infile.close()
    else:
        set_zoho_credentials(token)
        store_zoho_credentials(token)
    if 'debug' in globals() and debug > 0:
        print "Loaded obfuscated token ,%s>" % token
    infile.close()
    return token

def store_zoho_credentials(token=''):
    """Encodes and stores the current working token.
    Tokenss are not stored in plain text on disk nor
    in memory.
    """
    if 'debug' in globals() and debug > 0:
        print "Enter store credentials"
    if len(token) < 1:
        if 'debug' in globals() and debug > 0:
            print "No Token - storing default"
        token = "token"
        token = base64.b64encode(token)
    outfile = open('.zoho','wb')
    pickle.dump(token,outfile)
    outfile.close()
    os.chmod('.zoho', stat.S_IRWXU)
    if 'debug' in globals() and debug > 0:
        print "Storing:"
        print "Obfuscated Token: %s" % token
    return

def input_zoho_credentials(token=''):
    """Provides you with a way to input the necessary
    credentials and then store them securely with store_credentials.
    """
    if 'debug' in globals() and debug > 0:
        print "In input_credentials"
    try:
        token = base64.b64encode(getpass.getpass('Token:'))
    except EOFError:
        print "Error: PEBCAK - EOF received - using default token of 'token'"
        token = "token"
        token = base64.b64encode("token")
    if 'debug' in globals() and debug > 0:
        print "Results:"
        print "Obfuscated Token: %s" % token
    return token

def iso2zoho(timestamp):
    """
    Convert a UTC timestamp formatted in ISO 8601 into a Zoho friendly date
    """
    zohodate=makestr(datetime.datetime.fromtimestamp(iso2unix(makestr(timestamp))).strftime("%Y-%m-%d %H:%M:%S"))
    return zohodate

def makestr(strobj,max=0):
    """
    Make an object into a string, catch utf8 encoding
    """
    try:
      newstr=str(strobj)
    except UnicodeEncodeError:
      newstr=strobj.encode('ascii','ignore')
    finally:
      if (max>0) and (len(newstr)>max):
        return newstr[0:max]
      else:
        return newstr

class ultraDNS(object):
    """Class for managing and accessing UltraDNS
    """
    def __init__(self,environment,cmdtype="cmd"):
        """Initialize the cred dictionary and environment properties
        """
        self.cred = {}
        self.environment = environment[:]
        self.access_token = ''
        self.issued = ''
        self.expires = ''
        self.refresh_token = ''
        self.zone = {}
        self.default_column = 65
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
        return
    
    def set_credentials(self):
        """For self-contained script without password on file system
        """
        if 'debug' in globals() and debug > 0:
            print "In ultraDNS.set_credentials"
        self.cred['Username'] = "username"
        self.cred['Password'] = base64.b64encode("password")
        self.cred['Production'] = "https://restapi.ultradns.com"
        self.cred['Test'] = "https://test-restapi.ultradns.com"
        return
    
    def load_credentials(self):
        """Loads up the credentials and decodes them from
        the locally stored file .ultradns  Note that
        passwords are not stored in plain text on disk
        nor in memory.
        """
        if 'debug' in globals() and debug > 0:
            print "Enter load credentials"
        if os.path.exists('.ultradns'):
            infile = open('.ultradns','rb')
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
        if 'Production' not in self.cred.keys():
            if 'debug' in globals() and debug > 0:
                print "No Production Key - storing default"
            self.cred['Production'] = "https://restapi.ultradns.com"
        if 'Test' not in self.cred.keys():
            if 'debug' in globals() and debug > 0:
                print "No Test Key - storing default"
            self.cred['Test'] = "https://test-restapi.ultradns.com"
        outfile = open('.ultradns','wb')
        #self.cred['Password'] = base64.b64encode(self.cred['Password'])
        pickle.dump(self.cred,outfile)
        outfile.close()
        os.chmod('.ultradns', stat.S_IRWXU)
        if 'debug' in globals() and debug > 0:
            print "Storing:"
            print "Username: %s" % self.cred['Username']
            #print "Password: %s" % self.cred['Password']
            print "Production: %s" % self.cred['Production']
            print "Test: %s" % self.cred['Test']
        return
    
    def input_credentials(self):
        """Provides you with a way to input the necessary
        credentials and then store them securely with store_credentials.
        """
        if 'debug' in globals() and debug > 0:
            print "In input_credentials"
        try:
            self.cred['Username'] = raw_input('Username: ')
        except EOFError:
            print "Error: PEBCAK - EOF received - using default Username of 'Username'"
            self.cred['Username'] = "username"
        try:
            self.cred['Password'] = base64.b64encode(getpass.getpass('Password:'))
        except EOFError:
            print "Error: PEBCAK - EOF received - using default Password of 'password'"
            self.cred['Password'] = base64.b64encode("password")
        self.cred['Production'] = "https://restapi.ultradns.com"
        self.cred['Test'] = "https://test-restapi.ultradns.com"
        if 'debug' in globals() and debug > 0:
            print "Results:"
            print "Username: %s" % self.cred['Username']
            #print "Password: %s" % self.cred['Password']
            print "Production: %s" % self.cred['Production']
            print "Test: %s" % self.cred['Test']
        return
    
    def get_zone(self,zoneName):
        """Method to get the zone object for a given zoneName
        """
        if zoneName in self.zone.keys():
            return self.zone[zoneName]
        else:
            return None
    
    def palign(self,title,col,text):
        """Internal method to format an output line
        set self.default_column to the column you want to use
        """
        print title+"."*(col-len(title))+text
        return
    
    def print_username(self):
        """Print the Username from the credentials
        """
        self.palign("Username:",self.default_column,self.cred['Username'])
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
    
    def print_test(self):
        """Print the Test URL from the credentials
        """
        self.palign("Test",self.default_column,self.cred['Test'])
        return
    
    def print_environment(self):
        """Print the current working Environment
        """
        self.palign("Environment:",self.default_column,self.environment)
        return
    
    def print_access_token(self):
        """Print the current Access Token
        """
        self.palign("Access Token:",self.default_column, self.access_token)
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
    
    def print_refresh_token(self):
        """Print the Refresh Token value
        """
        self.palign("Refresh Token:",self.default_column,self.refresh_token)
        return
    
    def print_cred(self):
        """Method to print the current credentials
        """
        if 'debug' in globals() and debug > 0:
            print "enter print_cred"
        self.print_username()
        #self.print_password()
        self.print_production()
        self.print_test()
        self.print_environment()
        self.print_access_token()
        self.print_issued()
        self.print_expires()
        self.print_refresh_token()
        return
    
    def print_zone(self,zoneName):
        """Print out all records for a zone
        """
        if 'debug' in globals() and debug > 0:
            print "enter print_zone with zone = %s" % zoneName
        if zoneName in self.zone.keys():
            self.zone[zoneName].print_all()
        else:
            print "Error: zone %s not found" % zoneName
        return
    
    def print_all_zones(self):
        """Method to print all records in all zones
        """
        if 'debug' in globals() and debug > 0:
            print "enter print_all_zones"
        for zoneName in self.iter_zones():
            if 'debug' in globals() and debug > 0:
                print "printing zone %s" % zoneName
            zoneName.print_all()
        return
    
    def get_token(self):
        """Performs the initial authentication with ultraDNS
        and gets a working token and refresh token
        """
        headers = {
            'Content-type': 'application/x-www-form-urlencoded',
        }
        payload = {
          'grant_type':    'password',
          'username':      self.cred['Username'],
          'password':      base64.b64decode(self.cred['Password'])
        }
        authok=0
        while authok<1:
            if 'debug' in globals() and debug > 0:
                print "About to perform token request with UltraDNS"
            s = requests.post(self.cred[self.environment]+'/v1/authorization/token', headers=headers, params=payload)
            response=s.json()
            if 'debug' in globals() and debug > 0:
                pprint.pprint(response)
            if 'error' in response:
                if response['errorCode'] == 60001:
                    payload['password'] = self.cred['Password']
                    raise Exception('Error - bad ultraDNS User/Password')
                else:
                    print "Error received during ultraDNS authentication - retrying"
            else:
                payload['password'] = self.cred['Password']
                if 'debug' in globals() and debug > 0:
                    print "Authentication succeeded - continuing"
                authok=1
                self.issued = datetime.datetime.utcnow()
                if 'debug' in globals() and debug > 0:
                    issued_tstamp = utc_to_timestamp(self.issued)
                    print "Issued timestamp is %f" % issued_tstamp
                self.expires = datetime.datetime.utcfromtimestamp(utc_to_timestamp(self.issued) + \
                                                               float(response['expires_in']))
                self.access_token = response['access_token']
                self.refresh_token = response['refresh_token']
                if 'debug' in globals() and debug > 0:
                    self.print_issued()
                    self.print_expires()
                    print "Expire time: %f" % float(response['expires_in'])
                    self.print_access_token()
                    self.print_refresh_token()
        return
    
    def check_token(self):
        """Checks and if needed, updates the token
        """
        if utc_to_timestamp(self.expires) < utc_to_timestamp(datetime.datetime.utcnow()):
            update_token(self)
        return
    
    def update_token(self):
        """Updates the token using the refresh_token
        """
        headers = {
        'Content-type': 'application/x-www-form-urlencoded',
        }
        payload = {
          'grant_type':    'refresh_token',
          'refresh_token': self.refresh_token
        }
        if 'debug' in globals() and debug > 0:
            print "About to perform token request with UltraDNS"
        s = requests.post(self.cred[self.environment]+'/v1/authorization/token', headers=headers, params=payload)
        response=s.json()
        if 'debug' in globals() and debug > 0:
            pprint.pprint(response)
        if 'error' in response:
            if response['errorCode'] == 60001:
                raise Exception('Error - bad ultraDNS User/Password')
            else:
                print "Error received during ultraDNS authentication - retrying"
                self.get_token()
        else:
            if 'debug' in globals() and debug > 0:
                print "Authenticated succeeded - continuing"
            authok=1
            self.issued = datetime.datetime.utcnow()
            self.expires = datetime.datetime.utcfromtimestamp(utc_to_timestamp(self.issued) + \
                                                           float(response['expires_in']))
            self.access_token = response['access_token']
            self.refresh_token = response['refresh_token']
            if 'debug' in globals() and debug > 0:
                self.print_issued()
                self.print_expires()
                print "Expire time: %f" % float(response['expires_in'])
                self.print_access_token()
                self.print_refresh_token()
        return
    
    def load_zone(self,zoneName):
        """Gets a zone's metadata
        from ultraDNS.  Also loads the 
        rrset for a zone.
        """
        if 'debug' in globals() and debug > 0:
            print "enter load_zone with zone = %s" % zoneName
        headers = {
            'Content-type': 'application/x-www-form-urlencoded',
            'Authorization': 'Bearer '+self.access_token
        }
        payload = {
                   'offset': 0,
                   'limit': 1000,
                   'sort': 'NAME',
                   'reverse': 'false'
        }
        if 'debug' in globals() and debug > 0:
            print "in load_zone with %s" % zoneName
        if zoneName in self.zone.keys():
            self.delete_zone_cache(zoneName)
        s = requests.get(self.cred[self.environment]+'/v1/zones/'+zoneName, headers=headers, params=payload)
        response=s.json()
        if 'debug' in globals() and debug > 3:
            pprint.pprint(response)
        while 'error' in response:
            if 'debug' in globals() and debug > 0:
                print "Error received - retrying"
            self.get_token()
            s = requests.get(self.cred[self.environment]+'/v1/zones/'+zoneName, headers=headers, params=payload)
            response=s.json()
            if 'debug' in globals() and debug > 2:
                pprint.pprint(response)
        if 'debug' in globals() and debug > 0:
            print "zone request successful"
        if 'properties' in response.keys():
            zonename = response['properties']['name']
            if 'debug' in globals() and debug > 0:
                print "Processing <%s>" % zonename
            if 'resourceRecordCount' in response['properties'].keys():
                resourceRecordCount = int(response['properties']['resourceRecordCount'])
            else:
                resourceRecordCount = 0
            if 'lastModifiedDateTime' in response['properties'].keys():
                lastModifiedDateTime = response['properties']['lastModifiedDateTime']
            else:
                lastModifiedDateTime = ''
            if 'status' in response['properties'].keys():
                zonestatus = response['properties']['status']
            else:
                zonestatus = ''
            if 'type' in response['properties'].keys():
                zonetype = response['properties']['type']
            else:
                zonetype = ''
            if 'registrarInfo' in response.keys():
                if 'nameServers' in response['registrarInfo'].keys():
                    if 'debug' in globals() and debug > 0:
                        print "nameServers key found in results"
                    if 'ok' in response['registrarInfo']['nameServers'].keys():
                        if 'debug' in globals() and debug > 0:
                            print "ok key found in nameServers dictionary"
                        nameservers = response['registrarInfo']['nameServers']['ok']
                    else:
                        nameservers = []
                        if 'debug' in globals() and debug > 0:
                            print "no ok nameServers key found"
                if 'registrar' in response['registrarInfo'].keys():
                    registrar = response['registrarInfo']['registrar']
                    if 'debug' in globals() and debug > 0:
                        print "original registrar: <%s>" % registrar
                    registrar = registrar.strip()
                    if 'debug' in globals() and debug > 0:
                        print "registrar strip <%s>" % registrar
                    registrar = registrar.replace("\n", " ")
                    if 'debug' in globals() and debug > 0:
                        print "registrar finally <%s>" % registrar
                else:
                    registrar = ''
            else:
                nameservers = []
                registrar = ''
                if 'debug' in globals() and debug > 0:
                    print "no nameservers key found in results"
            self.zone[zonename] = ultraDNS_zone(self,zonename,resourceRecordCount,
                                                 lastModifiedDateTime,zonestatus,
                                                 zonetype,nameservers,registrar)
            self.load_rrset(zonename)
        else:
            print "Error loading zone %s" % zoneName
        return
    
    def delete_zone_cache(self,zoneName):
        """Method to delete the stored copy of a zone
        """
        if 'debug' in globals() and debug > 0:
            print "Enter delete_zone with %s" % zoneName
        if zoneName in self.zone.keys():
            if 'debug' in globals() and debug > 0:
                print "processing zone key %s - calling clear_rrset_cache" % zoneName
            self.clear_rrset_cache(zoneName)
            if 'debug' in globals() and debug > 0:
                print "deleting zone key %s " % zoneName
            del self.zone[zoneName]
            if 'debug' in globals() and debug > 0:
                print "Zone object %s deleted" % zoneName
        else:
            if 'debug' in globals() and debug > 0:
                print "Zone object %s not found - ignoring delete request" % zoneName
        return
    
    def reload_zone(self,zoneName):
        """Method to delete the current cached copy
        of a zone and reload it from ultraDNS.
        """
        if 'debug' in globals() and debug > 0:
            print "in reload_zone with %s" % zoneName
        if zoneName in self.zone.keys():
            self.delete_zone_cache(zoneName)
            self.load_zone(zoneName)
        else:
            print "Error: zone %s not found" % zoneName
        return
    
    def load_all_zones(self):
        """Gets all of the zones and their metadata
        from ultraDNS.  Also loads the rrsets associated
        with each zone loaded.
        """
        
        if 'debug' in globals() and debug > 0:
            print "enter load_all_zones"
        if len(self.zone.keys()) > 0:
            if 'debug' in globals() and debug > 0:
                print "zones already exist"
            for zname in self.zone.keys():
                if 'debug' in globals() and debug > 0:
                    print "clearing zone %s" % zname
                self.delete_zone_cache(zname)
        
        headers = {
            'Content-type': 'application/x-www-form-urlencoded',
            'Authorization': 'Bearer '+self.access_token
        }
        payload = {
                   'offset': 0,
                   'limit': 1000,
                   'sort': 'NAME',
                   'reverse': 'false'
        }
        if 'debug' in globals() and debug > 0:
            print "About to perform zone metadata request with UltraDNS"
        s = requests.get(self.cred[self.environment]+'/v1/zones', headers=headers, params=payload)
        response=s.json()
        if 'debug' in globals() and debug > 2:
            pprint.pprint(response)
        while 'error' in response:
            if 'debug' in globals() and debug > 0:
                print "Error received - retrying"
            self.get_token()
            s = requests.get(self.cred[self.environment]+'/v1/zones', headers=headers, params=payload)
            response=s.json()
            if 'debug' in globals() and debug > 2:
                pprint.pprint(response)
        if 'debug' in globals() and debug > 0:
            print "zone request successful"
        if 'resultInfo' in response.keys():
            if 'zones' in response.keys():
                if response['resultInfo']['returnedCount'] == response['resultInfo']['totalCount']:
                    for zonenum in range(int(response['resultInfo']['totalCount'])):
                        zonename = response['zones'][zonenum]['properties']['name']
                        if 'debug' in globals() and debug > 0:
                            print "Processing <%s>" % zonename
                        if 'resourceRecordCount' in response['zones'][zonenum]['properties'].keys():
                            resourceRecordCount = int(response['zones'][zonenum]['properties']['resourceRecordCount'])
                        else:
                            resourceRecordCount = 0
                        if 'lastModifiedDateTime' in response['zones'][zonenum]['properties'].keys():
                            lastModifiedDateTime = response['zones'][zonenum]['properties']['lastModifiedDateTime']
                        else:
                            lastModifiedDateTime = ''
                        if 'status' in response['zones'][zonenum]['properties'].keys():
                            zonestatus = response['zones'][zonenum]['properties']['status']
                        else:
                            zonestatus = ''
                        if 'type' in response['zones'][zonenum]['properties'].keys():
                            zonetype = response['zones'][zonenum]['properties']['type']
                        else:
                            zonetype = ''
                        if 'nameServers' in response['zones'][zonenum]['registrarInfo'].keys():
                            if 'debug' in globals() and debug > 0:
                                print "nameServers key found in results"
                            if 'ok' in response['zones'][zonenum]['registrarInfo']['nameServers'].keys():
                                if 'debug' in globals() and debug > 0:
                                    print "ok key found in nameServers dictionary"
                                nameservers = response['zones'][zonenum]['registrarInfo']['nameServers']['ok']
                            else:
                                nameservers = []
                                if 'debug' in globals() and debug > 0:
                                    print "no ok nameServers key found"
                        else:
                            nameservers = []
                            if 'debug' in globals() and debug > 0:
                                print "no nameservers key found in results"
                        if 'registrar' in response['zones'][zonenum]['registrarInfo'].keys():
                            registrar = response['zones'][zonenum]['registrarInfo']['registrar']
                            if 'debug' in globals() and debug > 0:
                                print "original registrar: <%s>" % registrar
                            registrar = registrar.strip()
                            if 'debug' in globals() and debug > 0:
                                print "registrar strip <%s>" % registrar
                            registrar = registrar.replace("\n", " ")
                            if 'debug' in globals() and debug > 0:
                                print "registrar finally <%s>" % registrar
                        else:
                            registrar = ''
                        if zonename in self.zone.keys():
                            self.delete_zone_cache(zonename)
                        self.zone[zonename] = ultraDNS_zone(self,zonename,resourceRecordCount,
                                                             lastModifiedDateTime,zonestatus,
                                                             zonetype,nameservers,registrar)
                        self.load_rrset(zonename)
                else:
                    print "Error: Did not get all available records"
            else:
                print "Error: No zones found"
        else:
            print "Error: No resultInfo found"
        return
    
    def print_zone_list(self):
        """Prints a quick list of all zones found
        """
        if len(self.zone.keys()) > 0:
            print ""
            for zonename in sorted(self.zone.keys()):
                self.palign("Zone:",self.default_column, zonename)
            print ""
        else:
            self.palign("Zone:",self.default_column, "None")
        return
    
    def iter_zones(self):
        """Yields the ultraDNS_zone objects in
        name sorted order.  You could use this to get
        all of the data on all zones printed out by
        doing something like this:
        
        for ultraDNS_zone in ultraDNS.iter_zones():
            ultraDNS_zone.print_all()
        
        """
        for zonename in sorted(self.zone.keys()):
            yield self.zone[zonename]
        return
    
    def zone_count(self):
        """Returns the current count of zones
        """
        return len(self.zone.keys())
    
    def clear_rrset_cache(self,zoneName):
        """Method to do good memory management in 
        deleting the individual records within a zone.
        """
        if 'debug' in globals() and debug > 0:
            print "In clear_rrset_cache for %s" % zoneName
        if len(self.zone[zoneName].rr_cname.keys()) > 0:
            if 'debug' in globals() and debug > 0:
                print "About to clear CNAME keys"
            for zrec in sorted(self.zone[zoneName].rr_cname.keys()):
                if 'debug' in globals() and debug > 1:
                    print "deleting cname key %s" % zrec
                del self.zone[zoneName].rr_cname[zrec]
        
        if len(self.zone[zoneName].rr_a.keys()) > 0:
            if 'debug' in globals() and debug > 0:
                print "About to clear A keys"
            for zrec in sorted(self.zone[zoneName].rr_a.keys()):
                if 'debug' in globals() and debug > 1:
                    print "deleting A key %s" % zrec
                del self.zone[zoneName].rr_a[zrec]
        
        if len(self.zone[zoneName].rr_ptr.keys()) > 0:
            if 'debug' in globals() and debug > 0:
                print "About to clear PTR keys"
            for zrec in sorted(self.zone[zoneName].rr_ptr.keys()):
                if 'debug' in globals() and debug > 1:
                    print "deleting PTR key %s" % zrec
                del self.zone[zoneName].rr_ptr[zrec]
        
        if len(self.zone[zoneName].rr_ns) > 0:
            if 'debug' in globals() and debug > 0:
                print "About to clear NS keys"
            for x in range(len(self.zone[zoneName].rr_ns)):
                if 'debug' in globals() and debug > 1:
                    print "deleting NS key [%s]" % (self.zone[zoneName].rr_ns[0])
                del self.zone[zoneName].rr_ns[0]
        
        if len(self.zone[zoneName].rr_txt) > 0:
            if 'debug' in globals() and debug > 0:
                print "About to clear TXT keys"
            for x in range(len(self.zone[zoneName].rr_txt)):
                if 'debug' in globals() and debug > 1:
                    print "deleting TXT key [%s]" % (self.zone[zoneName].rr_txt[0])
                del self.zone[zoneName].rr_txt[0]
        
        if len(self.zone[zoneName].rr_mx) > 0:
            if 'debug' in globals() and debug > 0:
                print "About to clear MX keys"
            for x in range(len(self.zone[zoneName].rr_mx)):
                if 'debug' in globals() and debug > 1:
                    print "deleting MX key [%s]" % (self.zone[zoneName].rr_mx[0])
                del self.zone[zoneName].rr_mx[0]
        return
    
    def load_rrset(self,zoneName):
        """Loads up the resource record sets from
        ultraDNS for a given zone.
        """
        if 'debug' in globals() and debug > 0:
            print "enter load_rrset"
        headers = {
            'Content-type': 'application/x-www-form-urlencoded',
            'Authorization': 'Bearer '+self.access_token
        }
        offset = int(0)
        response = {}
        response['resultInfo'] = {}
        response['resultInfo']['offset'] = offset
        response['resultInfo']['returnedCount'] = 0
        response['resultInfo']['totalCount'] = 1
        payload = {
                   'offset': offset,
                   'limit': 1000,
        }
        if zoneName in self.zone.keys():
            if 'debug' in globals() and debug > 0:
                print "About to perform zone rrset request with UltraDNS"
                print "offset: %s returnedCount: %d totalCount: %d" % \
                 (offset,int(response['resultInfo']['returnedCount']),\
                  int(response['resultInfo']['totalCount']))
            self.clear_rrset_cache(zoneName)
            while (offset+int(response['resultInfo']['returnedCount'])) <= int(response['resultInfo']['totalCount']):
                payload = {
                           'offset': offset,
                           'limit': 1000,
                }
                s = requests.get(self.cred[self.environment]+\
                                 '/v1/zones/'+zoneName+'/rrsets', \
                                 headers=headers, params=payload)
                response=s.json()
                while 'error' in response:
                    if 'debug' in globals() and debug > 0:
                        print "Error received - retrying"
                    self.get_token()
                    payload = {
                               'offset': offset,
                               'limit': 1000,
                    }
                    s = requests.get(self.cred[self.environment]+'/v1/zones/'+\
                                     zoneName+'/rrsets', headers=headers, params=payload)
                    response=s.json()
                if 'debug' in globals() and debug > 2:
                    print "Zone request results:"
                    pprint.pprint(response)
                if 'debug' in globals() and debug > 0:
                    print "Got offset: %d/%d returnedCount: %d totalCount: %d" % \
                     (offset,int(response['resultInfo']['offset']),\
                      int(response['resultInfo']['returnedCount']),\
                      int(response['resultInfo']['totalCount']))
                if 'rrSets' in response.keys() and zoneName == response['zoneName']:
                    if 'debug' in globals() and debug > 0:
                        print "zone request successful"
                    for rrSetRecord in response['rrSets']:
                        if 'debug' in globals() and debug > 1:
                            print rrSetRecord
                        ownerName,rrtype = '',''
                        ttl = 0
                        rdata = []
                        if 'ownerName' in rrSetRecord.keys():
                            ownerName = rrSetRecord['ownerName']
                        if 'rdata' in rrSetRecord.keys():
                            rdata = rrSetRecord['rdata']
                        if 'rrtype' in rrSetRecord.keys():
                            rrtype = rrSetRecord['rrtype']
                        if 'ttl' in rrSetRecord.keys():
                            ttl = rrSetRecord['ttl']
                        if rrtype.find(' ') > 0:
                            rrtype = rrtype.split(' ')[0]
                        ttl = int(ttl)
                        self.zone[zoneName].process_rr(ownerName,rdata,rrtype,ttl)
                if (offset+int(response['resultInfo']['returnedCount'])) == \
                      int(response['resultInfo']['totalCount']):
                    if 'debug' in globals() and debug > 0:
                        print "All data processed"
                        print "offset: %s returnedCount: %d totalCount: %d" % \
                          (offset,int(response['resultInfo']['returnedCount']),\
                           int(response['resultInfo']['totalCount']))
                    offset = 0
                    response['resultInfo']['returnedCount'] = int(1)
                    response['resultInfo']['totalCount'] = int(0)
                else:
                    offset += 1000
                    response['resultInfo']['returnedCount'] = int(0)
                    if 'debug' in globals() and debug > 0:
                        print "Incrementing offset by 1000: %d" % offset
        else:
            print "Zone: <%s> not found" % zonename
        return
    
    def add_rr_a(self,zoneName,hostName,address):
        """Adds or modifies an A record to the given zone.
        If record does not exists, adds.  If it does, updates.
        hostName must be FQDN terminated with a period
        """
        if 'debug' in globals() and debug > 0:
            print "Enter add_rr_a with %s = %s" % (hostName,address)
        headers = {
            'Content-type': 'application/json',
            'Authorization': 'Bearer '+self.access_token
        }
        payload = '{ "rdata": ["'+address+'"] }'
        checkok = 1
        response = {}
        update = 0
        txtype = ['add','update']
        if '.' not in hostName[-1:]:
            if 'debug' in globals() and debug > 0:
                print "No trailing period - adding"
            hostName = hostName + '.'
        if hostName.find("."+zoneName) < 1:
            print "Error - zoneName not in hostName or hostName not sub of zoneName"
            response = { 'error': 'Error - zoneName not in hostName '+\
                                  'or hostName not sub of zoneName'}
            checkok = 0
        if (checkok > 0):
            if (zoneName in self.zone.keys()):
                if 'debug' in globals() and debug > 0:
                    print "About to check if record exists already"
                if hostName in self.zone[zoneName].rr_a.keys():
                    if 'debug' in globals() and debug > 0:
                        print "record exists - flagging as update"
                    update = 1
                if update == 1:
                    if 'debug' in globals() and debug > 0:
                        print "About to perform rr patch request for %s with UltraDNS" % hostName
                    s = requests.patch(self.cred[self.environment]+'/v1/zones/'+zoneName+'/rrsets/A/'+hostName, headers=headers, data=payload)
                else:
                    if 'debug' in globals() and debug > 0:
                        print "About to perform rr add request for %s with UltraDNS" % hostName
                    s = requests.post(self.cred[self.environment]+'/v1/zones/'+zoneName+'/rrsets/A/'+hostName, headers=headers, data=payload)
                response=s.json()
                if 'debug' in globals() and debug > 0:
                    pprint.pprint(response)
                while 'error' in response:
                    if 'debug' in globals() and debug > 0:
                        print "Error received - retrying"
                    self.get_token()
                    s = requests.post(self.cred[self.environment]+'/v1/zones/'+zoneName+'/rrsets/A/'+hostName, headers=headers, data=payload)
                    response=s.json()
                if 'debug' in globals() and debug > 0:
                    print "Record add results:"
                    pprint.pprint(response)
                if (type(response) == dict) and ('message' in response.keys()):
                    if 'debug' in globals() and debug > 0:
                        print 'requested to %s %s IN A %s' % (txtype[update],hostName,address)
                        print "zone request %s" % response['message']
                    if 'Successful' in response['message']:
                        response['ok'] = 'record added/updated'
                    else:
                        print "Error: %s" % response['message']
                        response['error'] = response['message']
                        checkok = 0
            else:
                print "Zone: <%s> not found" % zoneName
                response = { 'error': 'Zone: <'+zoneName+'> not found' }
                checkok = 0
        else:
            if 'error' not in response.keys():
                response['error'] = 'invalid parameters'
            print "Error: <%s>" % response['error'] 
            checkok = 0
        return response
    
    def delete_rr_a(self,zoneName,hostName,address):
        """Deletes an A record from the given zone.
        hostName must be FQDN terminated with a period
        address must be full ip address and must exist 
        in the A record being deleted.
        """
        if 'debug' in globals() and debug > 0:
            print "Enter delete rr_a request for %s = %s with UltraDNS" % (hostName,address)
        checkok = 0
        response = {}
        if zoneName in self.zone.keys():
            if hostName in self.zone[zoneName].rr_a.keys():
                if address in self.zone[zoneName].rr_a[hostName][0]:
                    checkok = 1
                else:
                    print "Error - address %s not found in A record for host %s" % (address,hostName)
                    response['error'] = 'Error - address '+address+' not found in A record for host '+hostName
            else:
                print "Error - host %s A record not found" % hostName
                response['error'] = 'Error - A record for host '+hostName+' not found'
        else:
            print "Error - zone %s not found" % zoneName
            response['error'] = 'Error - zone '+zoneName+' not found'
        headers = {
            'Content-type': 'application/json',
            'Authorization': 'Bearer '+self.access_token
        }
        payload = '{ "rdata": ["'+address+'"] }'
        if (checkok > 0):
            if zoneName in self.zone.keys():
                if 'debug' in globals() and debug > 0:
                    print "About to perform rr delete request for %s = %s with UltraDNS" % (hostName,address)
                s = requests.delete(self.cred[self.environment]+'/v1/zones/'+zoneName+'/rrsets/A/'+hostName, headers=headers, data=payload)
                if 'debug' in globals() and debug > 0:
                    print "Response:"
                    pprint.pprint(s)
                    print "Type of Response:"
                    print type(s)
                    print "response.text:"
                    pprint.pprint(s.text)
                    print "content:"
                    pprint.pprint(s.content)
                    print "ok:"
                    pprint.pprint(s.ok)
                    print "repr"
                    print repr(s)
                    print "dict"
                    pprint.pprint(s.__dict__)
                    print "status code:"
                    pprint.pprint(s.status_code)
                    print "type of status code:"
                    print type(s.status_code)
                    print "url:"
                    pprint.pprint(s.url)
                if type(s) == requests.models.Response:
                    if s.status_code == 204:
                        response['ok'] = 'record deleted'
                    else:
                        print "Error: %s" % s
                        response['error'] = s
                else:
                    print "Error: <%s>" % s
                    response['error'] = s
                checkok = 0
                while (s.status_code != 204) and (checkok == 0):
                    if 'debug' in globals() and debug > 0:
                        print "Error received - retrying"
                    self.get_token()
                    s = requests.delete(self.cred[self.environment]+'/v1/zones/'+zoneName+'/rrsets/A/'+hostName, headers=headers, data=payload)
                    if 'debug' in globals() and debug > 0:
                        print "Response:"
                        pprint.pprint(s)
                if 'debug' in globals() and debug > 0:
                    print "Record delete results:"
                    pprint.pprint(s)
                if (s.status_code == 204):
                    checkok = 1
                    if 'debug' in globals() and debug > 0:
                        print 'requested to delete %s IN A %s' % (hostName,address)
                        print "zone request %s" % s
                    response['ok'] = 'record deleted'
            else:
                print "Error: zone <%s> not found" % zoneName
                response['error'] = "Error: zone "+zoneName+" not found"
        else:
            if 'debug' in globals() and debug > 0:
                pprint.pprint(response)
        return response
    
    def add_rr_cname(self,zoneName,hostName,target):
        """Adds or updates a CNAME record to the given zone.
        If record exists, updates.  If not, adds.
        hostName must be FQDN terminated with a period and 
        target must be FQDN terminated with a period.
        """
        if 'debug' in globals() and debug > 0:
            print "Enter add_rr_cname with %s = %s" % (hostName,target)
        headers = {
            'Content-type': 'application/json',
            'Authorization': 'Bearer '+self.access_token
        }
        payload = '{ "rdata": ["'+target+'"] }'
        response = {}
        checkok = 1
        update = 0
        txtype = ['add','update']
        if '.' not in hostName[-1:]:
            if 'debug' in globals() and debug > 0:
                print "No trailing period - adding"
            hostName = hostName + '.'
        if hostName.find("."+zoneName) < 1:
            print "Error - zoneName not in hostName or hostName not sub of zoneName"
            response['error'] = "Error - zoneName not in hostName or hostName not sub of zoneName"
            checkok = 0
        if (checkok > 0):
            if zoneName in self.zone.keys():
                if 'debug' in globals() and debug > 0:
                    print "checking to see if record exists already"
                if hostName in self.zone[zoneName].rr_cname.keys():
                    if 'debug' in globals() and debug > 0:
                        print 'record found - flagging for update'
                    update = 1
                if update == 1:
                    if 'debug' in globals() and debug > 0:
                        print "About to perform rr patch request for %s = %s with UltraDNS" % (hostName,target)
                    s = requests.patch(self.cred[self.environment]+'/v1/zones/'+zoneName+'/rrsets/CNAME/'+hostName, headers=headers, data=payload)
                else:
                    if 'debug' in globals() and debug > 0:
                        print "About to perform rr add request for %s = %s with UltraDNS" % (hostName,target)
                    s = requests.post(self.cred[self.environment]+'/v1/zones/'+zoneName+'/rrsets/CNAME/'+hostName, headers=headers, data=payload)
                response=s.json()
                if 'debug' in globals() and debug > 0:
                    pprint.pprint(response)
                while 'error' in response:
                    if 'debug' in globals() and debug > 0:
                        print "Error received - retrying"
                    self.get_token()
                    s = requests.post(self.cred[self.environment]+'/v1/zones/'+zoneName+'/rrsets/CNAME/'+hostName, headers=headers, data=payload)
                    response=s.json()
                if 'debug' in globals() and debug > 0:
                    print "Record add results:"
                    pprint.pprint(response)
                if (type(response) == dict) and ('message' in response.keys()):
                    if 'debug' in globals() and debug > 0:
                        print 'requested to %s %s IN CNAME %s' % (txtype[update],hostName,target)
                        print "zone request %s" % response['message']
                    if 'Successful' in response['message']:
                        response['ok'] = 'record added/updated'
                    else:
                        print "Error: %s" % response['message']
                        response['error'] = response['message']
                        checkok = 0
            else:
                response['error'] = 'Error: zone <'+zoneName+'> not found'
        else:
            if 'error' not in response.keys():
                response['error'] = 'invalid parameters'
            if 'debug' in globals() and debug > 0:
                pprint.pprint(response)
            print "Error: <%s>" % response['error']
        return response
    
    def delete_rr_cname(self,zoneName,hostName,target):
        """Deletes a CNAME record from the given zone.
        hostName must be FQDN terminated with a period
        target must be a FQDN and must exist 
        in the CNAME record being deleted.
        """
        if 'debug' in globals() and debug > 0:
            print "Enter delete rr_cname request for %s = %s with UltraDNS" % (hostName,target)
        checkok = 0
        response = {}
        if zoneName in self.zone.keys():
            if hostName in self.zone[zoneName].rr_cname.keys():
                if target in self.zone[zoneName].rr_cname[hostName][0]:
                    checkok = 1
                else:
                    print "Error - target %s not found in CNAME record for host %s" % (target,hostName)
                    response['error'] = 'Error - target '+target+' not found in CNAME record for host '+hostName
            else:
                print "Error - host %s CNAME record not found" % hostName
                response['error'] = 'Error - CNAME record for host '+hostName+' not found'
        else:
            print "Error - zone %s not found" % zoneName
            response['error'] = 'Error - zone '+zoneName+' not found'
        headers = {
            'Content-type': 'application/json',
            'Authorization': 'Bearer '+self.access_token
        }
        payload = '{ "rdata": ["'+target+'"] }'
        if (checkok > 0):
            if zoneName in self.zone.keys():
                if 'debug' in globals() and debug > 0:
                    print "About to perform rr delete request for %s = %s with UltraDNS" % (hostName,target)
                s = requests.delete(self.cred[self.environment]+'/v1/zones/'+zoneName+'/rrsets/CNAME/'+hostName, headers=headers, data=payload)
                if 'debug' in globals() and debug > 0:
                    print "Response:"
                    pprint.pprint(s)
                    print "Type of Response:"
                    print type(s)
                    print "response.text:"
                    pprint.pprint(s.text)
                    print "content:"
                    pprint.pprint(s.content)
                    print "ok:"
                    pprint.pprint(s.ok)
                    print "repr"
                    print repr(s)
                    print "dict"
                    pprint.pprint(s.__dict__)
                    print "status code:"
                    pprint.pprint(s.status_code)
                    print "type of status code:"
                    print type(s.status_code)
                    print "url:"
                    pprint.pprint(s.url)
                if type(s) == requests.models.Response:
                    if s.status_code == 204:
                        response['ok'] = 'record deleted'
                    else:
                        print "Error: %s" % s
                        response['error'] = s
                else:
                    print "Error: <%s>" % s
                    response['error'] = s
                checkok = 0
                while (s.status_code != 204) and (checkok == 0):
                    if 'debug' in globals() and debug > 0:
                        print "Error received - retrying"
                    self.get_token()
                    s = requests.delete(self.cred[self.environment]+'/v1/zones/'+zoneName+'/rrsets/CNAME/'+hostName, headers=headers, data=payload)
                    if 'debug' in globals() and debug > 0:
                        print "Response:"
                        pprint.pprint(s)
                if 'debug' in globals() and debug > 0:
                    print "Record delete results:"
                    pprint.pprint(s)
                if (s.status_code == 204):
                    checkok = 1
                    if 'debug' in globals() and debug > 0:
                        print 'requested to delete %s IN CNAME %s' % (hostName,target)
                        print "zone request %s" % s
                    response['ok'] = 'record deleted'
            else:
                print "Error: zone <%s> not found" % zoneName
                response['error'] = "Error: zone "+zoneName+" not found"
        else:
            if 'error' not in response.keys():
                response['error'] = 'invalid parameters'
            if 'debug' in globals() and debug > 0:
                pprint.pprint(response)
            print "Error: %s" % response['error']
        return response
    

class ultraDNS_zone(object):
    """ An ultraDNS_zone object is a container for a particular zone file
        and contains methods and containers for the various record types.
    """
    def __init__(self,parent,name,resourceRecordCount,lastModifiedDateTime,status,type,nameservers,registrar):
        self.parent = parent
        self.name = name[:]
        self.resourceRecordCount = int(resourceRecordCount)
        self.set_lastModifiedDateTime(lastModifiedDateTime)
        self.status = status[:]
        self.type = type[:]
        self.nameServers = [] # list of working dns servers per ultradns
        self.setNameServers(nameservers)
        self.registrar = registrar[:]
        self.rr_cname = {} # dict of cname records
        self.rr_a = {} # dict of A records
        self.rr_ptr = {} # dict of PTR records
        self.rr_txt = [] # list of TXT records
        self.rr_ns = [] # list of NS records
        self.rr_mx = [] # list of MX records
        self.rr_soa = '' # complete SOA record
        self.soa_nameserver = ''
        self.soa_email = ''
        self.soa_sn = ''
        self.soa_sn_year = 0
        self.soa_sn_month = 0
        self.soa_sn_day = 0
        self.soa_sn_index = 0
        self.soa_refresh = 0
        self.soa_retry = 0
        self.soa_expiry = 0
        self.soa_nx_ttl = 0
        self.default_column = 65
        return
    
    def palign(self,title,col,text):
        """Internal method to format an output line
        set self.default_column to the column you want to use
        """
        print title+"."*(col-len(title))+str(text)
        return
    
    def incr_sn(self):
        """Take an existing soa record and update the
        serial number by either setting it to the current
        day and an index of 1 if today is a greater date
        than the last update, or if today is the same date
        as the last update, increment the index by 1.
        """
        today_date = datetime.datetime.now()
        today_year = int(today_date.year)
        today_month = int(today_date.month)
        today_day = int(today_date.day)
        if int(today_year) == self.soa_sn_year:
            if int(today_month) == self.soa_sn_month:
                if int(today_day) == self.soa_sn_day:
                    self.soa_sn_index += 1
                else:
                    elf.soa_sn_day = today_day
                    self.soa_sn_index = 1
            else:
                self.soa_sn_month = today_month
                elf.soa_sn_day = today_day
                self.soa_sn_index = 1
        else:
            self.soa_sn_year = today_year
            self.soa_sn_month = today_month
            self.soa_sn_day = today_day
            self.soa_sn_index = 1
        self.soa_sn = str(self.soa_sn_year)+str.format("{0:02d}",self.soa_sn_month)+ \
                      str.format("{0:02d}",self.soa_sn_day)+str.format("{0:02d}",self.soa_sn_index)
        return
    
    def set_lastModifiedDateTime(self,lastModifiedDateTime):
        """Takes the last modified date and time and turns it
        into an actual datetime object.
        """
        lastModifiedDateTime_timestamp = iso2unix(lastModifiedDateTime)
        self.lastModifiedDateTime = datetime.datetime.utcfromtimestamp(lastModifiedDateTime_timestamp)
        return
        
    def print_zone_metadata(self):
        """This prints out the ultraDNS metadata for a given zone.
        When listing nameservers, it only lists the ones that
        ultraDNS marks as "ok".  Those marked as "missing" are not
        displayed.  This can be compared to the ns records of the zone
        to find entries which are not working from the view of ultraDNS.
        """
        self.palign("Name:",self.default_column,self.name)
        self.palign("Type:",self.default_column,self.type)
        self.palign("Status:",self.default_column,self.status)
        lastModifiedDateTime_str = self.lastModifiedDateTime.strftime("%m/%d/%y %H:%M:%S %z")
        self.palign("Last Modified:",self.default_column,lastModifiedDateTime_str)
        self.palign("Registrar:",self.default_column,self.registrar[0:40])
        if len(self.nameServers) > 0:
            for nameServer in self.nameServers:
                self.palign("Working NS:",self.default_column,nameServer)
        else:
            self.palign("Working NS:",self.default_column,"")
        return
    
    def setNameServers(self,nameservers):
        """Internal method to take the list of nameservers
        and add them into a list we can iterate.  This is
        part of the __init__ process.
        """
        if len(nameservers) > 0:
            for nameserver in nameservers:
                self.nameServers.append(nameserver)
                if 'debug' in globals() and debug > 0:
                    print "setNameServers: appending name server %s" % nameserver
        else:
            if 'debug' in globals() and debug > 0:
                print "setNameServers: no nameserver records submitted"
        return
    
    def process_rr(self,ownerName,rdata,rrtype,ttl):
        """internal method to take the ultraDNS RRSet DTO's
        returned by ultraDNS and store them in the collections
        within the zone.
        """
        if 'debug' in globals() and debug > 1:
            print "Enter process_rr"
            print "ownerName: %s" % ownerName
            print "rdata: %s" % rdata
            print "rrtype: %s" % rrtype
            print "ttl: %d" % int(ttl)
        if rrtype == 'SOA':
            if 'debug' in globals() and debug > 1:
                print "in SOA"
                print "rdata = %s" % rdata
                print "ttl = %d" % int(ttl)
            self.rr_soa = [rdata,ttl]
            self.soa_nameserver,self.soa_email,self.soa_sn, \
                self.soa_refresh,self.soa_retry,self.soa_expiry, \
                self.soa_nx_ttl = self.rr_soa[0][0].split(' ')
            self.soa_refresh = int(self.soa_refresh)
            self.soa_retry = int(self.soa_retry)
            self.soa_expiry = int(self.soa_expiry)
            self.soa_nx_ttl = int(self.soa_nx_ttl)
            self.soa_sn_year = int(self.soa_sn[0:4])
            self.soa_sn_month = int(self.soa_sn[4:6])
            self.soa_sn_day = int(self.soa_sn[6:8])
            self.soa_sn_index = int(self.soa_sn[8:10])
            if 'debug' in globals() and debug > 1:
                print "self.rr_soa[0] = %s" % self.rr_soa[0]
                print "self.rr_soa[1] = %d" % int(self.rr_soa[1])
        elif rrtype == 'TXT':
            if 'debug' in globals() and debug > 1:
                print "in TXT"
            self.rr_txt.append([rdata[0],ttl])
        elif rrtype == 'MX':
            if 'debug' in globals() and debug > 1:
                print "in MX"
            self.rr_mx.append([rdata,ttl])
        elif rrtype == 'NS':
            if 'debug' in globals() and debug > 1:
                print "in NS"
            self.rr_ns.append([rdata,ttl])
        elif rrtype == 'CNAME':
            if 'debug' in globals() and debug > 1:
                print "in CNAME"
            self.rr_cname[ownerName] = [rdata,ttl]
        elif rrtype == 'A':
            if 'debug' in globals() and debug > 1:
                print "in A"
            self.rr_a[ownerName] = [rdata,ttl]
        elif rrtype == 'PTR':
            if 'debug' in globals() and debug > 1:
                print "in PTR"
            self.rr_ptr[ownerName] = [rdata,ttl]
        return
    
    def print_cname(self,ownerName):
        """Print a cname record matching ownerName
        """
        if ownerName in self.rr_cname.keys():
            self.palign(ownerName+" "+str(self.rr_cname[ownerName][1])+" IN CNAME ", \
                        self.default_column, \
                        self.rr_cname[ownerName][0][0])
        return
    
    def get_cname(self,ownerName):
        """Finds and returns a list containing the name[0],
        the record it points to[1], and the ttl on the record[2]
        which are empty if the cname is not found.
        """
        cname = ''
        ttl = 0
        if ownerName in self.rr_cname.keys():
            cname = self.rr_cname[ownerName][0][0]
            ttl = self.rr_cname[ownerName][1]
        return ownerName,cname,ttl
    
    def iter_cname(self):
        """Iterator which returns a generator object for 
        tuples containing the name, what it is cnamed to, 
        and the ttl of the record.
        """
        for cname in self.rr_cname.keys():
            rcname,rtarget,rttl = self.get_cname(cname)
            yield cname,rtarget,rttl
        return
    
    def print_a(self,ownerName):
        """Print a given A record for ownerName
        """
        if ownerName in self.rr_a.keys():
            for x in range(len(self.rr_a[ownerName][0])):
                self.palign(ownerName+" "+str(self.rr_a[ownerName][1])+" IN A ",\
                    self.default_column, self.rr_a[ownerName][0][x])
        return
    
    def get_a(self,ownerName):
        """Finds and returns a tuple containing
        the name, list of a records, and ttl of the
        record if found, empty if not.
        """
        arec = ''
        ttl = 0
        if ownerName in self.rr_a.keys():
            arec = self.rr_a[ownerName][0]
            ttl = self.rr_a[ownerName][1]
        return ownerName,arec,ttl
    
    def iter_a(self):
        """Generator yields name, address, ttl from A records 
        """
        for arec in self.rr_a.keys():
            yield arec,self.rr_a[arec][0],rr_a[arec][1]
        return
    
    def print_soa(self):
        """Print the current SOA record and its individual values
        """
        if len(self.rr_soa) > 0:
            self.palign("SOA NS",self.default_column, self.soa_nameserver)
            self.palign("SOA Email",self.default_column, self.soa_email)
            self.palign("SOA SN",self.default_column, self.soa_sn)
            self.palign("SOA SN Year",self.default_column, str(self.soa_sn_year))
            self.palign("SOA SN Month",self.default_column, str.format("{0:02d}",self.soa_sn_month))
            self.palign("SOA SN Day",self.default_column, str.format("{0:02d}",self.soa_sn_day))
            self.palign("SOA SN Index",self.default_column, str.format("{0:02d}",self.soa_sn_index))
            self.palign("SOA RF",self.default_column, str(self.soa_refresh))
            self.palign("SOA RT",self.default_column,str(self.soa_retry))
            self.palign("SOA Exp",self.default_column, str(self.soa_expiry))
            self.palign("SOA NX TTL",self.default_column, str(self.soa_nx_ttl))
            self.palign("IN SOA",self.default_column, str(self.rr_soa[0][0]))
        if len(self.rr_soa) > 1:
            self.palign("TTL",self.default_column,str(self.rr_soa[1]))
        return
    
    def get_soa(self):
        """Returns a tuple with the soa record itself and
        the ttl for the soa record.
        """
        return self.rr_soa[0][0],self.rr_soa[1]
    
    def get_soa_full(self):
        """Returns a tuple with full details of the soa record
        broken down into the full soa record, the ttl on the record,
        the nameserver from the soa, the email from the soa, the 
        serial number year, month, day, index, the refresh, 
        retry, expiry, and soa ns ttl.
        """
        return self.rr_soa[0][0],self.rr_soa[1],self.soa_nameserver, \
               self.soa_email,self.soa_sn,self.soa_sn_year,self.soa_sn_month, \
               self.soa_sn_day,self.soa_sn_index,self.soa_refresh, \
               self.soa_retry,self.soa_expiry,self.soa_nx_ttl
               
    def get_soa_sn(self):
        """Returns the serial number as a single string
        """
        return self.soa_sn
    
    def get_soa_sn_full(self):
        """Returns a tuple of the serial number as a single
        string, the year, month, day, and index as integers.
        """
        return self.soa_sn,self.soa_sn_year,self.soa_sn_month,self.soa_sn_day,self.soa_sn_index
    
    def print_txt(self):
        """Prints the text records associated with a zone
        """
        if len(self.rr_txt) > 0:
            for txtrec in range(len(self.rr_txt)):
                self.palign(str(self.rr_txt[txtrec][1])+" IN TXT",self.default_column, self.rr_txt[txtrec][0])
        return
    
    def get_txt(self):
        """Returns a list containing lists of the txt records and their ttls
        """
        return self.rr_txt
    
    def iter_txt(self):
        """Generator yields txt record, ttl
        """
        for x in range(len(self.rr_txt)):
            yield self.rr_txt[x][0],self.rr_txt[x][1]
        return
    
    def print_mx(self):
        """Print all MX records for the domain
        """
        if len(self.rr_mx) > 0:
            for mxrec in range(len(self.rr_mx)):
                for subrec in range(len(self.rr_mx[mxrec][0])):
                    self.palign(str(self.rr_mx[mxrec][1])+" IN MX",self.default_column, self.rr_mx[mxrec][0][subrec])
        return
    
    def get_mx(self):
        """Returns a list containing a single list 
        made of a list of mx records[0] and
        the ttl for them[1].  So each mx host is
        in [0][0][x] and the ttl is in [0][1]
        and len([0][0]) is the # of hosts.
        This is specific to ultraDNS
        """
        return self.rr_mx
    
    def iter_mx(self):
        """Generator yields each mx host record,ttl
        """
        for x in range(len(self.rr_mx)):
            for y in range(len(self.rr_mx[x][0])):
                yield self.rr_mx[x][0][y],self.rr_mx[x][1]
        return
    
    def print_ns(self):
        """Print all NS records for the domain
        """
        if len(self.rr_ns) > 0:
            for nsrec in range(len(self.rr_ns)):
                for subrec in range(len(self.rr_ns[nsrec][0])):
                    self.palign(str(self.rr_ns[nsrec][1])+" IN NS",self.default_column, self.rr_ns[nsrec][0][subrec])
        return
    
    def get_ns(self):
        """Returns a list containing a list of ns servers[0]
        and the ttl for them [1]
        """
        return self.rr_ns[0][0],self.rr_ns[0][1]
    
    def iter_ns(self):
        """Generator yields each ns host,ttl
        """
        for x in range(len(self.rr_ns[0][0])):
            yield self.rr_ns[0][0][x],self.rr_ns[0][1]
        return
    
    def print_ptr(self,ownerName):
        """Print a PTR record for ownerName if found
        """
        if ownerName in self.rr_ptr.keys():
            for ptr in range(len(self.rr_ptr[ownerName][0])):
                self.palign(ownerName+str(self.rr_ptr[ownerName][1])+" IN PTR ",self.default_column, self.rr_ptr[ownerName][0][ptr])
        return
    
    def get_ptr(self,ownerName):
        """Finds and returns a list containing the name[0],
        the record it points to[1], and the ttl on the record[2]
        which are empty if the cname is not found.
        """
        ptr = ''
        ttl = 0
        if ownerName in self.rr_ptr.keys():
            ptr = self.rr_ptr[ownerName][0]
            ttl = self.rr_ptr[ownerName][1]
        return ownerName,ptr,ttl
    
    def iter_ptr(self):
        """Iterator which returns a generator object for 
        tuples containing the name, what it is cnamed to, 
        and the ttl of the record.
        """
        for ptr in self.rr_ptr.keys():
            yield ptr,self.get_ptr(ptr)[1],self.get_ptr(ptr)[2]
        return
    
    def print_all(self):
        """Print metadata and all records for a domain
        """
        print "*"*30
        self.print_zone_metadata()
        print "="*30
        self.print_soa()
        self.print_ns()
        self.print_txt()
        self.print_mx()
        for arec in sorted(self.rr_a.keys()):
            self.print_a(arec)
        for cnrec in sorted(self.rr_cname.keys()):
            self.print_cname(cnrec)
        for ptrrec in sorted(self.rr_ptr.keys()):
            self.print_ptr(ptrrec)
        print "*"*30
        return
    
    def a_to_ptr(self,ownerName):
        """Method to get a list of the A records,
        and if we host the PTR zone, get any 
        matching PTR records and return 
        ownerName,areclist,ptrlist,ptrzonelist,skiplist
        where ownerName is the hostname being checked
        areclist is a list of A records associated with that name
        ptrlist is a dictionary of ptr records for each IP address
        and skiplist is a list of zones we had to skip as we don't
        host them.
        """
        arec = self.rr_a[ownerName]
        areclist = []
        ptrlist = {}
        ptrzonelist = []
        skiplist = []
        missinglist = []
        if 'debug' in globals() and debug > 0:
            print "%"*40
            print "Checking %s A records to PTR records" % ownerName
        for x in range(len(arec[0])):
            if 'debug' in globals() and debug > 0:
                print "processing %d (%s)" % (x,arec[0][x])
            if arec[0][x] not in areclist:
                if 'debug' in globals() and debug > 0:
                    print "appending %s" % arec[0][x]
                areclist.append(arec[0][x])
            q1,q2,q3,q4 = arec[0][x].split(".")
            a_inv = str(q4)+"."+str(q3)+"."+str(q2)+"."+str(q1)+".in-addr.arpa."
            ptr_zone = str(q3)+"."+str(q2)+"."+str(q1)+".in-addr.arpa."
            if ptr_zone not in ptrzonelist:
                if 'debug' in globals() and debug > 0:
                    print "appending %s" % ptr_zone
                ptrzonelist.append(ptr_zone)
            if 'debug' in globals() and debug > 0:
                print "Quad: %s %s %s %s" % (q1,q2,q3,q4)
                print "Inverse record %s" % a_inv
                print "PTR Zone %s" % ptr_zone
            if ptr_zone in self.parent.zone.keys():
                if 'debug' in globals() and debug > 0:
                    print "checking for %s in %s" % (a_inv,ptr_zone)
                if a_inv in self.parent.zone[ptr_zone].rr_ptr.keys():
                    if 'debug' in globals() and debug > 0:
                        print "found %s in %s" % (a_inv,ptr_zone)
                    ptr = self.parent.zone[ptr_zone].rr_ptr[a_inv]
                else:
                    if 'debug' in globals() and debug > 0:
                        print "%s not found in %s" % (a_inv,ptr_zone)
                    ptr = [[]]
                    if a_inv not in missinglist:
                        if 'debug' in globals() and debug > 0:
                            print "%s not in missinglist" % a_inv
                        missinglist.append(arec[0][x])
                if 'debug' in globals() and debug > 0:
                    print "PTR set %s" % ptr
                ptrlist[arec[0][x]] = ptr[0]
                if 'debug' in globals() and debug > 0:
                    print "add %s -> %s" % (arec[0][x],ptr[0])
            else:
                if 'debug' in globals() and debug > 0:
                    print "Reverse zone %s not in ultraDNS - skipping %s" % (ptr_zone,arec[0][x])
                if arec[0][x] not in skiplist:
                    if 'debug' in globals() and debug > 0:
                        print "%s not in skiplist" % arec[0][x]
                    skiplist.append(arec[0][x])
        if 'debug' in globals() and debug > 0:
            print "%"*40
        return ownerName,areclist,ptrlist,ptrzonelist,skiplist,missinglist
    
    def ptr_to_a(self,ownerName):
        """Method to take a pointer record, get a list of the
        hosts it points to, and if we host the domain for the
        host, check and see if there are matching A records 
        for the PTR.  Returns ownerName,checkip,areclist,arecip
        where ownerName is the PTR record being checked,
        checkip is the IP address of the PTR record,
        areclist is a list of hostnames the IP points to,
        arecip is a dictionary of IP addresses the hostname
        resolves to, and skiplist is a list of domains we skipped
        as we don't host them.
        """
        areclist = []
        arecip = {}
        ptrlist = []
        skiplist = []
        missinglist = []
        q4,q3,q2,q1,ignore = ownerName.split(".",4)
        checkip = ".".join([q1,q2,q3,q4])
        if 'debug' in globals() and debug > 0:
            print "%"*40
        if 'debug' in globals() and debug > 0:
            print "in ptr_to_a with ownerName = %s and checkip = %s" % (ownerName,checkip)
        for x in range(len(self.rr_ptr[ownerName][0])):
            if 'debug' in globals() and debug > 0:
                print "processing %d (%s) " % (x,self.rr_ptr[ownerName][0][x])
            if self.rr_ptr[ownerName][0][x] not in areclist:
                if 'debug' in globals() and debug > 0:
                    print "[%d] append %s" % (x,self.rr_ptr[ownerName][0][x])
                areclist.append(self.rr_ptr[ownerName][0][x])
        for arec in areclist:
            arecdomain = arec.rsplit(".",3)[1]+"."+arec.rsplit(".",3)[2]+"."
            if 'debug' in globals() and debug > 0:
                print "arec = %s arecdomain = %s" % (arec,arecdomain)
            if arecdomain in self.parent.zone.keys():
                if 'debug' in globals() and debug > 0:
                    print "arecdomain [%s] in self.parent.zone.keys" % arecdomain
                if arec in self.parent.zone[arecdomain].rr_a.keys():
                    arecip[arec] = self.parent.zone[arecdomain].rr_a[arec][0]
                    if 'debug' in globals() and debug > 0:
                        print "%s in domain %s a.keys()" % (arec,arecdomain)
                        print "IP = %s" % arecip[arec]
                elif arec in self.parent.zone[arecdomain].rr_cname.keys():
                    if 'debug' in globals() and debug > 0:
                        print "%s in domain %s cname.keys()" % (arec,arecdomain)
                    arecdomain2 = self.parent.zone[arecdomain].rr_cname[arec][0][0].rsplit(".",3)[1]+"."+\
                                  self.parent.zone[arecdomain].rr_cname[arec][0][0].rsplit(".",3)[2]+"."
                    if 'debug' in globals() and debug > 0:
                        print "arecdomain2 = %s" % arecdomain2
                    if arecdomain2 in self.parent.zone.keys():
                        if 'debug' in globals() and debug > 0:
                            print "%s is one of our domains - checking it " % arecdomain2
                        arecip[arec] = self.parent.zone[arecdomain2].rr_a[self.parent.zone[arecdomain].rr_cname[arec][0][0]][0][0]
                        if 'debug' in globals() and debug > 0:
                            print "arecip = %s" % arecip[arec]
                    else:
                        if 'debug' in globals() and debug > 0:
                            print "%s is not one of our zones - storing hostname %s instead of ip" % \
                                   (arecdomain2,self.parent.zone[arecdomain].rr_cname[arec][0][0])
                        arecip[arec] = self.parent.zone[arecdomain].rr_cname[arec][0][0]
                else:
                    if 'debug' in globals() and debug > 0:
                        print "[%s] not found in fwd dns" % arec
                    if arec not in missinglist:
                        if 'debug' in globals() and debug > 0:
                            print "%s not in missinglist" % arec
                        missinglist.append(arec)
            else:
                if 'debug' in globals() and debug > 0:
                    print "Forward zone %s not in ultraDNS - skipping %s" % (arecdomain,arec)
                if arec not in skiplist:
                    if 'debug' in globals() and debug > 0:
                        print "%s not in skiplist" % arec
                    skiplist.append(arec)
        if 'debug' in globals() and debug > 0:
            print "%"*40
        return ownerName,checkip,areclist,arecip,skiplist,missinglist
    
    def a_rec_in_ptr(self,ownerName):
        """Method to see if each address associated
        with a hostname has a matching reverse DNS
        record.  Returns matched, missing, and skipped
        where each is a list of IP's and list of PTR zones
        that either had a match, did not have a match, 
        or were skipped.
        """
        if 'debug' in globals() and debug > 0:
            print "in a_rec_in_ptr with [%s]" % ownerName
        aownerName,aareclist,aptrlist,aptrzonelist,askiplist,amissinglist = self.a_to_ptr(ownerName)
        if 'debug' in globals() and debug > 0:
            print "aownerName: %s" % aownerName
            print "aareclist: %s" % str(aareclist)
            print "aptrlist: %s" % str(aptrlist)
            print "aptrzonelist; %s" % str(aptrzonelist)
            print "askiplist: %s" % str(askiplist)
            print "amissinglist; %s" % str(amissinglist)
            print "******************************************************"
        matched = []
        missing = list(amissinglist)
        skipped = []
        for arec in aareclist:
            if 'debug' in globals() and debug > 0:
                print "processing %s in aareclist" % arec
            if arec in askiplist:
                if 'debug' in globals() and debug > 0:
                    print "%s in askiplist" % arec
                if arec not in skipped:
                    if 'debug' in globals() and debug > 0:
                        print "%s not in skipped" % arec
                    skipped.append(arec)
            elif arec in aptrlist.keys() and ownerName in aptrlist[arec]:
                if 'debug' in globals() and debug > 0:
                    print "%s found in aptrlist.keys()" % arec
                if arec not in matched:
                    if 'debug' in globals() and debug > 0:
                        print "%s not in matched" % arec
                    matched.append(arec)
            else:
                if 'debug' in globals() and debug > 0:
                    print "%s missing" % arec
                if arec not in missing:
                    if 'debug' in globals() and debug > 0:
                        print "%s not in missing" % arec
                    missing.append(arec)
        return ownerName,aareclist,aptrzonelist,matched,missing,skipped 
    
    def ptr_rec_in_a(self,ownerName):
        """Method to see if each hostname associated
        with a PTR record has a matching A record.  Returns
        matched, missing and skipped where each is a list of
        hostnames that were found, not found, or skipped.
        """
        if 'debug' in globals() and debug > 0:
            print "*"*40
        if 'debug' in globals() and debug > 0:
            print "in ptr_rec_in_a with [%s]" % ownerName
        pownerName,pcheckip,pareclist,parecip,pskiplist,pmissinglist = self.ptr_to_a(ownerName)
        if 'debug' in globals() and debug > 0:
            print "pownerName: %s" % pownerName
            print "pcheckip: %s" % pcheckip
            print "pareclist: %s" % str(pareclist)
            print "parecip: %s" % str(parecip)
            print "pskiplist: %s" % str(pskiplist)
            print "pmissinglist; %s" % str(pmissinglist)
            print "*"*40
        matched = []
        missing = list(pmissinglist)
        skipped = []
        for arec in pareclist:
            if 'debug' in globals() and debug > 0:
                print "processing %s in pareclist" % arec
            if arec in pskiplist:
                if 'debug' in globals() and debug > 0:
                    print "%s in pskiplist" % arec
                if arec not in skipped:
                    if 'debug' in globals() and debug > 0:
                        print "%s not in skipped" % arec
                    skipped.append(arec)
            elif arec in parecip.keys() and pcheckip in parecip[arec]:
                if 'debug' in globals() and debug > 0:
                    print "%s in parecip.keys and pcheckip in parecip" % arec
                if arec not in matched:
                    if 'debug' in globals() and debug > 0:
                        print "%s not in matched" % arec
                    matched.append(arec)
            else:
                if 'debug' in globals() and debug > 0:
                    print "adding %s to missing" % arec
                if arec not in missing:
                    if 'debug' in globals() and debug > 0:
                        print "%s not in missing" % arec
                    missing.append(arec)
        return ownerName,pcheckip,pareclist,matched,missing,skipped
    
    def check_fwd_zone(self):
        """Method to accept a forward zone name
        and work through the A records
        checking them against PTR records.
        Returns a dictionary keyed on the 
        hostname containing the IP addresses, 
        PTR zones, matched, missing 
        and skipped lists (see a_rec_in_ptr or
        ptr_rec_in_a)
        """
        results = {}
        results['ptrzones'] = []
        for hostname in self.rr_a.keys():
            ownerName,aareclist,aptrzonelist,matched,missing,skipped = self.a_rec_in_ptr(hostname)
            for x in aptrzonelist:
                if x in results['ptrzones']:
                    pass
                else:
                    results['ptrzones'].append(x)
            results[ownerName] = { 'addresslist': aareclist,
                                   'matched': matched,
                                   'missing': missing,
                                   'skipped': skipped}
        return results
    
    def check_rev_zone(self):
        """Method to accept the reverse zone name 
        for a /24 subnet and work through the 
        PTR records checking them against A records.
        Returns a dictionary keyed on the IP address 
        containing the matched, missing and skipped 
        lists (see a_rec_in_ptr or ptr_rec_in_a).
        """
        results = {}
        if 'debug' in globals() and debug > 0:
            print "="*40
        for ptrrec in self.rr_ptr.keys():
            if 'debug' in globals() and debug > 0:
                print "="*40
            ownerName,pcheckip,pareclist,matched,missing,skipped = self.ptr_rec_in_a(ptrrec)
            results[pcheckip] = { 'ptr': ownerName,
                                  'hostlist': pareclist,
                                  'matched': matched,
                                  'missing': missing,
                                  'skipped': skipped}
            if 'debug' in globals() and debug > 0:
                print "="*40
        return results

class SSL_Labs(object):
    """Primary class for interfacing with SSLLabs.
    Future versions will integrate the classes defined below
    instead of using standalone definitions and methods.
    """
    def __init__(self):
        self.engineVersion = ''
        self.criteriaVersion = ''
        self.maxAssessments = 0
        self.currentAssessments = 0
        self.newAssessmentCoolOff = 0
        self.messages = []
        self.baseURL='https://api.ssllabs.com/api/v2/'
        
    def get_info(self):
        """Method to check and see of SSLLabs is available
        """
        headers = {'content-type': 'application/json'}
        url=self.baseURL+'info'
        payload={
        }
        r = requests.get(url, headers=headers, params=payload)
        if r.status_code == 200:
            results=r.json()
        else:
            results = r
        if 'debug' in globals() and debug > 0:
            pprint.pprint(results)
            pprint.pprint(r.headers)
        if r.status_code == 200:
            self.engineVersion = str(results['engineVersion'])
            self.criteriaVersion = str(results['criteriaVersion'])
            self.maxAssessments = int(results['maxAssessments'])
            self.currentAssessments = int(results['currentAssessments'])
            self.messages = copy.deepcopy(results['messages']) # []string
            self.newAssessmentCoolOff = int(results['newAssessmentCoolOff'])
            if self.newAssessmentCoolOff > 0:
                if 'debug' in globals() and debug > 0:
                    print "newAssessmentCoolOff > 0: %d - sleeping" % self.newAssessmentCoolOff
                time.sleep(int(self.newAssessmentCoolOff/1000))
                time.sleep(1)
        return r,results
    
    def print_info(self):
        print "engineVersion: %s" % self.engineVersion
        print "criteriaVersion: %s" % self.criteriaVersion
        print "currentAssessments: %d" % self.currentAssessments
        print "maxAssessments: %d" % self.maxAssessments
        print "messages: %s" % self.messages
        print 'newAssessmentCoolOff: %d' % self.newAssessmentCoolOff
    
    def analyze_host(self,host,publish='off',startNew='on',fromCache='off',\
                maxAge=0,all='done',ignoreMismatch='on'):
        headers = {'content-type': 'application/json'}
        url=self.baseURL+'analyze'
        payload={'host': host,'publish': publish, 'startNew': startNew,\
                 'fromCache': fromCache, 'maxAge': maxAge, 'all': all,\
                 'ignoreMismatch': ignoreMismatch
        }
        r = requests.get(url, headers=headers, params=payload)
        if r.status_code == 200:
            results=r.json()
        else:
            results = r
        if 'debug' in globals() and debug > 0:
            pprint.pprint(results)
            pprint.pprint(r.headers)
        if r.status_code == 200:
            if 'debug' in globals() and debug > 0:
                print "status code 200"
            return r,results
        return r,results
    
    def check_status(self,host,publish='off',startNew='off',fromCache='on',\
                maxAge=24,all='done',ignoreMismatch='on'):
        headers = {'content-type': 'application/json'}
        url=self.baseURL+'analyze'
        payload={'host': host,'publish': publish, 'startNew': startNew,\
                 'fromCache': fromCache, 'maxAge': maxAge, 'all': all,\
                 'ignoreMismatch': ignoreMismatch
        }
        grades = {}
        r = requests.get(url, headers=headers, params=payload)
        if r.status_code == 200:
            results=r.json()
        else:
            results = r
        if 'debug' in globals() and debug > 0:
            pprint.pprint(results)
            pprint.pprint(r.headers)
        return r,results
    
    def getEndpointData(self,host,s,fromCache='on'):
        pass
    
    def getStatusCodes(self):
        pass

class LabsSuite(object):
    """For future integration.
    """
    def __init__(self):
        self.id = 0
        self.name = ''
        self.cipherStrength = 0
        self.dhStrength = 0
        self.dhP = 0
        self.dhG = 0
        self.dhYs = 0
        self.ecdhBits = 0
        self.ecdhStrength = 0
        self.q = None

class LabsSuites(object):
    """For future integration
    """
    def __init__(self):
        self.list = []
        self.preference = None

class LabsEndpoint(object):
    """For future integration.
    """
    def __init__(self):
        self.ipAddress = ''
        self.serverName = ''
        self.statusMessage = ''
        self.statusDetails = ''
        self.statusDetailsMessage = ''
        self.grade = ''
        self.gradeTrustIgnored = ''
        self.hasWarnings = False
        self.isExceptional = False
        self.progress = -1
        self.duration = 0
        self.eta = 0
        self.delegation = 0
        self.details = None

class LabsReport(object):
    """For future integration.
    """
    def __init__(self):
        self.host = ''
        self.port = 0
        self.protocol = ''
        self.isPublic = False
        self.status = ''
        self.statusMessage = ''
        self.startTime = 0
        self.testTime = 0
        self.engineVersion = ''
        self.criteriaVersion = ''
        self.cacheExpiryTime = 0
        self.endpoints = {}
        self.rawJSON = ''

class LabsEndpointDetails(object):
    """For future integration.
    """
    def __init__(self):
        self.hostStartTime = 0
        self.key = None # LabsKey object
        self.cert = None # LabsCert object
        self.chain = None # LabsChain object
        self.protocols = []
        self.suites = None # LabsSuites object
        self.serverSignature = ''
        self.prefixDelegation = False
        self.nonPrefixDelegation = False
        self.vulnBeast = False
        self.renegSupport = 0
        self.stsResponseHeader = ''
        self.stsMaxAge = 0
        self.stsSubdomains = None
        self.pkpResponseHeader = ''
        self.sessionResumption = 0
        self.compressionMethods = 0
        self.supportsNpn = False
        self.npnProtocols = ''
        self.sessionTickets = 0
        self.ocspStapling = False
        self.staplingRevocationStatus = 0
        self.sniRequired = False
        self.httpStatusCode = 0
        self.httpForwarding = ''
        self.supportsRc4 = False
        self.forwardSecrecy = 0
        self.rc4WithModern = False
        self.sims = None #LabsSimDetails
        self.heartbleed = False
        self.heartbeat = False
        self.openSslCcs = 0
        self.poodle = False
        self.poodleTls = 0
        self.fallbackScsv = False
        self.freak = False
        self.hasSct = 0
        self.dhPrimes = []
        self.dhUsesKnownPrimes = 0
        self.dhYsReuse = False
        self.logjam = False

class LabsKey(object):
    """For future integration.
    """
    def __init__(self):
        self.size = 0
        self.strength = 0
        self.alg = ''
        self.debianFlaw = False
        self.q = None

class LabsHost(object):
    """For future integration.  Host object.
    """
    def __init__(self,host):
        self.host = ''
        self.port = 0
        self.protocol = ''
        self.isPublic = False
        self.status = ''
        self.statusMessage = ''
        self.startTime = 0
        self.testTime = 0
        self.engineVersion = ''
        self.criteriaVersion = ''
        self.cacheExpiryTime = ''
        self.endpoints = []
        self.certHostnames = []

class LabsCert(object):
    """For future integration.
    """
    def __init__(self):
        self.subject = ''
        self.commonNames = []
        self.altNames = []
        self.notBefore = 0
        self.notAfter = 0
        self.issuerSubject = ''
        self.sigAlg = ''
        self.issuerLabel = ''
        self.revocationInfo = 0
        self.crlURIs = []
        self.ocspURIs = []
        self.revocationStatus = 0
        self.crlRevocationStatus = 0
        self.ocspRevocationStatus = 0
        self.sgc = 0
        self.validationType = ''
        self.issues = 0
        self.sct = False

class LabsChainCert(object):
    """For future integration.
    """
    def __init__(self):
        self.subject = ''
        self.label = ''
        self.notBefore = 0
        self.notAfter = 0
        self.issuerSubject = ''
        self.issuerLabel = ''
        self.sigAlg = ''
        self.issues = 0
        self.keyAlg = ''
        self.keySize = 0
        self.keyStrength = 0
        self.revocationStatus = 0
        self.crlRevocationStatus = 0
        self.ocspRevocationStatus = 0
        self.raw = ''

class LabsChain(object):
    """For future integration.
    """
    def __init__(self):
        self.certs = [] # []LabsChainCert
        self.issues = 0

class LabsProtocol(object):
    """For future integration.
    """
    def __init__(self):
        self.id = 0x0
        self.name = ''
        self.version = ''
        self.v2SuitesDisabled = False
        self.q = None

class LabsSimClient(object):
    """For future integration.
    """
    def __init__(self):
        self.id = 0
        self.name = ''
        self.platform = ''
        self.version = ''
        self.isReference = False

class LabsSimulation(object):
    """For future integration.
    """
    def __init__(self):
        self.client = None # LabsSimClient
        self.errorCode = 0
        self.attempts = 0
        self.protocolId = 0
        self.suiteId = 0

class LabsSimDetails(object):
    """For future integration.
    """
    def __init__(self):
        self.results = [] # []LabsSimulation

class LabsStatusCodes(object):
    """For future integration
    """
    def __init__(self):
        self.statusDetails = {}
        
class LabsInfo(object):
    """For future integration
    """
    def __init__(self):
        self.version = ''
        self.criteriaVersion = ''
        self.maxAssessments = 0
        self.currentAssessments = 0
        self.newAssessmentCoolOff = 0
        self.messages = []

def main():
    """Main entry point to host the command line parser and
    call the necessary method to perform the scans etc.
    """
    parser = argparse.ArgumentParser(description=\
             'SSL Labs scan of all UltraDNS A record hosts with tcp/443 enabled')
    
    metavar='{scan'
    #metavar = metavar + ',shell' # uncomment to enable clean python -i shell access
    metavar = metavar + '}'
    subparsers = parser.add_subparsers(metavar=metavar)
    
    scan_parser = subparsers.add_parser('scan',\
                    help = 'Scan for ssl and upload results')
    scan_parser.set_defaults(func=cmd_scan_and_upload)
    scan_parser.add_argument('-debug', action='store', type = int, default=0,\
                    dest='debug', help='Debug level 0-9')
    scan_parser.add_argument('-i', action='store_true', default = False,\
                    dest='askpass', help='Prompt for credentials to use and store')
    
    cl = {}
    results = {}
    args = {}
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

