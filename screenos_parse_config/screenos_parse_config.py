#!/usr/bin/env python
#

import base64
import os
import pprint
import readline

import argparse

class Address(object):
    """
    Class to contain address definitions
    for hosts or subnets
    """
    def __init__(self,addrname,zone,mapto=''):
        if 'debug' in globals() and debug > 1:
            print "init address %s" % addrname
        self.name = str(addrname)
        self.zone = zone
        self.mapto = str(mapto)
        self.addr = {}
        self.comment = ''
        self.duplicates = {}
        self.duplicates['count'] = 0
        self.group = False
        return
    
    def add_addr(self,addr,zone):
        """
        Method to add an IP address to an address object
        """
        if 'debug' in globals() and debug > 0:
            print "in add_addr %s" % addr
        if addr in self.addr.keys():
            self.duplicates['count'] += 1
            self.duplicates[self.duplicates['count']] = "["+zone.zonename+":"+self.name+"] "+addr
        self.addr[addr] = str(addr)
        return
    
    def print_duplicatelist(self):
        """
        Method to print out a list of duplicates found during adds
        """
        if self.duplicates['count'] > 0:
            print "%0d duplicates found for [%s:%s]" % (self.duplicates['count'],self.zone.zonename,self.name)
            for num in sorted(self.duplicates.keys()):
                if type(num) is int:
                    print "    %0d: %s" % (num,self.duplicates[num])
        return
    
    def add_comment(self,comment):
        """
        Method to add a comment to an address object
        """
        if 'debug' in globals() and debug > 0:
            print "in add_comment %s" % comment
        self.comment = str(comment)
        return
    
    def print_address(self,spaces=0,negated=False):
        """
        method to print out the address with specified indentation
        """
        if spaces > 0:
            print " "*(spaces-1),
        if negated:
            for addr in sorted(self.addr.keys()):
                if len(self.mapto) > 0:
                    print "*NOT* [%s:%s]: %s -> %s *NOT*" % (self.zone.zonename,
                                                           self.name,
                                                           self.addr[addr],
                                                           self.mapto)
                else:
                    print "*NOT* [%s:%s]: %s *NOT*" % (self.zone.zonename,self.name,self.addr[addr])
        else:
            for addr in sorted(self.addr.keys()):
                if len(self.mapto) > 0:
                    print "[%s:%s]: %s -> %s" % (self.zone.zonename,
                                               self.name,
                                               self.addr[addr],
                                               self.mapto)
                else:
                    print "[%s:%s]: %s" % (self.zone.zonename,self.name,self.addr[addr])
        return
    
    def print_comment(self,spaces=0,negated=False):
        """
        Method to print out the comment line
        """
        if spaces > 0:
            print " "*(spaces-1),
        print "%s" % self.comment
        return

class AddressGroup(object):
    """
    Class to contain groups of addresses
    """
    def __init__(self,groupname,zone):
        if 'debug' in globals() and debug > 1:
            print "in init group %s" % groupname
        self.name = str(groupname)
        self.zone = zone
        self.addr = {}
        self.mapto = ''
        self.comment = ''
        self.duplicates = {}
        self.duplicates['count'] = 0
        self.group = True
        
    def add_addr(self,addrname,addr):
        """
        Method to add an address to the address group
        """
        if addr in self.addr.keys():
            self.duplicates['count'] += 1
            self.duplicates[self.duplicates['count']] = "["+zone.zonename+":"+self.name+"] "+addr
        if str(addrname) not in self.addr.keys():
            self.addr[str(addrname)] = addr
        return
    
    def add_comment(self,comment):
        """
        Method to add a comment to the address group
        """
        self.comment = str(comment)
        return
    
    def print_address(self,spaces=0,negated=False):
        """
        Method to print out the addresses in the address group
        """
        if spaces > 0:
            print " "*(spaces-1),
        if negated:
            print "*NOT* Address group: [%s:%s] *NOT*" % (zelf.zone.zonename,self.name)
        else:
            print "Address group: [%s:%s]" % (self.zone.zonename,self.name)
        for address in sorted(self.addr.keys()):
            self.addr[address].print_address(spaces+2)
        return
    
    def print_duplicatelist(self):
        """
        Method to print out a list of duplicates found during adds
        """
        if self.duplicates['count'] > 0:
            print "%0d duplicates found for [%s:%s]" % (self.duplicates['count'],self.zone.zonename,self.name)
            for num in sorted(self.duplicates.keys()):
                if type(num) is int:
                    print "    %0d: %s" % (num,self.duplicates[num])
        return

class Zone(object):
    """
    Class to contain zone definitions and group
    different objects which are included in the
    zone
    """
    def __init__(self,zonename):
        if 'debug' in globals() and debug > 1:
            print "init zone %s" % zonename
        self.zonename = str(zonename).replace("\"","")
        self.addresses = {}
        self.duplicates = {}
        return
    
    def __len__(self):
        '''Method to let me check for zone
        '''
        return 1
    
    def add_address(self,address):
        """
        Method to add an address to the zone object
        """
        if 'debug' in globals() and debug > 0:
            print "in add address %s to zone" % address.name
        if address.name not in self.addresses.keys():
            self.addresses[str(address.name)] = address
            if 'debug' in globals() and debug > 0:
                print "added address entry"
        else:
            if 'debug' in globals() and debug > 0:
                print "address existed - ignoring add"
        return
    
    def add_address_group(self,address_group):
        """
        Method to add an address_group to the zone object
        """
        if 'debug' in globals() and debug > 0:
            print "in add address_group %s" % address_group.groupname
        if address_group.groupname not in self.addresses.keys():
            self.addresses[str(address_group.groupname)] = address_group
            if 'debug' in globals() and debug > 0:
                print "added address_group"
        else:
            if 'debug' in globals() and debug > 0:
                print "address group found - ignoring add"
        return

class Service(object):
    """
    Class to contain a network service.
    Only applies to tcp, udp or icmp, and rpc = 0 as well as all = 0
    """
    def __init__(self,servicename,protonum=0,ssfrom=0,ssto=0,sdfrom=0,sdto=0):
        if 'debug' in globals() and debug > 1:
            print "in init service %s" % servicename
        self.name = str(servicename)
        self.protonum = int(protonum)
        self.ssfrom = int(ssfrom)
        self.ssto = int(ssto)
        self.sdfrom = int(sdfrom)
        self.sdto = int(sdto)
        self.group = False
        self.protocols = {}
        self.protocols[0] = "RPC/ANY"
        self.protocols[1] = "ICMP"
        self.protocols[6] = "TCP"
        self.protocols[17] = "UDP"
        self.protocols[47] = "GRE"
        self.protocols[89] = "OSPF"
        self.protocols[132] = "SCTP"
        return
    
    def print_service(self,spaces=0,negated=False):
        if spaces > 0:
            print " "*(spaces-1),
        if negated:
            print "*NOT* [%s]" % self.name,
        else:
            print "[%s]" % self.name,
        if self.protonum in self.protocols.keys():
            protoname = self.protocols[self.protonum]
        else:
            protoname = ''
        print "%s[%d]" % (protoname,self.protonum),
        if self.sdfrom != self.sdto:
            if negated:
                print "ports %d-%d *NOT*" % (self.sdfrom,self.sdto)
            else:
                print "ports %d-%d" % (self.sdfrom,self.sdto)
        else:
            if negated:
                print "port %d *NOT*" % (self.sdfrom)
            else:
                print "port %d" % (self.sdfrom)
        return

class ServiceGroup(object):
    """
    Class to group services together
    """
    def __init__(self,groupname,parent):
        if 'debug' in globals() and debug > 1:
            print "in init service group %s" % groupname
        self.name = str(groupname)
        self.services = {}
        self.comment = ''
        self.group = True
        self.parent = parent
        return
    
    def add_service(self,service):
        """
        method to add a service to the group object
        """
        if str(service.name) not in self.services.keys():
            self.services[str(service.name)] = service
        else:
            if 'debug' in globals() and debug > 0:
                print 'service already there - skipping add'
        return
    
    def print_service(self,spaces=0,negated=False):
        if spaces > 0:
            print " "*(spaces-1),
        if negated:
            print "*NOT* Service group: [%s] *NOT*" % self.name
        else:
            print "Service group: [%s]" % self.name
        for services in sorted(self.services.keys()):
            self.services[services].print_service(spaces+2)
        return

class PolicyItem(object):
    """
    Object to contain a policy rule
    """
    def __init__(self,policynum,parent):
        if 'debug' in globals() and debug > 1:
            print "in init policyItem %d" % policynum
        self.number = int(policynum)
        self.name = ''
        self.from_zone = ''
        self.to_zone = ''
        self.order = 0
        self.srcaddr = {}
        self.srcsvc  = {}
        self.dstaddr = {}
        self.dstsvc  = {}
        self.action  = 'deny'
        self.log = False
        self.interface = ''
        self.vpn = ''
        self.disabled = False
        self.parent = parent
        return
    
    def set_from_zone(self,from_zone):
        self.from_zone = from_zone
        return
    
    def set_to_zone(self,to_zone):
        self.to_zone = to_zone
        return
    
    def set_order(self,order):
        self.order = int(order)
        return
    
    def set_disabled(self,disabled):
        self.disabled = disabled
        return
    
    def set_name(self,name):
        self.name = str(name)
        return
    
    def set_action(self,action):
        self.action = str(action)
        return
        
    def set_log(self,log):
        self.log = log
        return
    
    def set_interface(self,interface):
        self.interface = interface
        return
        
    def set_vpn(self,vpn):
        self.vpn = vpn
        return
    
    def add_src(self,srcaddrname,srcaddr,negated=False):
        if 'debug' in globals() and debug > 0:
            print "in add_src with %s" % srcaddrname
            if srcaddrname.find('MIP') >= 0:
                print "Found MIP in the name at %d" % srcaddrname.find('MIP')
            if srcaddrname.find('VIP') >= 0:
                print "Found VIP in the name at %d" % srcaddrname.find('VIP')
        if srcaddrname.find('MIP(') == 0:
            self.parent.add_mip_policy_item(srcaddrname,self.number,'src')
        if srcaddrname.find('VIP(') == 0:
            self.parent.add_vip_policy_item(srcaddrname,self.number,'src')
        if srcaddrname not in self.srcaddr.keys():
            self.srcaddr[srcaddrname] = {}
            self.srcaddr[srcaddrname]['src'] = srcaddr
            self.srcaddr[srcaddrname]['negated'] = negated 
        else:
            if 'debug' in globals() and debug > 0:
                print "source address %s already in policy - ignoring" % srcaddrname
        return
    
    def add_src_svc(self,srcsvcname,srcsvc,negated=False):
        if srcsvcname not in self.srcsvc.keys():
            self.srcsvc[srcsvcname] = {}
            self.srcsvc[srcsvcname]['svc'] = srcsvc
            self.srcsvc[srcsvcname]['negated'] = negated 
        else:
            if 'debug' in globals() and debug > 0:
                print "source service %s already in policy - ignoring" % srcsvcname
        return
    
    def add_dst(self,dstaddrname,dstaddr,negated=False):
        if 'debug' in globals() and debug > 0:
            print "in add_dst with %s" % dstaddrname
            if dstaddrname.find('MIP') >= 0:
                print "Found MIP in the name at %d" % dstaddrname.find('MIP')
            if dstaddrname.find('VIP') >= 0:
                print "Found VIP in the name at %d" % dstaddrname.find('VIP')
        if dstaddrname.find('MIP(') == 0:
            self.parent.add_mip_policy_item(dstaddrname,self.number,'dst')
        if dstaddrname.find('VIP(') == 0:
            self.parent.add_vip_policy_item(dstaddrname,self.number,'dst')
        if dstaddrname not in self.dstaddr.keys():
            self.dstaddr[dstaddrname] = {}
            self.dstaddr[dstaddrname]['dst'] = dstaddr
            self.dstaddr[dstaddrname]['negated'] = negated 
        else:
            if 'debug' in globals() and debug > 0:
                print "destination address %s already in policy - ignoring" % dstaddrname
        return
    
    def add_dst_svc(self,dstsvcname,dstsvc,negated=False):
        if dstsvcname not in self.dstsvc.keys():
            self.dstsvc[dstsvcname] = {}
            self.dstsvc[dstsvcname]['svc'] = dstsvc
            self.dstsvc[dstsvcname]['negated'] = negated
        else:
            if 'debug' in globals() and debug > 0:
                print "destination service %s already in policy - ignoring" % dstsvcname
        return
    
    def print_item(self,spaces=0):
        if spaces > 0:
            print " "*(spaces-1),
        print "\nPolicy ID [%02d] " % self.number,
        if len(self.name) > 0:
            print " (%s) " % self.name,
        if self.disabled:
            print " <disabled>"
        else:
            print
        if spaces > 0:
            print " "*(spaces-1),
        print "From:"
        for addr in sorted(self.srcaddr.keys()):
            if self.srcaddr[addr]['negated']:
                self.srcaddr[addr]['src'].print_address(spaces+4,True)
            else:
                self.srcaddr[addr]['src'].print_address(spaces+4)
        if spaces > 0:
            print " "*(spaces-1),
        print "To:"
        for addr in sorted(self.dstaddr.keys()):
            if self.dstaddr[addr]['negated']:
                self.dstaddr[addr]['dst'].print_address(spaces+4,True)
            else:
                self.dstaddr[addr]['dst'].print_address(spaces+4)
        if spaces > 0:
            print " "*(spaces-1),
        print "Services:"
        for service in sorted(self.dstsvc.keys()):
            if self.dstsvc[service]['negated']:
                self.dstsvc[service]['svc'].print_service(spaces+4,True)
            else:
                self.dstsvc[service]['svc'].print_service(spaces+4)
        if spaces > 0:
            print " "*(spaces-1),
        print "Action:  %s" % self.action,
        if self.log:
            print " [Log]"
        else:
            print
        return

class PolicySet(object):
    """
    Class to contain a policy set 
    of rules for one zone to another
    """
    def __init__(self,from_zone,to_zone,parent):
        self.name = str(from_zone.zonename)+' to '+str(to_zone.zonename)
        if 'debug' in globals() and debug > 1:
            print "in init policy set %s" % self.name
        self.rule = {}
        self.parent = parent
        return
    
    def add_rule(self,policyItem):
        """
        Method to add a rule in the correct
        order to the policy set based on the
        order discovered in the config file
        """
        if int(policyItem.order) not in self.rule.keys():
            self.rule[int(policyItem.order)] = policyItem
        else:
            print "Error: order [%d] rule [%d] already exists - ignoring"
        return
    
    def print_policy_set(self,spaces=0):
        print "-"*50
        if spaces > 0:
            print " "*(spaces-1),
        print "Policy Set %s:" % self.name
        for rulenum in sorted(self.rule.keys()):
            if spaces > 0:
                print " "*(spaces-1),
            if 'debug' in globals() and debug > 0:
                print "processing [%d] policy %d\n" % (rulenum,self.rule[rulenum].number)
            self.rule[rulenum].print_item(spaces+2)
        print "-"*50
        return
    
class NetScreen(object):
    """
    Class to parse and analyze NetScreen
    configuration files.
    """
    def __init__(self,filename=''):
        """
        Method to initalize the various dictionaries
        needed to map out the firewall objects and rules.
        """
        if 'debug' in globals() and debug > 1:
            print "*"*50
            print "init netScreen(%s)" % filename
            print "*"*50
        self.prev = -1
        self.curr = 0
        self.open = False
        self.zones = {}
        self.interfaces = {}
        self.addresses = {}
        self.policies = {}
        self.policy_discover_order = {}
        self.policySets = {}
        self.services = {}
        self.protocols = {}
        self.protocols[0] = "RPC/ANY"
        self.protocols[1] = "ICMP"
        self.protocols[6] = "TCP"
        self.protocols[17] = "UDP"
        self.protocols[47] = "GRE"
        self.protocols[58] = "ICMP6"
        self.protocols[89] = "OSPF"
        self.protocols[132] = "SCTP"
        self.found_service = False
        self.found_group_service = False
        self.found_address = False
        self.found_group_address = False
        self.found_zone = False
        self.found_interface = False
        self.found_policy = False
        self.mips = {}
        self.mipstarget = {}
        self.mipsintf = {}
        self.vips = {}
        self.vipstarget = {}
        self.vipsintf = {}
        self.vipssrc = {}
        self.vipsdst = {}
        self.dips = {}
        self.dipsdef = {}
        self.dipsintf = {}
        
        self._init_any()
        if 'debug' in globals() and debug > 0:
            print "Calling load_predefined"
        self._load_predefined()
        if 'debug' in globals() and debug > 0:
            print "return from predefined - next to input config file"
        while len(filename) < 1:
            filename = raw_input('File name:')
        if os.path.exists(filename):
            self.filename = str(filename)
        else:
            raise IOError('File '+filename+' not found')
        self._find_sections(filename)
        if self.found_service:
            self.parse_service_block()
        if self.found_zone:
            self.parse_zone_block()
        if self.found_interface:
            self.parse_interface_block()
        if self.found_address:
            self.parse_address_block()
        if self.found_group_address:
            self.parse_address_group_block()
        if self.found_group_service:
            self.parse_service_group_block()
        if self.found_policy:
            self.parse_policies()
            self.parse_policy_sets()
        return
    
    def add_mip(self,mipname,target,intf):
        """
        Method to add a dictionary of the MIP's and where they are used
        """
        self.mips[mipname] = {}
        self.mipstarget[mipname] = str(target)
        self.mipsintf[mipname] = str(intf)
        return
    
    def add_vip(self,vipname,srcport,dstport,target,intf):
        """
        Method to add a dictionary of the VIP's and where they are used
        """
        self.vips[vipname] = {}
        self.vipstarget[vipname] = str(target)
        self.vipsintf[vipname] = str(intf)
        self.vipssrc[vipname] = str(srcport)
        self.vipsdst[vipname] = str(dstport)
        return
    
    def add_dip(self,dipnum,dipdef,intf):
        """
        Method to add a dictionary of the DIP's and where they are used
        """
        self.dips[dipnum] = {}
        self.dipsdef[dipnum] = str(dipdef)
        self.dipsintf[dipnum] = str(intf)
        return
    
    def add_mip_policy_item(self,mipname,item,srcdst):
        """
        Method to add a policy item to the mip dictionary
        """
        self.mips[mipname][int(item)] = srcdst+"/Policy ID "+str(item)
        return
    
    def add_vip_policy_item(self,vipname,item,srcdst):
        """
        Method to add a policy item to the vip dictionary
        """
        self.vips[vipname][int(item)] = srcdst+"/Policy ID "+str(item)
        return
    
    def add_zone(self,zonename):
        """
        Method to add a zone to the dictionary
        """
        zonename = zonename.replace("\"","")
        if zonename in self.zones.keys():
            if 'debug' in globals() and debug > 0:
                print "Zone %s eady exists - ignoring add" % zonename
        else:
            if 'debug' in globals() and debug > 0:
                print "Adding Zone %s" % zonename
            self.zones[zonename] = Zone(zonename)
        return
    
    def _find_sections(self,filename):
        if 'debug' in globals() and debug > 0:
            print "Checking contents of %s for sections" % filename
        self._open_infile()
        while self.prev < self.curr:
            inrec = self.infile.readline().strip()
            self.prev = int(self.curr)
            self.curr = self.infile.tell()
            if len(inrec) > 0:
                if inrec.find('set service ') >= 0:
                    if 'debug' in globals() and debug > 1:
                        print "found service in [%s]" % inrec
                    self.found_service = True
                elif inrec.find('set group service ') >= 0:
                    if 'debug' in globals() and debug > 1:
                        print "found group service in [%s]" % inrec
                    self.found_group_service = True
                elif inrec.find('set address ') >= 0:
                    if 'debug' in globals() and debug > 1:
                        print "found address in [%s]" % inrec
                    self.found_address = True
                elif inrec.find('set group address ') >= 0:
                    if 'debug' in globals() and debug > 1:
                        print "found group address in [%s]" % inrec
                    self.found_group_address = True
                elif inrec.find('set zone ') >= 0:
                    if 'debug' in globals() and debug > 1:
                        print "found zone in [%s]" % inrec
                    self.found_zone = True
                elif inrec.find('set interface ') >= 0:
                    if 'debug' in globals() and debug > 1:
                        print "found interface in [%s]" % inrec
                    self.found_interface = True
                elif inrec.find('set policy ') >= 0:
                    if 'debug' in globals() and debug > 1:
                        print "found policy in [%s]" % inrec
                    self.found_policy = True
        self._close_infile()
        return
    
    def _init_any(self):
        """
        Method to initialize the default definitions
        of "Any" in addresses or services
        """
        self.add_zone('Global')
        self.addresses['Any'] = Address('Any',self.zones['Global'])
        self.addresses['Any'].add_addr('0.0.0.0/0','Global')
        self.addresses['ANY'] = Address('ANY',self.zones['Global'])
        self.addresses['ANY'].add_addr('0.0.0.0/0','Global')
        self.services['Any'] = Service('Any',0,0,65535,0,65535)
        self.services['ANY'] = Service('ANY',0,0,65535,0,65535)
        
        self.addresses['Any-IPv4'] = Address('Any-IPv4',self.zones['Global'])
        self.addresses['Any-IPv4'].add_addr('0.0.0.0/0','Global')
        self.addresses['ANY-IPv4'] = Address('ANY-IPv4',self.zones['Global'])
        self.addresses['ANY-IPv4'].add_addr('0.0.0.0/0','Global')
        self.services['Any-IPv4'] = Service('Any-IPv4',0,0,65535,0,65535)
        self.services['ANY-IPv4'] = Service('ANY-IPv4',0,0,65535,0,65535)
        
        self.addresses['Any-IPv6'] = Address('Any-IPv6',self.zones['Global'])
        self.addresses['Any-IPv6'].add_addr('::/0','Global')
        self.addresses['ANY-IPv6'] = Address('ANY-IPv6',self.zones['Global'])
        self.addresses['ANY-IPv6'].add_addr('::/0','Global')
        self.services['Any-IPv6'] = Service('Any-IPv6',0,0,65535,0,65535)
        self.services['ANY-IPv6'] = Service('ANY-IPv6',0,0,65535,0,65535)
        return 
    
    def generate_predefined(self):
        """
        Method to load in the predefined service and
        service groups for Netscreen as stored on 
        disk in the files services and service-groups 
        """
        if 'debug' in globals() and debug > 0:
            print "in input_predefined"
        self.services = {}
        indent=' '*8
        defindent = " "*4
        outfile = open('define_defaults','wb')
        outfile.write(defindent+'def _load_predefined(self):\n')
        self.infile = open('services','rb')
        self.prev = self.infile.tell()
        inrec = self.infile.readline().strip()
        if 'debug' in globals() and debug > 2:
            print "read in initial record [%s]" % inrec
        self.curr = self.infile.tell()
        while self.curr > self.prev:
            if inrec.find(',') > 0:
                servicename,protonum,ports = inrec.split(',')
                if 'debug' in globals() and debug > 2:
                    print "split out:"
                    print servicename
                    print protonum
                    print ports
                protonum = int(protonum)
                if ports.find('-') < 1:
                    if 'debug' in globals() and debug > 2:
                        print "no dash found - setting from/to same"
                    sdfrom = int(ports)
                    sdto = int(ports)
                else:
                    sdfrom,sdto = ports.split('-')
                    if 'debug' in globals() and debug > 2:
                        print "split out:"
                        print sdfrom
                        print sdto
                    sdfrom = int(sdfrom)
                    sdto = int(sdto)
                if 'debug' in globals() and debug > 2:
                    print "creating [%s] = [%d] [0] [65535] [%d] [%d]" % (servicename,protonum,sdfrom,sdto)
                self.services[servicename] = Service(servicename,protonum,0,65535,sdfrom,sdto)
                node = 'self.services["'+servicename+'"]'
                action = ' = Service("'+servicename
                action = action + '",'+str(protonum)
                action = action + ',0,65535,'+str(sdfrom)
                action = action + ','+str(sdto)+')'
                outfile.write(indent+node+action+'\n')
                if 'debug' in globals() and debug > 2:
                    self.services[servicename].print_service()
            self.prev = int(self.curr)
            inrec = self.infile.readline().strip()
            self.curr = self.infile.tell()
        self.infile.close()
        protobynum = {}
        for service in sorted(self.services.keys()):
            if self.services[service].protonum in protobynum.keys():
                protobynum[self.services[service].protonum][service] = {}
                protobynum[self.services[service].protonum][service]['from'] = self.services[service].sdfrom
                protobynum[self.services[service].protonum][service]['to'] = self.services[service].sdto
            else:
                protobynum[self.services[service].protonum] = {}
                protobynum[self.services[service].protonum][service] = {}
                protobynum[self.services[service].protonum][service]['from'] = self.services[service].sdfrom
                protobynum[self.services[service].protonum][service]['to'] = self.services[service].sdto
        self.infile = open('service-groups','rb')
        self.prev = self.infile.tell()
        inrec = self.infile.readline().strip()
        self.curr = self.infile.tell()
        while self.curr > self.prev:
            if inrec.find(',') > 0:
                servicegroupname,services = inrec.split(',',1)
                services = services.split(',')
                self.services[servicegroupname] = ServiceGroup(servicegroupname,self)
                node = 'self.services["'+servicegroupname+'"]'
                action = ' = ServiceGroup("'+servicegroupname+'",self)'
                outfile.write(indent+node+action+'\n')
                for i in range(len(services)):
                    services[i] = services[i].replace('\"','')
                    self.services[servicegroupname].add_service(self.services[services[i]])
                    action = '.add_service(self.services["'+services[i]+'"])'
                    outfile.write(indent+node+action+'\n')
            self.prev = int(self.curr)
            inrec = self.infile.readline().strip()
            self.curr = self.infile.tell()
        outfile.write(indent+'return\n')
        self.infile.close()
        outfile.close()
        return
    
    def _load_predefined(self):
        self.services["AOL"] = Service("AOL",6,0,65535,5190,5194)
        self.services["APPLE-ICHAT-SNATMAP"] = Service("APPLE-ICHAT-SNATMAP",17,0,65535,5678,5678)
        self.services["BGP"] = Service("BGP",6,0,65535,179,179)
        self.services["CHARGEN"] = Service("CHARGEN",17,0,65535,19,19)
        self.services["DHCP-Relay"] = Service("DHCP-Relay",17,0,65535,67,67)
        self.services["DISCARD"] = Service("DISCARD",17,0,65535,9,9)
        self.services["DNS"] = Service("DNS",17,0,65535,53,53)
        self.services["ECHO"] = Service("ECHO",17,0,65535,7,7)
        self.services["FINGER"] = Service("FINGER",6,0,65535,79,79)
        self.services["FTP"] = Service("FTP",6,0,65535,21,21)
        self.services["FTP-Get"] = Service("FTP-Get",6,0,65535,21,21)
        self.services["FTP-Put"] = Service("FTP-Put",6,0,65535,21,21)
        self.services["GNUTELLA"] = Service("GNUTELLA",17,0,65535,6346,6347)
        self.services["GOPHER"] = Service("GOPHER",6,0,65535,70,70)
        self.services["GRE"] = Service("GRE",47,0,65535,0,65535)
        self.services["GTP"] = Service("GTP",6,0,65535,3386,3386)
        self.services["H.323"] = Service("H.323",6,0,65535,1720,1720)
        self.services["HTTP"] = Service("HTTP",6,0,65535,80,80)
        self.services["HTTP-EXT"] = Service("HTTP-EXT",6,0,65535,8000,8001)
        self.services["HTTPS"] = Service("HTTPS",6,0,65535,443,443)
        self.services["ICMP"] = Service("ICMP",1,0,65535,0,65535)
        self.services["ICMP Address Mask"] = Service("ICMP Address Mask",1,0,65535,0,65535)
        self.services["ICMP Dest Unreachable"] = Service("ICMP Dest Unreachable",1,0,65535,0,65535)
        self.services["ICMP Fragment Needed"] = Service("ICMP Fragment Needed",1,0,65535,0,65535)
        self.services["ICMP Fragment Reassembly"] = Service("ICMP Fragment Reassembly",1,0,65535,0,65535)
        self.services["ICMP Host Unreachable"] = Service("ICMP Host Unreachable",1,0,65535,0,65535)
        self.services["ICMP Parameter Problem"] = Service("ICMP Parameter Problem",1,0,65535,0,65535)
        self.services["ICMP Port Unreachable"] = Service("ICMP Port Unreachable",1,0,65535,0,65535)
        self.services["ICMP Protocol Unreach"] = Service("ICMP Protocol Unreach",1,0,65535,0,65535)
        self.services["ICMP Redirect"] = Service("ICMP Redirect",1,0,65535,0,65535)
        self.services["ICMP Redirect Host"] = Service("ICMP Redirect Host",1,0,65535,0,65535)
        self.services["ICMP Redirect TOS & Host"] = Service("ICMP Redirect TOS & Host",1,0,65535,0,65535)
        self.services["ICMP Redirect TOS & Net"] = Service("ICMP Redirect TOS & Net",1,0,65535,0,65535)
        self.services["ICMP Source Quench"] = Service("ICMP Source Quench",1,0,65535,0,65535)
        self.services["ICMP Source Route Fail"] = Service("ICMP Source Route Fail",1,0,65535,0,65535)
        self.services["ICMP Time Exceeded"] = Service("ICMP Time Exceeded",1,0,65535,0,65535)
        self.services["ICMP-ANY"] = Service("ICMP-ANY",1,0,65535,0,65535)
        self.services["ICMP-INFO"] = Service("ICMP-INFO",1,0,65535,0,65535)
        self.services["ICMP-TIMESTAMP"] = Service("ICMP-TIMESTAMP",1,0,65535,0,65535)
        self.services["ICMP6-ANY"] = Service("ICMP6-ANY",58,0,65535,0,65535)
        self.services["ICMP6 Dst Unreach addr"] = Service("ICMP6 Dst Unreach addr",58,0,65535,0,65535)
        self.services["ICMP6 Dst Unreach admin"] = Service("ICMP6 Dst Unreach admin",58,0,65535,0,65535)
        self.services["ICMP6 Dst Unreach beyond"] = Service("ICMP6 Dst Unreach beyond",58,0,65535,0,65535)
        self.services["ICMP6 Dst Unreach port"] = Service("ICMP6 Dst Unreach port",58,0,65535,0,65535)
        self.services["ICMP6 Dst Unreach route"] = Service("ICMP6 Dst Unreach route",58,0,65535,0,65535)
        self.services["ICMP6 Echo Reply"] = Service("ICMP6 Echo Reply",58,0,65535,0,65535)
        self.services["ICMP6 Echo Request"] = Service("ICMP6 Echo Request",58,0,65535,0,65535)
        self.services["ICMP6 HAAD Reply"] = Service("ICMP6 HAAD Reply",58,0,65535,0,65535)
        self.services["ICMP6 HAAD Request"] = Service("ICMP6 HAAD Request",58,0,65535,0,65535)
        self.services["ICMP6 MP Advertisement"] = Service("ICMP6 MP Advertisement",58,0,65535,0,65535)
        self.services["ICMP6 MP Solicitation"] = Service("ICMP6 MP Solicitation",58,0,65535,0,65535)
        self.services["ICMP6 Packet Too Big"] = Service("ICMP6 Packet Too Big",58,0,65535,0,65535)
        self.services["ICMP6 Param Prob header"] = Service("ICMP6 Param Prob header",58,0,65535,0,65535)
        self.services["ICMP6 Param Prob nexthdr"] = Service("ICMP6 Param Prob nexthdr",58,0,65535,0,65535)
        self.services["ICMP6 Param Prob option"] = Service("ICMP6 Param Prob option",58,0,65535,0,65535)
        self.services["ICMP6 Time Exceed reasse"] = Service("ICMP6 Time Exceed reasse",58,0,65535,0,65535)
        self.services["ICMP6 Time Exceed transi"] = Service("ICMP6 Time Exceed transi",58,0,65535,0,65535)
        self.services["IDENT"] = Service("IDENT",6,0,65535,113,113)
        self.services["IKE"] = Service("IKE",17,0,65535,500,500)
        self.services["IKE-NAT"] = Service("IKE-NAT",17,0,65535,500,500)
        self.services["IMAP"] = Service("IMAP",6,0,65535,143,143)
        self.services["Internet-Locator-Service"] = Service("Internet-Locator-Service",6,0,65535,389,389)
        self.services["IRC"] = Service("IRC",6,0,65535,6660,6669)
        self.services["L2TP"] = Service("L2TP",17,0,65535,1701,1701)
        self.services["LDAP"] = Service("LDAP",6,0,65535,389,389)
        self.services["LPR"] = Service("LPR",6,0,65535,515,515)
        self.services["MAIL"] = Service("MAIL",6,0,65535,25,25)
        self.services["MGCP-CA"] = Service("MGCP-CA",17,0,65535,2727,2727)
        self.services["MGCP-UA"] = Service("MGCP-UA",17,0,65535,2427,2427)
        self.services["MS-AD-BR"] = Service("MS-AD-BR",0,0,65535,0,0)
        self.services["MS-AD-DRSUAPI"] = Service("MS-AD-DRSUAPI",0,0,65535,0,0)
        self.services["MS-AD-DSROLE"] = Service("MS-AD-DSROLE",0,0,65535,0,0)
        self.services["MS-AD-DSSETUP"] = Service("MS-AD-DSSETUP",0,0,65535,0,0)
        self.services["MS-DTC"] = Service("MS-DTC",0,0,65535,0,0)
        self.services["MS-EXCHANGE-DATABASE"] = Service("MS-EXCHANGE-DATABASE",0,0,65535,0,0)
        self.services["MS-EXCHANGE-DIRECTORY"] = Service("MS-EXCHANGE-DIRECTORY",0,0,65535,0,0)
        self.services["MS-EXCHANGE-INFO-STORE"] = Service("MS-EXCHANGE-INFO-STORE",0,0,65535,0,0)
        self.services["MS-EXCHANGE-MTA"] = Service("MS-EXCHANGE-MTA",0,0,65535,0,0)
        self.services["MS-EXCHANGE-STORE"] = Service("MS-EXCHANGE-STORE",0,0,65535,0,0)
        self.services["MS-EXCHANGE-SYSATD"] = Service("MS-EXCHANGE-SYSATD",0,0,65535,0,0)
        self.services["MS-FRS"] = Service("MS-FRS",0,0,65535,0,0)
        self.services["MS-IIS-COM"] = Service("MS-IIS-COM",0,0,65535,0,0)
        self.services["MS-IIS-IMAP4"] = Service("MS-IIS-IMAP4",0,0,65535,0,0)
        self.services["MS-IIS-INETINFO"] = Service("MS-IIS-INETINFO",0,0,65535,0,0)
        self.services["MS-IIS-NNTP"] = Service("MS-IIS-NNTP",0,0,65535,0,0)
        self.services["MS-IIS-POP3"] = Service("MS-IIS-POP3",0,0,65535,0,0)
        self.services["MS-IIS-SMTP"] = Service("MS-IIS-SMTP",0,0,65535,0,0)
        self.services["MS-ISMSERV"] = Service("MS-ISMSERV",0,0,65535,0,0)
        self.services["MS-MESSENGER"] = Service("MS-MESSENGER",0,0,65535,0,0)
        self.services["MS-MQQM"] = Service("MS-MQQM",0,0,65535,0,0)
        self.services["MS-NETLOGON"] = Service("MS-NETLOGON",0,0,65535,0,0)
        self.services["MS-RPC-ANY"] = Service("MS-RPC-ANY",0,0,65535,0,0)
        self.services["MS-RPC-EPM"] = Service("MS-RPC-EPM",17,0,65535,135,135)
        self.services["MS-SCHEDULER"] = Service("MS-SCHEDULER",0,0,65535,0,0)
        self.services["MS-SQL"] = Service("MS-SQL",6,0,65535,1433,1433)
        self.services["MS-WIN-DNS"] = Service("MS-WIN-DNS",0,0,65535,0,0)
        self.services["MS-WINS"] = Service("MS-WINS",0,0,65535,0,0)
        self.services["MS-WMIC"] = Service("MS-WMIC",0,0,65535,0,0)
        self.services["MSN"] = Service("MSN",6,0,65535,1863,1863)
        self.services["NBDS"] = Service("NBDS",17,0,65535,138,138)
        self.services["NBNAME"] = Service("NBNAME",17,0,65535,137,137)
        self.services["NetMeeting"] = Service("NetMeeting",6,0,65535,1720,1720)
        self.services["NFS"] = Service("NFS",17,0,65535,111,111)
        self.services["NNTP"] = Service("NNTP",6,0,65535,119,119)
        self.services["NS Global"] = Service("NS Global",6,0,65535,15397,15397)
        self.services["NS Global PRO"] = Service("NS Global PRO",6,0,65535,15397,15397)
        self.services["NSM"] = Service("NSM",17,0,65535,69,69)
        self.services["NTP"] = Service("NTP",17,0,65535,123,123)
        self.services["OSPF"] = Service("OSPF",89,0,65535,0,65535)
        self.services["PC-Anywhere"] = Service("PC-Anywhere",17,0,65535,5632,5632)
        self.services["PING"] = Service("PING",1,0,65535,0,65535)
        self.services["PINGv6"] = Service("PING",58,0,65535,0,65535)
        self.services["POP3"] = Service("POP3",6,0,65535,110,110)
        self.services["PPTP"] = Service("PPTP",6,0,65535,1723,1723)
        self.services["RADIUS"] = Service("RADIUS",17,0,65535,1812,1813)
        self.services["Real Media"] = Service("Real Media",6,0,65535,7070,7070)
        self.services["REXEC"] = Service("REXEC",6,0,65535,512,512)
        self.services["RIP"] = Service("RIP",17,0,65535,520,520)
        self.services["RLOGIN"] = Service("RLOGIN",6,0,65535,513,513)
        self.services["RPC"] = Service("RPC",0,0,65535,0,65535)
        self.services["RSH"] = Service("RSH",6,0,65535,514,514)
        self.services["RTSP"] = Service("RTSP",6,0,65535,554,554)
        self.services["SCCP"] = Service("SCCP",6,0,65535,2000,2000)
        self.services["SCTP-ANY"] = Service("SCTP-ANY",132,0,65535,0,65535)
        self.services["SIP"] = Service("SIP",17,0,65535,5060,5060)
        self.services["SMB"] = Service("SMB",6,0,65535,139,139)
        self.services["SMTP"] = Service("SMTP",6,0,65535,25,25)
        self.services["SNMP"] = Service("SNMP",17,0,65535,161,161)
        self.services["SQL Monitor"] = Service("SQL Monitor",17,0,65535,1434,1434)
        self.services["SQL*Net V1"] = Service("SQL*Net V1",6,0,65535,1525,1525)
        self.services["SQL*Net V2"] = Service("SQL*Net V2",6,0,65535,1521,1521)
        self.services["SSH"] = Service("SSH",6,0,65535,22,22)
        self.services["SUN-RPC"] = Service("SUN-RPC",0,0,65535,0,0)
        self.services["SUN-RPC-ANY"] = Service("SUN-RPC-ANY",0,0,65535,0,0)
        self.services["SUN-RPC-MOUNTD"] = Service("SUN-RPC-MOUNTD",0,0,65535,0,0)
        self.services["SUN-RPC-NFS"] = Service("SUN-RPC-NFS",0,0,65535,0,0)
        self.services["SUN-RPC-NLOCKMGR"] = Service("SUN-RPC-NLOCKMGR",0,0,65535,0,0)
        self.services["SUN-RPC-PORTMAPPER"] = Service("SUN-RPC-PORTMAPPER",17,0,65535,111,111)
        self.services["SUN-RPC-RQUOTAD"] = Service("SUN-RPC-RQUOTAD",0,0,65535,0,0)
        self.services["SUN-RPC-RSTATD"] = Service("SUN-RPC-RSTATD",0,0,65535,0,0)
        self.services["SUN-RPC-RUSERD"] = Service("SUN-RPC-RUSERD",0,0,65535,0,0)
        self.services["SUN-RPC-SADMIND"] = Service("SUN-RPC-SADMIND",0,0,65535,0,0)
        self.services["SUN-RPC-SPRAYD"] = Service("SUN-RPC-SPRAYD",0,0,65535,0,0)
        self.services["SUN-RPC-STATUS"] = Service("SUN-RPC-STATUS",0,0,65535,0,0)
        self.services["SUN-RPC-WALLD"] = Service("SUN-RPC-WALLD",0,0,65535,0,0)
        self.services["SUN-RPC-YPBIND"] = Service("SUN-RPC-YPBIND",0,0,65535,0,0)
        self.services["SYSLOG"] = Service("SYSLOG",17,0,65535,514,514)
        self.services["TALK"] = Service("TALK",17,0,65535,517,518)
        self.services["TCP"] = Service("TCP",6,0,65535,0,65535)
        self.services["TCP-ANY"] = Service("TCP-ANY",6,0,65535,0,65535)
        self.services["TELNET"] = Service("TELNET",6,0,65535,23,23)
        self.services["TFTP"] = Service("TFTP",17,0,65535,69,69)
        self.services["TRACEROUTE"] = Service("TRACEROUTE",1,0,65535,0,65535)
        self.services["UDP"] = Service("UDP",17,0,65535,0,65535)
        self.services["UDP-ANY"] = Service("UDP-ANY",17,0,65535,0,65535)
        self.services["UUCP"] = Service("UUCP",17,0,65535,540,540)
        self.services["VDO Live"] = Service("VDO Live",6,0,65535,7000,7010)
        self.services["VNC"] = Service("VNC",6,0,65535,5800,5800)
        self.services["WAIS"] = Service("WAIS",6,0,65535,210,210)
        self.services["WHOIS"] = Service("WHOIS",6,0,65535,43,43)
        self.services["WINFRAME"] = Service("WINFRAME",6,0,65535,1494,1494)
        self.services["X-WINDOWS"] = Service("X-WINDOWS",6,0,65535,6000,6063)
        self.services["YMSG"] = Service("YMSG",6,0,65535,5050,5050)
        self.services["APPLE-ICHAT"] = ServiceGroup("APPLE-ICHAT",self)
        self.services["APPLE-ICHAT"].add_service(self.services["AOL"])
        self.services["APPLE-ICHAT"].add_service(self.services["APPLE-ICHAT-SNATMAP"])
        self.services["APPLE-ICHAT"].add_service(self.services["DNS"])
        self.services["APPLE-ICHAT"].add_service(self.services["HTTP"])
        self.services["APPLE-ICHAT"].add_service(self.services["HTTPS"])
        self.services["APPLE-ICHAT"].add_service(self.services["SIP"])
        self.services["MGCP"] = ServiceGroup("MGCP",self)
        self.services["MGCP"].add_service(self.services["MGCP-CA"])
        self.services["MGCP"].add_service(self.services["MGCP-UA"])
        self.services["MS-AD"] = ServiceGroup("MS-AD",self)
        self.services["MS-AD"].add_service(self.services["MS-AD-BR"])
        self.services["MS-AD"].add_service(self.services["MS-AD-DRSUAPI"])
        self.services["MS-AD"].add_service(self.services["MS-AD-DSROLE"])
        self.services["MS-AD"].add_service(self.services["MS-AD-DSSETUP"])
        self.services["MS-EXCHANGE"] = ServiceGroup("MS-EXCHANGE",self)
        self.services["MS-EXCHANGE"].add_service(self.services["MS-EXCHANGE-DATABASE"])
        self.services["MS-EXCHANGE"].add_service(self.services["MS-EXCHANGE-DIRECTORY"])
        self.services["MS-EXCHANGE"].add_service(self.services["MS-EXCHANGE-INFO-STORE"])
        self.services["MS-EXCHANGE"].add_service(self.services["MS-EXCHANGE-MTA"])
        self.services["MS-EXCHANGE"].add_service(self.services["MS-EXCHANGE-STORE"])
        self.services["MS-EXCHANGE"].add_service(self.services["MS-EXCHANGE-SYSATD"])
        self.services["MS-IIS"] = ServiceGroup("MS-IIS",self)
        self.services["MS-IIS"].add_service(self.services["MS-IIS-COM"])
        self.services["MS-IIS"].add_service(self.services["MS-IIS-IMAP4"])
        self.services["MS-IIS"].add_service(self.services["MS-IIS-INETINFO"])
        self.services["MS-IIS"].add_service(self.services["MS-IIS-NNTP"])
        self.services["MS-IIS"].add_service(self.services["MS-IIS-POP3"])
        self.services["MS-IIS"].add_service(self.services["MS-IIS-SMTP"])
        self.services["VOIP"] = ServiceGroup("VOIP",self)
        self.services["VOIP"].add_service(self.services["H.323"])
        self.services["VOIP"].add_service(self.services["MGCP-CA"])
        self.services["VOIP"].add_service(self.services["MGCP-UA"])
        self.services["VOIP"].add_service(self.services["SCCP"])
        self.services["VOIP"].add_service(self.services["SIP"])
        return
    
    def _close_infile(self):
        """
        Ensure input file is closed
        """
        if self.open:
            self.infile.close()
            self.open = False
            self.curr = 0
            self.prev = -1
            self.inrec = ''
        return
    
    def _open_infile(self):
        """
        Ensure input file is closed
        """
        if not self.open:
            self.infile = open(self.filename,'rb') 
            self.open = True
            self.curr = 0
            self.prev = -1
            self.inrec = ''
        return
    
    def _get_next(self):
        """
        Method to get next record while
        tracking for eof vs eol
        i.e. read which doesn't increment
        position in file since we are at eof
        """
        self.prev = int(self.curr)
        self.inrec = self.infile.readline().strip()
        self.curr = int(self.infile.tell())
        if self.prev == self.curr:
            self._close_infile()
        return
    
    def parse_service_block(self):
        """
        Method to parse out service definition lines
        """
        if 'debug' in globals() and debug > 0:
            print "*"*50
            print "Parsing service block"
            print "*"*50
        self._open_infile()
        inrec = self.infile.readline().strip()
        self.prev = int(self.curr)
        self.curr = self.infile.tell()
        if len(inrec) > 0:
            while self.open and self.inrec.find('set service ') < 0:
                if 'debug' in globals() and debug > 2:
                    print "skipping %s" % self.inrec
                self._get_next()
            while self.inrec.find('set service ') == 0:
                # Only parse service definitions - ignore timeouts etc
                if self.inrec.find(' protocol ') > 0:
                    servicename = self.inrec.split('\"')[1]
                    sname = self.inrec.split('\"')[2].split(' ')[2].upper()
                    psrc = self.inrec.split('\"')[2].split(' ')[4]
                    pdst = self.inrec.split('\"')[2].split(' ')[6]
                    sfrom = int(psrc.split('-')[0])
                    sto = int(psrc.split('-')[1])
                    dfrom = int(pdst.split('-')[0])
                    dto = int(pdst.split('-')[1])
                    pnum = int(self.services[sname].protonum)
                    self.services[servicename] = Service(servicename,pnum,sfrom,sto,dfrom,dto)
                self._get_next()
        self._close_infile()
        return
    
    def parse_zone_block(self):
        """
        Method to parse out the zones configured on the firewall
        """
        if 'debug' in globals() and debug > 0:
            print "*"*50
            print "Parsing zone block"
            print "*"*50
        self._open_infile()
        inrec = self.infile.readline().strip()
        self.prev = int(self.curr)
        self.curr = self.infile.tell()
        if len(inrec) > 0:
            while self.open and self.inrec.find('set zone ') < 0:
                if 'debug' in globals() and debug > 2:
                    print "skipping %s" % self.inrec
                self._get_next()
            while self.inrec.find('set zone ') >= 0:
                zonename = self.inrec.split('\"')[1]
                if 'debug' in globals() and debug > 0:
                    print "adding zone %s" % zonename
                self.add_zone(zonename)
                self._get_next()
        self._close_infile()
        return
        
    def parse_interface_block(self):
        """
        Method to parse out the interfaces configured on the firewall
        """
        if 'debug' in globals() and debug > 0:
            print "*"*50
            print "Parsing interface block"
            print "*"*50
        self._open_infile()
        inrec = self.infile.readline().strip()
        self.prev = int(self.curr)
        self.curr = self.infile.tell()
        if len(inrec) > 0:
            while self.open and self.inrec.find('set interface ') < 0:
                if 'debug' in globals() and debug > 2:
                    print "skipping %s" % self.inrec
                self._get_next()
            while self.inrec.find('set interface ') >= 0 or \
                  self.inrec.find('set auth-server ') >= 0:
                if self.inrec.find('set auth-server ') >= 0:
                    self._get_next()
                    continue
                if self.inrec.find('set interface \"') == 0:
                    intname = self.inrec.split('\"')[1]
                else:
                    intname = self.inrec.split(' ')[2]
                if intname not in self.interfaces.keys():
                    self.interfaces[intname] = {}
                    self.interfaces[intname]['unnumbered'] = False
                    self.interfaces[intname]['unnumbered-interface'] = ''
                    self.interfaces[intname]['manageable'] = False
                    self.interfaces[intname]['manage-ip'] = ''
                    self.interfaces[intname]['ip'] = ''
                    self.interfaces[intname]['ipv6'] = {}
                    self.interfaces[intname]['nat'] = False
                    self.interfaces[intname]['route'] = False
                    self.interfaces[intname]['description'] = ''
                    self.interfaces[intname]['mtu'] = 1500
                    self.interfaces[intname]['manage-ssh'] = False
                    self.interfaces[intname]['manage-telnet'] = False
                    self.interfaces[intname]['manage-snmp'] = False
                    self.interfaces[intname]['manage-ssl'] = False
                    self.interfaces[intname]['manage-ping'] = False
                    self.interfaces[intname]['dip'] = {}
                    self.interfaces[intname]['vip'] = []
                    self.interfaces[intname]['mip'] = {}
                    self.interfaces[intname]['zone'] = ''
                if self.inrec.find(' zone ') > 0:
                    zonename = self.inrec.split(' ')[4].replace("\"","")
                    if zonename in self.zones.keys():
                        self.interfaces[intname]['zone'] = self.zones[zonename]
                    else:
                        self.add_zone(zonename)
                        self.interfaces[intname]['zone'] = self.zones[zonename]
                if self.inrec.find(' ip unnumbered ') > 0:
                    self.interfaces[intname]['unnumbered'] = True
                    self.interfaces[intname]['unnumbered-interface'] = self.inrec.split(' ')[6]
                elif self.inrec.find(' ip manageable') > 0:
                    self.interfaces[intname]['manageable'] = True
                elif self.inrec.find(' manage-ip ') > 0:
                    self.interfaces[intname]['manage-ip'] = self.inrec.split(' ')[4]
                elif self.inrec.find(' ip ') > 0:
                    if self.inrec.find('.') > 0:
                        self.interfaces[intname]['ip'] = self.inrec.split(' ')[4]
                    elif self.inrec.find(':') >= 0:
                        self.interfaces[intname]['ipv6'][self.inrec.split(' ')[5]] = self.inrec.split(' ')[5]
                if self.inrec.find(' nat') > 0:
                    self.interfaces[intname]['nat'] = True
                if self.inrec.find(' route') > 0:
                    self.interfaces[intname]['route'] = True
                if self.inrec.find(' description ') > 0:
                    if self.inrec.find('set interface \"') == 0:
                        self.interfaces[intname]['description'] = self.inrec.split('\"')[3]
                    else:
                        self.interfaces[intname]['description'] = self.inrec.split('\"')[1]
                if self.inrec.find(' mtu ') > 0:
                    self.interfaces[intname]['mtu'] = int(self.inrec.split(' ')[4])
                if self.inrec.find(' manage ssh ') > 0:
                    self.interfaces[intname]['manage-ssh'] = True
                if self.inrec.find(' manage telnet ') > 0:
                    self.interfaces[intname]['manage-telnet'] = True
                if self.inrec.find(' manage snmp ') > 0:
                    self.interfaces[intname]['manage-snmp'] = True
                if self.inrec.find(' manage ssl ') > 0:
                    self.interfaces[intname]['manage-ssl'] = True
                if self.inrec.find(' manage ping ') > 0:
                    self.interfaces[intname]['manage-ping'] = True
                if self.inrec.find(' vip ') > 0:
                    self.interfaces[intname]['vip'].append(self.inrec.split(' vip ')[1])
                    addrname = 'VIP('+self.inrec.split(' vip ')[1].split(' ')[0]+')'
                    addr = self.inrec.split(' vip ')[1].split(' ')[0]
                    target = self.inrec.split(' vip ')[1].split(' ')[3]
                    srcport = self.inrec.split(' vip ')[1].split()[1]
                    dstport = self.inrec.split(' vip ')[1].split()[2]
                    self.add_vip(addrname,srcport,dstport,target,intname)
                    if addrname not in self.addresses.keys():
                        if 'Global' not in self.zones.keys():
                            self.add_zone('Global')
                        self.addresses[addrname] = Address(addrname,self.zones['Global'],target)
                        self.addresses[addrname].add_addr(str(addr),self.zones['Global'])
                        self.addresses[addrname].add_comment(addrname+' to '+target)
                if self.inrec.find(' mip ') > 0:
                    if self.inrec.find(' host ') > 0:
                        self.interfaces[intname]['mip'][self.inrec.split(' mip ')[1].split(' ')[0]] = \
                            self.inrec.split(' mip ')[1].split(' host ')[1].split(' ')[0]
                        addrname = 'MIP('+self.inrec.split(' mip ')[1].split(' ')[0]+')'
                        addr = self.inrec.split(' mip ')[1].split(' ')[0]
                        target = self.inrec.split(' mip ')[1].split(' host ')[1].split(' ')[0]
                        self.add_mip(addrname,target,intname)
                        if addrname not in self.addresses.keys():
                            if 'Global' not in self.zones.keys():
                                self.add_zone('Global')
                            self.addresses[addrname] = Address(addrname,self.zones['Global'],target)
                            self.addresses[addrname].add_addr(str(addr),self.zones['Global'])
                            self.addresses[addrname].add_comment(addrname+' mips to '+target)
                    else:
                        self.interfaces[intname]['mip'][self.inrec.split(' mip ')[1]] = self.inrec.split(' mip ')[1]
                if self.inrec.find(' dip ') > 0:
                    if 'debug' in globals() and debug > 0:
                        print "Parsing out DIP definition in %s" % self.inrec
                    self.interfaces[intname]['dip'][self.inrec.split(' ')[4]] = self.inrec.split(' dip ')[1].split(" ",1)[1]
                    self.add_dip(self.inrec.split(' ')[4],self.inrec.split(' dip ')[1].split(" ",1)[1],intname)
                    if 'debug' in globals() and debug > 0:
                        print "Added DIP #%s as %s" % ()
                self._get_next()
        self._close_infile()
        return
    
    def parse_address_block(self):
        """
        Method to parse out the named addresses configured on the firewall
        """
        if 'debug' in globals() and debug > 0:
            print "*"*50
            print "Parsing address block"
            print "*"*50
        self._open_infile()
        inrec = self.infile.readline().strip()
        self.prev = int(self.curr)
        self.curr = self.infile.tell()
        if len(inrec) > 0:
            while self.open and self.inrec.find('set address ') < 0:
                if 'debug' in globals() and debug > 2:
                    print "skipping %s" % self.inrec
                self._get_next()
            while self.inrec.find('set address ') >= 0:
                if 'debug' in globals() and debug > 0:
                    print "parsing set address"
                zonename = self.inrec.split('\"')[1]
                if 'debug' in globals() and debug > 0:
                    print "zonename parsed: %s" % zonename
                if zonename not in self.zones.keys():
                    if 'debug' in globals() and debug > 0:
                        print "zonename %s not found in zones.keys" % zonename
                    self.add_zone(zonename)
                    if 'debug' in globals() and debug > 0:
                        print "created zone %s" % zonename
                        print type(self.zones[zonename])
                addrname = self.inrec.split('\"')[3]
                addr = self.inrec.split('\"')[4].lstrip()
                if 'debug' in globals() and debug > 0:
                    print "parsed addrname=addr %s=%s" % (addrname,addr)
                    if addrname.find("MIP") >= 0:
                        print "*** FOUND MIP ***"
                if addrname not in self.addresses.keys():
                    if 'debug' in globals() and debug > 0:
                        print "addrname %s is new - adding to self.addresses" % addrname
                    self.addresses[addrname] = Address(addrname,self.zones[zonename])
                    if 'debug' in globals() and debug > 0:
                        print type(self.addresses[addrname])
                else:
                    print
                
                self.addresses[addrname].add_addr(addr,self.zones[zonename])
                self.zones[zonename].add_address(self.addresses[addrname])
                if len(self.inrec.split('\"')) > 5:
                     self.addresses[addrname].add_comment(self.inrec.split('\"')[5])
                self._get_next()
        self._close_infile()
        return
    
    def parse_address_group_block(self):
        """
        Method to parse out the address groups configured on the firewall
        """
        if 'debug' in globals() and debug > 0:
            print "*"*50
            print "Parsing group address block"
            print "*"*50
        self._open_infile()
        inrec = self.infile.readline().strip()
        self.prev = int(self.curr)
        self.curr = self.infile.tell()
        if len(inrec) > 0:
            while self.open and self.inrec.find('set group address ') < 0:
                if 'debug' in globals() and debug > 2:
                    print "skipping %s" % self.inrec
                self._get_next()
            while self.inrec.find('set group address ') >= 0:
                zonename = self.inrec.split('\"')[1]
                if 'debug' in globals() and debug > 0:
                    print "processing zonename %s" % zonename
                if zonename not in self.zones.keys():
                    if 'debug' in globals() and debug > 0:
                        print "zonename %s not found in zones.keys" % zonename
                    self.add_zone(zonename)
                    if 'debug' in globals() and debug > 0:
                        print "created zone %s" % zonename
                        print type(self.zones[zonename])
                groupname = self.inrec.split('\"')[3]
                if 'debug' in globals() and debug > 0:
                    print "processing groupname %s" % groupname
                if groupname not in self.addresses.keys():
                    if 'debug' in globals() and debug > 0:
                        print "new group - creating entry"
                    if zonename in self.zones.keys():
                        self.addresses[groupname] = AddressGroup(groupname,self.zones[zonename])
                    else:
                        print "Error: zone %s not found" % zonename
                if len(self.inrec.split('\"')) > 5:
                    if 'debug' in globals() and debug > 0:
                        print "self.inrec.split_quote > 5"
                    if self.inrec.split('\"')[4].find(' add ') >= 0:
                        if 'debug' in globals() and debug > 0:
                            print "processing add: %s" % self.inrec
                        addrname = self.inrec.split('\"')[5]
                        if 'debug' in globals() and debug > 0:
                            if addrname.find('MIP') >= 0:
                                print "*** FOUND MIP ***"
                        if addrname in self.addresses.keys():
                            if 'debug' in globals() and debug > 0:
                                print 'addr found in addresses - adding object to group'
                            self.addresses[groupname].add_addr(addrname,self.addresses[addrname])
                        else:
                            print "Error: address %s not defined yet" % addrname
                    elif self.inrec.split('\"')[4].find(' comment ') >= 0:
                        if 'debug' in globals() and debug > 0:
                            print "processing comment: %s" % self.inrec
                        self.addresses[groupname].add_comment(self.inrec.split('\"')[5])
                else:
                    if 'debug' in globals() and debug > 0:
                        print "self.inrec.split_quotes 5 or less - short line %s" % self.inrec
                self._get_next()
        self._close_infile()
        return
    
    def parse_service_group_block(self):
        """
        Method to parse out service group definitions
        """
        if 'debug' in globals() and debug > 0:
            print "*"*50
            print "Parsing service group block"
            print "*"*50
        self._open_infile()
        inrec = self.infile.readline().strip()
        self.prev = int(self.curr)
        self.curr = self.infile.tell()
        if len(inrec) > 0:
            while self.open and self.inrec.find('set group service ') < 0:
                if 'debug' in globals() and debug > 2:
                    print "skipping %s" % self.inrec
                self._get_next()
            while self.inrec.find('set group service ') >= 0:
                if 'debug' in globals() and debug > 0:
                    print "processing [%s]" % self.inrec
                groupname = self.inrec.split('\"')[1]
                if 'debug' in globals() and debug > 0:
                    print "processing group [%s]" % groupname
                if groupname not in self.services.keys():
                    if 'debug' in globals() and debug > 0:
                        print "groupname [%s] doesnt exist - adding" % groupname
                    self.services[groupname] = ServiceGroup(groupname,self)
                if len(self.inrec.split('\"')) > 2:
                    if 'debug' in globals() and debug > 0:
                        print "inrec.split_quotes > 2"
                    if self.inrec.split('\"')[2].find(' add ') >= 0:
                        if 'debug' in globals() and debug > 0:
                            print "add found"
                        servicename = self.inrec.split('\"')[3]
                        if 'debug' in globals() and debug > 0:
                            print "processing servicename [%s]" % servicename
                        if servicename not in self.services.keys():
                            print "Error: protocol [%s] not found" % servicename
                        else:
                            if servicename not in self.services[groupname].services.keys():
                                if 'debug' in globals() and debug > 0:
                                    print "servicename [%s] not found - adding" % servicename 
                                self.services[groupname].add_service(self.services[servicename])
                    elif self.inrec.split('\"')[2].find(' comment ') >= 0:
                        comment = self.inrec.split('\"')[3]
                        if 'debug' in globals() and debug > 0:
                            print "found comment - adding [%s]" % comment
                        self.services[groupname].comment = comment
                else:
                    if 'debug' in globals() and debug > 0:
                        print "short service group line [%s]" % self.inrec
                self._get_next()
        self._close_infile()
        return
        
    def parse_policies(self):
        """
        Method to parse policy definitions
        """
        if 'debug' in globals() and debug > 0:
            print "*"*50
            print "Parsing policy block"
            print "*"*50
        self._open_infile()
        inrec = self.infile.readline().strip()
        self.prev = int(self.curr)
        self.curr = self.infile.tell()
        if len(inrec) > 0:
            cur_policy = 0
            last_policy = 0
            policy_counter = 0
            if 'debug' in globals() and debug > 1:
                print "Before parse policies while with %s" % self.inrec
            while self.open and self.inrec.find('set policy id ') < 0:
                if 'debug' in globals() and debug > 1:
                    print "skipping %s" % self.inrec
                self._get_next()
            if 'debug' in globals() and debug > 1:
                print "dropped out with inrec %s:" % self.inrec
            while self.inrec.find('set policy id ') >= 0 or \
                  self.inrec.find('set src-address ') >= 0 or \
                  self.inrec.find('set dst-address ') >= 0 or \
                  self.inrec.find('set service ') >= 0 or \
                  self.inrec.find('set vpn ') >= 0 or \
                  self.inrec.find('set attack ') >= 0 or \
                  self.inrec.find('set url ') >= 0 or \
                  self.inrec.find('set log ') >= 0 or \
                  self.inrec.find('exit') >= 0:
                if 'debug' in globals() and debug > 0:
                    print "in while set policy id loop"
                if self.inrec.find('set policy id ') >= 0:
                    if 'debug' in globals() and debug > 0:
                        print "matched set policy id"
                    if cur_policy == int(self.inrec.split(' ')[3]):
                        if 'debug' in globals() and debug > 0:
                            print "cur_policy matches inrec"
                    else:
                        if 'debug' in globals() and debug > 0:
                            print "moving policy ids"
                        last_policy = int(cur_policy)
                        cur_policy = int(self.inrec.split(' ')[3])
                        policy_counter += 1
                        self.policy_discover_order[int(policy_counter)] = int(cur_policy)
                        if 'debug' in globals() and debug > 0:
                            print "now last_policy = %d" % last_policy
                            print "now cur_policy = %d" % cur_policy
                    if cur_policy in self.policies.keys():
                        if 'debug' in globals() and debug > 0:
                            print "cur_policy in self.policies already"
                    else:
                        if 'debug' in globals() and debug > 0:
                            print "initializing policy entry for %d" % cur_policy
                        self.policies[cur_policy] = PolicyItem(int(cur_policy),self)
                        self.policies[cur_policy].set_order(int(policy_counter))
                    if len(self.inrec.split(' ')) == 4:
                        if 'debug' in globals() and debug > 0:
                            print "short set policy id %d" % cur_policy
                    else:
                        if 'debug' in globals() and debug > 0:
                            print "inrec longer than 4"
                        if cur_policy in self.policies.keys():
                            if 'debug' in globals() and debug > 0:
                                print "cur_policy %d in policies.keys" % cur_policy
                        else:
                            if 'debug' in globals() and debug > 0:
                                print "cur_policy %d not in keys - initing" % cur_policy
                            self.policies[cur_policy] = PolicyItem(int(cur_policy),self)
                            self.policies[cur_policy].set_order(int(policy_counter))
                        if 'debug' in globals() and debug > 0:
                            print "processing [%s]" % self.inrec.split(' ')[4]
                        if self.inrec.split(' ')[4].find('disable') >= 0:
                            if 'debug' in globals() and debug > 0:
                                print "matched disable"
                            self.policies[cur_policy].set_disabled(True)
                        elif self.inrec.split(' ')[4].find('name') >= 0:
                            if 'debug' in globals() and debug > 0:
                                print "matched name"
                            self.policies[cur_policy].set_name(self.inrec.split('\"')[1])
                            zonename = self.inrec.split('\"')[3]
                            if 'debug' in globals() and debug > 0:
                                print "from zone %s" % zonename
                            if zonename in self.zones.keys():
                                if 'debug' in globals() and debug > 0:
                                    print 'zone %s already exists' % zonename
                                self.policies[cur_policy].set_from_zone(self.zones[zonename])
                            else:
                                if 'debug' in globals() and debug > 0:
                                    print "add new zone %s" % zonename
                                self.add_zone(zonename)
                                self.policies[cur_policy].set_from_zone(self.zones[zonename])
                            zonename = self.inrec.split('\"')[5]
                            if 'debug' in globals() and debug > 0:
                                print "to zone %s" % zonename
                            if zonename in self.zones.keys():
                                if 'debug' in globals() and debug > 0:
                                    print 'zone %s already exists' % zonename
                                self.policies[cur_policy].set_to_zone(self.zones[zonename])
                            else:
                                if 'debug' in globals() and debug > 0:
                                    print "add new zone %s" % zonename
                                self.add_zone(zonename)
                                self.policies[cur_policy].set_to_zone(self.zones[zonename])
                            if self.inrec.split('\"')[7].find('!') == 0:
                                negated = True
                                addrname = self.inrec.split('\"')[7][1:]
                                if addrname in self.addresses.keys():
                                    if 'debug' in globals() and debug > 0:
                                        print "adding src address %s" % addrname
                                    self.policies[cur_policy].add_src(addrname,self.addresses[addrname],negated)
                                else:
                                    print "error - address %s not found" % addrname
                                if 'debug' in globals() and debug > 0:
                                    print "negating address %s" % addrname
                            else:
                                negated = False
                                addrname = self.inrec.split('\"')[7]
                                if addrname in self.addresses.keys():
                                    if 'debug' in globals() and debug > 0:
                                        print "adding src address %s" % addrname
                                    self.policies[cur_policy].add_src(addrname,self.addresses[addrname],negated)
                                else:
                                    print "error - address %s not found" % addrname
                            if self.inrec.split('\"')[9].find('!') == 0:
                                negated = True
                                addrname = self.inrec.split('\"')[9][1:]
                                if addrname in self.addresses.keys():
                                    if 'debug' in globals() and debug > 0:
                                        print "adding dst address %s" % addrname
                                    self.policies[cur_policy].add_dst(addrname,self.addresses[addrname],negated)
                                else:
                                    print "error - address %s not found" % addrname
                                if 'debug' in globals() and debug > 0:
                                    print "negating address %s" % addrname
                            else:
                                negated = False
                                addrname = self.inrec.split('\"')[9]
                                if addrname in self.addresses.keys():
                                    if 'debug' in globals() and debug > 0:
                                        print "adding dst address %s" % addrname
                                    self.policies[cur_policy].add_dst(addrname,self.addresses[addrname],negated)
                                else:
                                    print "error - address %s not found" % addrname
                            if self.inrec.split('\"')[11].find('!') == 0:
                                negated = True
                                protoname = self.inrec.split('\"')[11][1:]
                                if protoname in self.services.keys():
                                    if 'debug' in globals() and debug > 0:
                                        print "adding service %s" % protoname
                                    self.policies[cur_policy].add_dst_svc(protoname,self.services[protoname],negated)
                                else:
                                    print "error - service %s not found" % protoname
                                if 'debug' in globals() and debug > 0:
                                    print "negating service %s" % protoname
                            else:
                                negated = False
                                protoname = self.inrec.split('\"')[11]
                                if protoname in self.services.keys():
                                    if 'debug' in globals() and debug > 0:
                                        print "adding service %s" % protoname
                                    self.policies[cur_policy].add_dst_svc(protoname,self.services[protoname],negated)
                                else:
                                    print "error - service %s not found" % protoname
                            action = self.inrec.split('\"')[12].lstrip()
                            if 'debug' in globals() and debug > 0:
                                print "action = %s" % action
                            if action.find('log') > 0:
                                if 'debug' in globals() and debug > 0:
                                    print "setting log to true"
                                self.policies[cur_policy].set_log(True)
                                action = action[0:action.find(' log')]
                                if 'debug' in globals() and debug > 0:
                                    print "action now = %s" % action
                            else:
                                if 'debug' in globals() and debug > 0:
                                    print "setting log false"
                                self.policies[cur_policy].set_log(False)
                            if action.find('permit') >= 0:
                                if 'debug' in globals() and debug > 0:
                                    print "setting action to permit"
                                self.policies[cur_policy].set_action('permit')
                            elif action.find('deny') >= 0:
                                if 'debug' in globals() and debug > 0:
                                    print "setting action to deny"
                                self.policies[cur_policy].set_action('deny')
                            elif action.find('reject') >= 0:
                                if 'debug' in globals() and debug > 0:
                                    print "setting action to reject"
                                self.policies[cur_policy].set_action('reject')
                            elif action.find('tunnel') >= 0:
                                if 'debug' in globals() and debug > 0:
                                    print "setting action to %s" % action
                                self.policies[cur_policy].set_action(action)
                            else:
                                if 'debug' in globals() and debug > 0:
                                    print "setting action to other?"
                                self.policies[cur_policy].set_action('other?')
                        elif self.inrec.split(' ')[4].find('from') >= 0:
                            if 'debug' in globals() and debug > 0:
                                print "matched from"
                            zonename = self.inrec.split('\"')[1]
                            if 'debug' in globals() and debug > 0:
                                print "processing from zone %s" % zonename
                            if zonename in self.zones.keys():
                                if 'debug' in globals() and debug > 0:
                                    print "zone found - setting"
                                self.policies[cur_policy].set_from_zone(self.zones[zonename])
                            else:
                                if 'debug' in globals() and debug > 0:
                                    print "zone not found - adding"
                                self.add_zone(zonename)
                                self.policies[cur_policy].set_from_zone(self.zones[zonename])
                            zonename = self.inrec.split('\"')[3]
                            if 'debug' in globals() and debug > 0:
                                print "processing to zone %s" % zonename
                            if zonename in self.zones.keys():
                                if 'debug' in globals() and debug > 0:
                                    print "zone found - setting"
                                self.policies[cur_policy].set_to_zone(self.zones[zonename])
                            else:
                                if 'debug' in globals() and debug > 0:
                                    print "zone not found - adding"
                                self.add_zone(zonename)
                                self.policies[cur_policy].set_to_zone(self.zones[zonename])
                            if self.inrec.split('\"')[5].find('!') == 0:
                                negated = True
                                addrname = self.inrec.split('\"')[5][1:]
                                if addrname in self.addresses.keys():
                                    if 'debug' in globals() and debug > 0:
                                        print "adding src address %s" % addrname
                                    self.policies[cur_policy].add_src(addrname,self.addresses[addrname],negated)
                                else:
                                    print "error - address %s not found" % addrname
                                if 'debug' in globals() and debug > 0:
                                    print "negating address %s" % addrname
                            else:
                                negated = False
                                addrname = self.inrec.split('\"')[5]
                                if addrname in self.addresses.keys():
                                    if 'debug' in globals() and debug > 0:
                                        print "adding src address %s" % addrname
                                    self.policies[cur_policy].add_src(addrname,self.addresses[addrname],negated)
                                else:
                                    print "error - address %s not found" % addrname
                            if self.inrec.split('\"')[7].find('!') == 0:
                                negated = True
                                addrname = self.inrec.split('\"')[7][1:]
                                if addrname in self.addresses.keys():
                                    if 'debug' in globals() and debug > 0:
                                        print "adding dst address %s" % addrname
                                    self.policies[cur_policy].add_dst(addrname,self.addresses[addrname],negated)
                                else:
                                    print "error - address %s not found" % addrname
                                if 'debug' in globals() and debug > 0:
                                    print "negating address %s" % addrname
                            else:
                                negated = False
                                addrname = self.inrec.split('\"')[7]
                                if addrname in self.addresses.keys():
                                    if 'debug' in globals() and debug > 0:
                                        print "adding dst address %s" % addrname
                                    self.policies[cur_policy].add_dst(addrname,self.addresses[addrname],negated)
                                else:
                                    print "error - address %s not found" % addrname
                            if self.inrec.split('\"')[9].find('!') == 0:
                                negated = True
                                protoname = self.inrec.split('\"')[9][1:]
                                if protoname in self.services.keys():
                                    if 'debug' in globals() and debug > 0:
                                        print "adding dst service %s" % protoname
                                    self.policies[cur_policy].add_dst_svc(protoname,self.services[protoname],negated)
                                else:
                                    print "error - service %s not found" % protoname
                                if 'debug' in globals() and debug > 0:
                                    print "negating service %s" % protoname
                            else:
                                negated = False
                                protoname = self.inrec.split('\"')[9]
                                if protoname in self.services.keys():
                                    if 'debug' in globals() and debug > 0:
                                        print "adding dst service %s" % protoname
                                    self.policies[cur_policy].add_dst_svc(protoname,self.services[protoname],negated)
                                else:
                                    print "error - service %s not found" % protoname
                            action = self.inrec.split('\"')[10].lstrip()
                            if 'debug' in globals() and debug > 0:
                                print "processing action %s" % action
                            if action.find('log') > 0:
                                if 'debug' in globals() and debug > 0:
                                    print "setting log true"
                                self.policies[cur_policy].set_log(True)
                                action = action[0:action.find(' log')]
                            else:
                                if 'debug' in globals() and debug > 0:
                                    print "setting log true"
                                self.policies[cur_policy].set_log(False)
                            if 'debug' in globals() and debug > 0:
                                print "action now %s" % action
                            if action.find('permit') >= 0:
                                if 'debug' in globals() and debug > 0:
                                    print "setting action permit"
                                self.policies[cur_policy].set_action('permit')
                            elif action.find('deny') >= 0:
                                if 'debug' in globals() and debug > 0:
                                    print "setting action deny"
                                self.policies[cur_policy].set_action('deny')
                            elif action.find('reject') >= 0:
                                if 'debug' in globals() and debug > 0:
                                    print "setting action reject"
                                self.policies[cur_policy].set_action('reject')
                            elif action.find('tunnel') >= 0:
                                if 'debug' in globals() and debug > 0:
                                    print "setting action %s" % action
                                self.policies[cur_policy].set_action(action)
                            else:
                                if 'debug' in globals() and debug > 0:
                                    print "setting action other?"
                                self.policies[cur_policy].set_action('other?')
                        else:
                            if 'debug' in globals() and debug > 0:
                                print "dropped through parsing set policy id with no match inrec:"
                                print self.inrec
                elif self.inrec.find('set src-address ') >= 0:
                    if 'debug' in globals() and debug > 0:
                        print "in set src-address with [%s]" % self.inrec
                    if self.inrec.split('\"')[1].find('!') == 0:
                        negated = True
                        src_addr =  self.inrec.split('\"')[1][1:]
                    else:
                        negated = False
                        src_addr =  self.inrec.split('\"')[1]
                    if src_addr in self.addresses.keys():
                        if 'debug' in globals() and debug > 0:
                            print "adding src_addr [%s] to policy" % src_addr
                        self.policies[cur_policy].add_src(src_addr,self.addresses[src_addr],negated)
                    else:
                        print "Error - src_addr %s not found" % src_addr
                    if negated:
                        if 'debug' in globals() and debug > 0:
                            print "negating src_addr"
                elif self.inrec.find('set dst-address ') >= 0:
                    if 'debug' in globals() and debug > 0:
                        print "in set dst-address with [%s]" % self.inrec
                    if self.inrec.split('\"')[1].find('!') == 0:
                        negated = True
                        dst_addr =  self.inrec.split('\"')[1][1:]
                    else:
                        negated = False
                        dst_addr =  self.inrec.split('\"')[1]
                    if dst_addr in self.addresses.keys():
                        if 'debug' in globals() and debug > 0:
                            print "adding dst_addr [%s] to policy" % dst_addr
                        self.policies[cur_policy].add_dst(dst_addr,self.addresses[dst_addr],negated)
                    else:
                        print "Error - dst_addr %s not found" % dst_addr
                    if negated:
                        if 'debug' in globals() and debug > 0:
                            print "negating dst_addr"
                elif self.inrec.find('set service ') >= 0:
                    if 'debug' in globals() and debug > 0:
                        print "in set service with [%s]" % self.inrec
                    if self.inrec.split('\"')[1].find('!') == 0:
                        negated = True
                        service =  self.inrec.split('\"')[1][1:]
                    else:
                        negated = False
                        service =  self.inrec.split('\"')[1]
                    if service in self.services.keys():
                        if 'debug' in globals() and debug > 0:
                            print "adding service [%s] to policy" % service
                        self.policies[cur_policy].add_dst_svc(service,self.services[service],negated)
                    else:
                        print "Error - service %s not found" % service
                    if negated:
                        if 'debug' in globals() and debug > 0:
                            print "negating service"
                else:
                    if 'debug' in globals() and debug > 0:
                        print "wtf - we didn't match anything inrec:"
                        if 'debug' in globals() and debug > 1:
                            print self.inrec
                if 'debug' in globals() and debug > 0:
                    print "bottom of method while loop - getting next record:"
                self._get_next()
                if 'debug' in globals() and debug > 1:
                    print self.inrec
        self._close_infile()
        return
    
    def parse_policy_sets(self):
        """
        Method to take the policy rules and create
        sets based on zone-from - zone-to
        """
        if 'debug' in globals() and debug > 0:
            print "parsing policy sets"
        for policynum in sorted(self.policies.keys()):
            setname = str(self.policies[policynum].from_zone.zonename)+\
                      ' to '+str(self.policies[policynum].to_zone.zonename)
            if 'debug' in globals() and debug > 0:
                print "processing policy set %s" % setname
            if setname not in self.policySets.keys():
                if 'debug' in globals() and debug > 0:
                    print "new policy set - creating object"
                self.policySets[setname] = PolicySet(self.policies[policynum].from_zone,\
                                                     self.policies[policynum].to_zone,self)
            if 'debug' in globals() and debug > 0:
                print "adding rule %d" % policynum
            self.policySets[setname].add_rule(self.policies[policynum])
        return
    
    def print_all_policySets(self):
        """
        Method to print out all policy sets
        """
        linelen = 50
        leftside = "*****"
        rightside = str(leftside)
        nl = "Policies:"
        leftspace = ((linelen-len(nl))//2) - len(leftside)
        rightspace = (((linelen-len(nl))//2) - len(leftside)) + ((linelen-len(nl))%2)
        line = leftside + " "*leftspace
        line = line + nl + " "*rightspace
        line = line + rightside
        print "="*linelen
        print line
        print "="*linelen
        for setname in sorted(self.policySets.keys()):
            self.policySets[setname].print_policy_set(2)
        linelen = 50
        print "="*linelen
        leftside = "*****"
        rightside = str(leftside)
        nl = "End "+self.filename
        leftspace = ((linelen-len(nl))//2) - len(leftside)
        rightspace = (((linelen-len(nl))//2) - len(leftside)) + ((linelen-len(nl))%2)
        line = leftside + " "*leftspace
        line = line + nl + " "*rightspace
        line = line + rightside
        print line
        print "="*linelen
        return
    
    def print_interfaces(self):
        '''Method to print the interfaces and their
        properties, including MIP mapping
        '''
        linelen = 50
        print "="*linelen
        leftside = "*****"
        rightside = str(leftside)
        nl = "Configuration file: "+self.filename
        leftspace = ((linelen-len(nl))//2) - len(leftside)
        rightspace = (((linelen-len(nl))//2) - len(leftside)) + ((linelen-len(nl))%2)
        line = leftside + " "*leftspace
        line = line + nl + " "*rightspace
        line = line + rightside
        print line
        linelen = 50
        print "="*linelen
        leftside = "     "
        rightside = str(leftside)
        nl = "Interfaces:"
        leftspace = ((linelen-len(nl))//2) - len(leftside)
        rightspace = (((linelen-len(nl))//2) - len(leftside)) + ((linelen-len(nl))%2)
        line = leftside + " "*leftspace
        line = line + nl + " "*rightspace
        line = line + rightside
        print line
        print "="*linelen
        for intf in sorted(self.interfaces.keys()):
            print
            print "[%s]" % intf
            print "IP: %s" % str(self.interfaces[intf]['ip'])
            if len(self.interfaces[intf]['ipv6']) > 0:
                for ipv6addr in sorted(self.interfaces[intf]['ipv6'].keys()):
                    print "IP: %s" % str(ipv6addr)
            print "Description: %s" % str(self.interfaces[intf]['description'])
            if len(self.mips.keys()) > 0:
                for mip in sorted(self.mips.keys()):
                    if mip in self.mipsintf.keys() and intf in self.mipsintf[mip]:
                        print ' %s  maps to %s' % (mip,self.mipstarget[mip])
            if len(self.dips.keys()) > 0:
                for dip in sorted(self.dips.keys()):
                    if dip in self.dipsintf.keys() and intf in self.dipsintf[dip]:
                        print "DIP: [%s] %s" % (dip,self.dipsdef[dip])
            if len(self.vips.keys()) > 0:
                for vip in sorted(self.vips.keys()):
                    if vip in self.vipsintf.keys() and intf in self.vipsintf[vip]:
                        print "VIP: %s[%s] maps to %s[%s]" % (vip,self.vipssrc[vip],self.vipstarget[vip],self.vipsdst[vip])
            print "MTU: %d" % int(self.interfaces[intf]['mtu'])
            print "NAT: %s" % repr(self.interfaces[intf]['nat'])
            print "Route: %s" % repr(self.interfaces[intf]['route'])
            print "Unnumbered: %s" % repr(self.interfaces[intf]['unnumbered'])
            print "Unnumbered Intf: %s" % self.interfaces[intf]['unnumbered-interface']
            print "Manage IP: %s" % self.interfaces[intf]['manage-ip']
            manage = "Not Manageable: " if self.interfaces[intf]['manageable'] else "Manageable: "
            if self.interfaces[intf]['manage-ping']: manage = manage + 'Ping ' 
            if self.interfaces[intf]['manage-snmp']: manage = manage + 'SNMP '
            if self.interfaces[intf]['manage-ssh']: manage = manage + 'SSH '
            if self.interfaces[intf]['manage-ssl']: manage = manage + 'SSL '
            if self.interfaces[intf]['manage-telnet']: manage = manage + 'TELNET '
            if len(self.interfaces[intf]['zone']) > 0:
                print "Zone: %s" % self.interfaces[intf]['zone'].zonename
        print "="*linelen
        return
    
    def print_zones(self):
        """
        Method to print out a list of all zones found
        """
        print "\nZone list:"
        
        if len(self.zones.keys()) < 1:
            print "No zones found"
        else:
            for zone in sorted(self.zones.keys()):
                print "%s" % zone
        print
        return
    
    def print_mips(self):
        """
        Method to print out MIP mappings to policy items
        """
        print
        for mip in sorted(self.mips.keys()):
            print " %s maps to %s" % (mip,self.mipstarget[mip])
            mipcheck = mip.replace("MIP","VIP")
            if mipcheck in self.vips.keys():
                print "    ***     NOTE: MIP has matching VIP"
            if len(self.mips[mip].keys()) > 0:
                for polid in sorted(self.mips[mip].keys()):
                    srcdst = self.mips[mip][polid].split('/')[0]
                    print "   Found in %s Policy ID %d" % (srcdst,polid)
        print
        return
    
    def print_vips(self):
        """
        Method to print out VIP mappings to policy items
        """
        print
        for vip in sorted(self.vips.keys()):
            print " %s[%s] maps to %s[%s]" % (vip,self.vipssrc[vip],self.vipstarget[vip],self.vipsdst[vip])
            vipcheck = vip.replace("VIP","MIP")
            if vipcheck in self.mips.keys():
                print "    ***     NOTE: VIP has matching MIP"
            if len(self.vips[vip].keys()) > 0:
                for polid in sorted(self.vips[vip].keys()):
                    srcdst = self.vips[vip][polid].split('/')[0]
                    print "   Found in %s Policy ID %d" % (srcdst,polid)
        print
        return
    
    def print_dips(self):
        """
        Method to print out DIP List
        """
        print
        for dip in sorted(self.dips.keys()):
            print " DIP [%s] maps to %s on %s" % (dip,self.dipsdef[dip],self.dipsintf[dip])
        print
        return
    
    def match_mip(self,prefix):
        """
        Method to take the existing MIP and map out a MIP in the
        new subnet, then generate the screenos commands to add that MIP 
        to the interface and to all policy items it is found in
        """
        for mip in sorted(self.mips.keys()):
            if mip.find(':') < 0:
                newmip = "MIP("+prefix+"."+mip.rsplit('.',1)[1]
                newaddr=newmip.split("(")[1].split(")")[0]
                print 
                if newmip in self.mips.keys():
                    print
                    print "*"*80
                    if mip.find(prefix)==4:
                        print "*   Existing MIP found in new target subnet!!!"
                        print "*   %s maps to %s on %s" % (mip,self.mipstarget[mip],self.mipsintf[mip])
                    else:
                        print "*   Duplicate MIP found for new target %s" % "x.x.x."+mip.rsplit('.',1)[1]
                        print "*   Existing %s maps to %s on %s" % (mip,self.mipstarget[mip],self.mipsintf[mip])
                        print "*   Existing mip in target subnet %s maps to %s on %s" % (newmip,self.mipstarget[newmip],self.mipsintf[newmip])
                        print "*   Translating mip from old subnet into new subnet would conflict with existing mip in new subnet"
                    print "*"*80
                print "set interface "+self.mipsintf[mip]+" mip "+newaddr+" host "+self.mipstarget[mip]+\
                      " netmask 255.255.255.255 vr \"trust-vr\""
                if len(self.mips[mip].keys()) > 0:
                    for polnum in sorted(self.mips[mip].keys()):
                        policy = self.mips[mip][polnum]
                        srcdst = policy.split("/")[0]
                        print "set policy id %d" % polnum
                        print "set %s-address \"MIP(%s)\"" % (srcdst,newaddr)
                        print "exit"
        return
    
    def print_addressnames(self):
        """
        Method to print out the address/address groups found
        """
        print "Address/Address Groups:"
        if len(self.addresses.keys()) < 1:
            print "No address or address groups found"
        else:
            for addr in sorted(self.addresses.keys()):
                self.addresses[addr].print_address()
                self.addresses[addr].print_duplicatelist()
        print
        return
    
    def print_services(self):
        """
        Method to print out all service/service groups
        """
        print "Service/Service Groups:"
        if len(self.services.keys()) < 1:
            print "No service/service groups found"
        else:
            for service in sorted(self.services.keys()):
                self.services[service].print_service()
        print
        return

def cmd_print_config(args):
    """
    Method to process the command line request
    """
    global debug
    debug = int(args['debug'])
    if 'debug' in globals() and debug > 0:
        pprint.pprint(args)
        for arg in args.keys():
            print "%s is %s" % (arg,str(type(args[arg])))
    filename = str(args['filename'])
    generate = str(args['generate'])
    subnet = str(args['subnet'])
    p_interfaces = str(args['interfaces'])
    p_zones = str(args['zones'])
    p_addressnames = str(args['addressnames'])
    p_services = str(args['services'])
    p_mips = str(args['mips'])
    if os.path.exists(filename):
        ns = NetScreen(filename)
        ns.print_all_policySets()
        print
        if p_interfaces.find('True') == 0:
            ns.print_interfaces()
            print
        if p_zones.find('True') == 0:
            ns.print_zones()
            print
        if p_addressnames.find('True') == 0:
            ns.print_addressnames()
            print
        if p_services.find('True') == 0:
            ns.print_services()
            print
        if p_mips.find('True') == 0:
            print "MIPS:"
            ns.print_mips()
            print "VIPS:"
            ns.print_vips()
            print
            print "DIPS:"
            ns.print_dips()
            print
        if generate.find('True') == 0:
            if len(subnet) > 0:
                if subnet.find('.') == 3:
                    sub1,sub2,sub3 = subnet.split('.')
                    subn1 = int(sub1)
                    subn2 = int(sub2)
                    subn3 = int(sub3)
                    if ((subn1 > 0) and (subn1 < 256)) and \
                       ((subn2 >=0) and (subn2 < 256)) and \
                       ((subn3 >=0) and (subn3 < 256)):
                        ns.match_mip(subnet)
                    else:
                        print "Subnet not formatted properly or invalid subnet values - should be like 10.1.50 (no trailing period)"
                else:
                    print "Subnet not formatted properly - should be like 10.1.50 (no trailing period)"
            else:
                print "Generate requires a subnet to use in the new rules"
    else:
        print "Error: file <%s> not found" % filename
    return {'args': args,ns: ns}

def main():
    
    print_parser = argparse.ArgumentParser(description=\
             'Analyze screenos firewall configuration file')
    
    print_parser.add_argument('filename',action='store',\
                    help='Name of configuration file to parse',\
                    nargs=1)
    print_parser.set_defaults(func=cmd_print_config)
    print_parser.add_argument('-debug', action='store', type = int, default=0,\
                    dest='debug', help='Debug level 0-9')
    print_parser.add_argument('-g', action='store_true', default = False,\
                    dest='generate', help='Generate new rules for new subnet (see -n)')
    print_parser.add_argument('-n', action='store', dest='subnet',\
                    help='(See -g) New subnet e.g. 10.1.50 (no end period)')
    print_parser.add_argument('-i', action='store_true', default = False,\
                    dest='interfaces', help='Print interface information')
    print_parser.add_argument('-z', action='store_true', default = False,\
                    dest='zones', help='Print zone information')
    print_parser.add_argument('-a', action='store_true', default = False,\
                    dest='addressnames', help='Print address/address group information')
    print_parser.add_argument('-s', action='store_true', default = False,\
                    dest='services', help='Print service/service group information')
    print_parser.add_argument('-m', action='store_true', default = False,\
                    dest='mips', help='Print mips/vips/dips list')
    cl = {}
    results = {}
    args = {}
    try:
        cl=print_parser.parse_args()
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
    return {'parser': print_parser,'cl': cl,'args': args,'results': results}

if __name__ == "__main__":
    session = main()
