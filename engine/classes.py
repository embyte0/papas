#!/usr/bin/env python2.7

# Copyright (C) 2010-2021 Marco `embyte` Balduzzi
# This file is part of PAPAS.
#
# PAPAS is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# PAPAS is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Nome-Programma.  If not, see <http://www.gnu.org/licenses/>.

######################################################
#   PAPAS, the PArameter Pollution Analysis System   #
#                                                    #
#   https://github.com/embyte0/papas                 #
#                                   embyte (c) 2010  #
######################################################


import socket, time, re, sys
import urlparse

import log
import html

###########
# globals #
###########
HTTPCONNECTION_TIMEOUT = 10

###########
# classes #
###########

# network class
class net:
    def __init__(self, host, port):
        self.server = host
        self.server_port = port
        print "* Connecting to %s:%d..."%(self.server, self.server_port),
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.settimeout(HTTPCONNECTION_TIMEOUT);  

    def connect(self):
        if self.s.connect_ex((self.server, self.server_port)) == 0:
            print "ok"
        else:
            print "failed"
            return -1        
            
    def kill(self):
        self.s.close()
        
    def send(self, what):    
        if self.s.sendall(what)!=None:
            log.myprint("Error in sending data to xul " + what)
        
    # -1 error
    # -2 redirect
    def send_and_receive(self, what, ignore_redirect=False):
        if self.s.sendall(what)!=None:
            log.myprint( "! Error in sending data to xul " + what)
            return -1
            
        else:
            readData = ""            
            while True:
                try:                
                    data = self.s.recv(1024)
                    readData += data
                except socket.timeout:
                    log.myprint("!Timeout for " + what)                                        
                    return -1
                
                # here we use --EOF-- as delimiter to understand when server has finished to send data
                if readData[-7:] == '--EOF--': 
                    break

            # we implement the redirect check here to speed up
            page_url = re.search('URL:([^\|]+)\|', readData, re.M).group(1)
            if page_url!=what and ignore_redirect==False:
                log.myprint( "!Redirect: %s -> %s"%(what, page_url))
                return -1 
                
            return readData


# a form
class form:
    def __init__(self, form_id, action, method):
        self.form_id = form_id
        self.action = action
        self.method = method
        self.l_inputs = []

    def add_input(self, _type, _name, _value):
        self.l_inputs.append((_type, _name, _value)) 

    # TODO: to verify!!
    def to_string(self):
        ret = ""
        for i in self.l_inputs:
            _type = i[0]
            _name = i[1]
            _value = i[2]

            if _name=="":   # a limitation? if there is no name continue with the next param
                continue
            elif _type=="text" and re.match("e-?mail$", _name, re.I):
                _value = "hpp@iseclab.org"
            elif _type=="password" or re.match("pass(word)?$", _name, re.I) or re.match("passwd$", _name, re.I):
                _value = "aXsdP1j2"
            elif _value == "":
                _value = "foo"      # int or string?? mhhh
                
            ret+= _name + "=" + _value + "&"

        return ret

    def myprint(self):
        log.myprint( "form_id=%s action=%s method=%s"%(self.form_id, self.action, self.method))
        for i in self.l_inputs: log.myprint( "type=%s name=%s value=%s"%(i[0], i[1], i[2]))
        

# an instance of a page
class instance:
    def __init__(self, l_links, l_forms, body, precedence):
        self.l_links = l_links
        self.l_forms = l_forms
        self.body = body
        self.precedence = precedence
        self.vulnerable = False

# a single page
class page:
    def __init__(self, baseurl):
        self.baseurl = baseurl          # http://www.site.com/page.php
        self.d_instances = {}           # dict of instances
    
    def add_instance(self, params, l_links, l_forms, body, precedence):
        if params in self.d_instances:   # a page with this instance is already present
            return -1
        i = instance(l_links, l_forms, body, precedence)
        self.d_instances[params] = i
        
    def set_vulnerable(self, params):
        i = self.d_instances[params]
        i.vulnerable = True
        
    def get_instances(self):
        return self.d_instances
        
    def has_instance(self, params):
        if params in self.d_instances.keys():
            return True
              
    # return the list of all the parameter supposed to be accepted by that page as a dictionary of keys=paramname, value
    def get_params(self):
        d_params = {}
        for params in self.d_instances.keys():
            for m in re.finditer('([^&=]+)=([^&]*)', params):        
                name = m.group(1)
                value = m.group(2) 
                if name not in d_params: d_params[name]=value
        return d_params


# a site
class site:
    def __init__(self, homepage):
        self.homepage = homepage
        self.d_baseurls = {}            # the dict of pages
        self.vulnerable = []            # the vulnerable pages
        
        self.stats = {}                 # handle the stats on the site
        self.stats[-1]=[]
        self.stats[0]=[]
        self.stats[1]=[]
        self.stats[2]=[]
        self.stats[4]=[]
        
    def add_page(self, baseurl, params, l_links, l_forms, body, precedence):
        if baseurl in self.d_baseurls:  
            p = self.d_baseurls[baseurl]
            if p.add_instance(params, l_links, l_forms, body, precedence) == -1:   # return -1 if the same instance is present (duplicate page and instance)
                log.myprint( "D! page with this instance already present")
                return -1
        else:
            p = page(baseurl)           # add a new page
            p.add_instance(params, l_links, l_forms, body, precedence)
            self.d_baseurls[baseurl] = p

    def get_pages(self):
        return self.d_baseurls
        
    def get_name(self):
        return self.homepage
    
    def set_beginTime(self, beginTime):
        self.beginTime = beginTime
    def get_beginTime(self):
        return self.beginTime
        
    def has_page(self, url):
        t = urlparse.urlsplit(url)
        baseurl = t[0]+'://'+t[1]+t[2]
        params = t[3]
        if baseurl in self.d_baseurls:
            p = self.d_baseurls[baseurl]
            if p.has_instance(params):
                return True
        return False
            
        
    def get_n_instances(self, baseurl):
        try:
            page = self.d_baseurls[baseurl]
        except KeyError:
            return 0
            
        return len(page.get_instances())

    def update_stats(self, retval, fullurl):
        self.stats[retval].append(fullurl)
    
    def set_instance_as_vulnerable(self, baseurl, params):    
        p = self.d_baseurls[baseurl]
        p.set_vulnerable(params)
        
    #
    def add_vulnerable_page(self, baseurl, inj_type, inj_fullurl):
        self.vulnerable.append((baseurl, inj_type, inj_fullurl))
        
        
    def print_stats(self):
        log.myprint("")
        log.myprint("-------------------- SUMMARY --------------------------------")
        log.myprint( "Site %s [scanned in %d secs.]"%(self.homepage, int(time.time()-self.get_beginTime())))
        log.myprint("")
        
        log.myprint( "# crawled           %d"%len(self.stats[0]))
        log.myprint( "# P/V-scan analyzed %d"%len(self.d_baseurls))

        log.myprint("")
        
        log.myprint( "# vulnerable      %d"%len(self.stats[1]))
        log.myprint( "# duplicated      %d"%len(self.stats[2]))
        log.myprint( "# skipped         %d"%len(self.stats[4]))
        log.myprint( "# error           %d"%len(self.stats[-1]))

        log.myprint("")
        log.myprint("Details on the SCAN:")
        
        self.print_pages_stats()                    # cycle each page 
        
    def get_html_stats(self):
        summary = html.add_section("Summary", (
                                  ("Scan time","%s sec(s)"%int(time.time()-self.get_beginTime())), ("Crawled",len(self.stats[0])), 
                                  ("P/V-scan analyzed",len(self.d_baseurls)), ("Vulnerable",len(self.stats[1])), 
                                  ("Duplicated",len(self.stats[2])), ("Skipped",len(self.stats[4])), 
                                  ("Error",len(self.stats[-1])))
        )
        
        return summary
     
     
    def get_html_vulnerable(self):
        vulnerable = html.add_vuln_section("Vulnerable Pages", [(page[0], page[1], page[2]) for page in self.vulnerable])       
        return vulnerable


    def get_html_precedence(self):
        rows = []
        for p in self.d_baseurls.values():
            once = True 
            for params,instance in p.d_instances.items():
                if params != "":    
                    if once == True:
                        rows.append((p.baseurl,"%d instance(s)"%len(p.d_instances)))    # the title
                        once = False
                        
                    if instance.precedence=="-1" or instance.precedence=="-3":
                        rows.append(("<i>&nbsp;&nbsp;&nbsp;?%s<i>"%params[:128], "<i>NaN</i>"))
                    else:
                        rows.append(("<i>&nbsp;&nbsp;&nbsp;?%s<i>"%params[:128], "<i>%s</i>"%instance.precedence))                    
#                else:               
#                    rows.append(("&nbsp;&nbsp;&nbsp;no parameters", ""))

        precedence = html.add_fixedsize_section("Precedence Logs (only URLs with parameters are shown)", rows)        
        return precedence

        
    def print_pages_stats(self):
        for p in self.d_baseurls.values():
            log.myprint("")
            log.myprint( "page baseurl : %s"%p.baseurl)
            log.myprint( "parameters   : %s"%p.get_params())
            log.myprint( "instances    : %d"%len(p.d_instances))
                                
            i=1
            for params,instance in p.d_instances.items():
                log.myprint( " %d p[:30]:%s #l:%d #f:%d length:%dB precedence:%s vulnerable:%s"%(i, params[:30], len(instance.l_links), len(instance.l_forms), len(instance.body), instance.precedence, instance.vulnerable))
                i+=1
        
    # TODO FINISH!! i.precedence should always be a string!
    def get_global_prec(self):
        l_precs = []
        for p in self.d_baseurls.values():
            for i in p.d_instances.values():
                if i.precedence.find('-1')==0:
                    l_precs.append('-1')
                elif i.precedence.find('-3')==0:
                    l_precs.append('-3')
                elif i.precedence.find('a ')==0:
                    l_precs.append('a')
                elif i.precedence.find('b ')==0:
                    l_precs.append('b')
                elif i.precedence.find('v1 v2')==0 or i.precedence.find('v1v2')==0 or i.precedence.find('v1.v2')==0:
                    l_precs.append('both')
                elif i.precedence.find('error_')==0:
                    l_precs.append('e')

        l_precs = set(l_precs)                    
        l_ret = []

        if 'e' in l_precs:  
            l_ret.append('e')
        
        if 'a' in l_precs:
            if 'b' in l_precs:    
                l_ret.append('?')
            elif 'both' in l_precs: 
                l_ret.append('?')
            else:
                l_ret.append('a')
        
        elif 'b' in l_precs:
            if 'both' in l_precs: 
                l_ret.append('?')
            else:
                l_ret.append('b')
        
        elif 'both' in l_precs: 
            l_ret.append('both')        
        
        elif '-1' in l_precs: 
            l_ret.append('-1')
        
        elif '-3' in l_precs: 
            l_ret.append('-3')
        
        else:    
            l_ret.append('-2')
        
        return l_ret
