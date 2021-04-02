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

from optparse import OptionParser
import sys, time, re, os
import urlparse
import random
import pickle   # serialization libary  
import traceback    # logging catched exceptions
import difflib
import urllib

import smtplib
from email.mime.text import MIMEText   # prepare the mail syntax


from time import localtime, strftime

from classes import *
import log
import sqlerrors

import html     # for the report

import pg       # for connecting to the PAPAS database

###########
# globals #
###########
APPNAME="PAPAS"
APPVERSION="1.0.2"
FFX_HOST="127.0.0.1"

MAXINSTANCES=5
MAXINJ=50
MAXTIMESITE=3600            # max n sec. per site

DATADIR="data"
DATADIR_HTML="/var/www/reports/"
LOGFILE_PROBER="prober.log"
ERRORFILE_PROBER="prober.err"

STDOUT="papas.stdout.log"
STDERR="papas.stderr.log"

# credentials for emailing communications, in enabled
MAIL = { "user":"USER_NAME_HERE",
         "passwd":"PASSWORD_HERE" }

d_sites = {}          # the visited sites
d_baseurls = {}       # the dict of the baseurls (e.g. http://www.sites.com/page.php)
l_trash = []          # pages we dont want (cannot) test -- this is also to prevent loops
d_already_tested = {} # pages with parameters (url+inpage) already tested

site_is_vulnerable = False


#############
# functions #
#############


# return the first level domain
def __get_fld(d):
    l_d = d.split('.')
    if len(l_d) >= 2:
        return l_d[-2]+'.'+l_d[-1]
    else:
        return d
    

def __escape_regexp_char(s):
    s = s.replace('.','\.')
    s = s.replace('^','\^')
    s = s.replace('$','\$')
    s = s.replace('*','\*')
    s = s.replace('+','\+') 
    s = s. replace('?','\?')
    s = s. replace('{','\{')
    s = s. replace('}','\}')
    s = s. replace('[','\[')
    s = s. replace(']','\]')
    s = s. replace('(','\(')
    s = s. replace(')','\)')
    s = s. replace('|','\|')    
    return s    
    


# called from check_url_precedence()
# upon an injection with doubled parameters, analyze the body to detect errors on the databse backend,
# how the parameters appear, etc...
# p=parameter name, v1=first value, v2=second value
def __parse_body(body, v1, v2):
    v1 = __escape_regexp_char(v1.lower())
    v2 = __escape_regexp_char(v2.lower())

    regexp = "[^a-zA-Z0-9]%s %s[^a-zA-Z0-9]"%(v1,v2)
    if re.search(regexp, body, re.M):
        return "v1 v2"

    regexp = "[^a-zA-Z0-9]%s%s[^a-zA-Z0-9]"%(v1,v2)
    if re.search(regexp, body, re.M):
        return "v1v2"

    regexp = "[^a-zA-Z0-9]%s[^<>=]{1,5}%s[^a-zA-Z0-9]"%(v1,v2)      # the {1,5} should remove the FP
    m = re.search(regexp, body, re.M)
    if m != None:
        print m.group(0)
        return "v1.v2"
        
    if re.search('<input.*?value="?array.*?>', body, re.M):
        return "v1.v2"
        

    # error tests
    return sqlerrors.check(body)
    


# stripout the HTML body (e.g. javascript code, images and comments)
def strip_html(data):

    # 
    data = re.sub("\t", '', data)   

    # (?i) is:
    # Case insensitive Python regular expression without re.compile 
    # http://stackoverflow.com/questions/500864/case-insensitive-python-regular-expression-without-re-compile

    # the ? is the non-greedy version of .*
    data = re.sub('(?is)<!--.*?-->', '', data)
    data = re.sub('(?is)<img .*?>', '', data)
    data = re.sub('(?is)<embed.*?>', '', data)
    data = re.sub('(?is)<style.*?</style>', '', data)    # inline style
    data = re.sub('(?is)<iframe.*?</iframe>', '', data)
    data = re.sub('(?is)<object.*?</object>', '', data)        
    data = re.sub('(?is)<noscript.*?</noscript>', '', data)    
    data = re.sub('(?is)<script.*?</script>', '', data)
    data = re.sub('(?is)action="[^"]+"', '', data)       # the form action often point to the page itself   

    data = re.sub('(?i)<span.*?></span>', '', data)   # <SPAN> without content
    data = re.sub('(?i)<div.*?></div>', '', data)     # <DIV>  without content    

    data = re.sub('(?i)[\d\.,]+ (sec|min)', '', data)     # timing stuff 
       
    # for checking the precedence we go to lowercase
    return data.lower()
    
    
        
# check the parameter precendece for a NEW page (given its full URL)
# -1 I was not able to detect one
# -2 skipped: page cannot be test since does not have parameters
# -3 broken page
def check_url_precedence(url):
    broken_page = False         # TEST: we introduce this to discriminate pages where a change to the parameters value does not modify the answer
    t = urlparse.urlsplit(url)
    baseurl = t[0]+'://'+t[1]+t[2]
    params = t[3]

    # if URL does not have params, we return
    if params == "":
        return "-2"
    print "url_precedence() ",
    sys.stdout.flush()

    u1 = baseurl + "?" + params  
    recvData = netObj.send_and_receive(u1)
    if recvData == -1:
        return "-1"
    body1 = recvData[recvData.find("BODY:")+5:recvData.find("--EOF--")]
    body1 = strip_html(body1)
    sys.stdout.flush()
    
    ### DEBUG CODE
    #f = open("body1.html", "w")
    #f.write(body1)
    #f.close()
    ###

    for m in re.finditer('([^&=]+)=([^&$]*)', params):
        print ". ",    
        name = m.group(1)
        value = m.group(2)
        if value == "": value="bar"  # for empty values, use bar
        
        #we dont need anymore the strip since we work with str.replace() below
        #value = re.sub('[\^\$\*\+\?\{\}\\\[\]\(\)\|]','', value)         # strip from value the regexp stuff

        if value == "":
            new_value="foo"
        elif value.isdigit(): 
            new_value=str(int(value)+1)
        else:
            new_value="ab"+value[2:]
        # test: let's put a minimum of 3 char
        if len(new_value)==1: new_value+="99"
        elif len(new_value)==2: new_value+="9"
        
        u2 = baseurl + "?" + params.replace("%s=%s"%(name,value), "%s=%s"%(name,new_value))
        recvData = netObj.send_and_receive(u2)
        if recvData == -1:
            continue    # error - try next parameter
        body2 = recvData[recvData.find("BODY:")+5:recvData.find("--EOF--")]      
        body2 = strip_html(body2)
        sys.stdout.flush()
        
        ### DEBUG CODE
        #f = open("body2.html", "w")
        #f.write(body2)
        #f.close()
        ###
            
        u_after = baseurl + "?" + params.replace("%s=%s"%(name,value), "%s=%s&%s=%s"%(name, value, name, new_value))
        recvData = netObj.send_and_receive(u_after)
        if recvData == -1:
            continue    # error - try next parameter
        body_both = recvData[recvData.find("BODY:")+5:recvData.find("--EOF--")]             
        body_both = strip_html(body_both)
        sys.stdout.flush()
        
        ### DEBUG CODE
        #f = open("body_both.html", "w")
        #f.write(body_both)
        #f.close()
        ###

        if body1==body2==body_both:    # broken page with _this_ parameter
            broken_page = True
        elif body1==body_both and body2!=body_both:
            return "b [%s = %s -> %s]"%(name, value, new_value)
        elif body1!=body_both and body2==body_both:
            return "a [%s = %s -> %s]"%(name, value, new_value)
        else:
            precedence = __parse_body(body_both, value, new_value)   # check sql error, both terms, etc..
            if precedence != "-1":
                return "%s [%s = %s -> %s]"%(precedence, name, value, new_value)
            else:
                # here we use this heuristic
                b = difflib.SequenceMatcher (None, body_both, body1)
                a = difflib.SequenceMatcher (None, body_both, body2)
                b_ratio = b.ratio()
                a_ratio = a.ratio()               
                print "(ratio: b[%.2f] a[%.2f])"%(b_ratio, a_ratio),                
                if abs(a_ratio-b_ratio)>0.05:
                    if b_ratio>a_ratio and b_ratio>=0.75:
                            return "b [%s = %s -> %s]"%(name, value, new_value)
                    if a_ratio>b_ratio and a_ratio>=0.75:
                            return "a [%s = %s -> %s]"%(name, value, new_value)
            broken_page = False
                    
    # END
    if broken_page:
        return "-3"       
    else:
        return "-1"    # this is in case we didn't manage to detect one    
    
    

# parse the data coming from Firefox's XUL plugin
# site_domains of * disable the same domain check
# for default only parse parametrized_links
def parse(recvData, site_domain, only_parametrized_links=True):
    if len(recvData) == 0:
        return ("", "", None, None, "")

    # delimiter is | as per our conventions
    try:
        url = re.search('URL:([^\|]+)\|', recvData, re.M).group(1)        
        t = urlparse.urlsplit(url)
        baseurl = t[0]+'://'+t[1]+t[2]
        params = t[3]

        s_links = re.search('LINKS:([^\|]*)\|', recvData, re.M).group(1)
        l_links = []
        for m in re.finditer('<a href="([^"]+)">', s_links):           
            l = m.group(1)
                      
            # We moved this check from the plugin to HERE
            # TODO> maybe add a limiter to the links?
            if only_parametrized_links==True and not urlparse.urlparse(l).query:    
                continue    # filter on parametrized link:
            
            # only consider links starting from the root URL (that one specified by the user to scan)
            k = urlparse.urlsplit(l)
            
            if site_domain == "*":                      # every domain
                l_links.append(l)
            elif l.startswith(site_domain):             # absolute link
                l_links.append(l)
            elif k[0]=="" and k[1]=="" and k[2]!="":    #relative link 
                l_links.append(l)
                    
        s_forms = re.search('FORMS:([^\|]*)\|', recvData, re.M).group(1)
        l_forms = []
        for m1 in re.finditer('<form id="([^"]*)" action="([^"]*)" method="([^"]*)">(.*?)</form>', s_forms):
            form_id = m1.group(1)
            if form_id == "":   form_id = "NaN"  # noname form          
            action = m1.group(2)
            if action == "":    action = url    # if action is not set, its the same page (html reference)
            method = m1.group(3).lower()        # ->lowercase
            if method == "":    method = "get"  # default method is get
            s_inputs = m1.group(4)

            f = form(form_id, action, method)
            
            for m2 in re.finditer('<input type="([^"]*)" name="([^"]*)" value="([^"]*)">', s_inputs):         
                _type = m2.group(1)
                _name = m2.group(2)
                _value = m2.group(3).replace(' ', '+')      # we dont want to have spaces in the form inputs'name
                f.add_input(_type, _name, _value)
            #DEBUG
            #f.myprint()   # print form
            l_forms.append(f)

    except TypeError:
        log.myprint("! typeError: %s"%recvData)
        return ("", "", None, None, "")

    body = recvData[recvData.find("BODY:")+5:recvData.find("--EOF--")]
    body = strip_html(body)
    

    #DEBUG
    # print l_links,l_forms
    
    return (baseurl, params, l_links, l_forms, body)
  


  
# given the list of links and forms (contained in a page), this returns a dictionary of all the parameters
# for which try the injection (+ possible values taken from the already seen page)
def unique_contained_data(l_links, forms):            
    d_ret = {}
    
    for url in l_links:
        t = urlparse.urlsplit(url)
        params = t[3]
               
        for m in re.finditer('([^&=]+)=([^&$]*)', params):
            name = m.group(1)
            value = m.group(2)
            
            if name in d_ret:
                if value not in d_ret[name]:
                    d_ret[name].append(value)            
            else:
                d_ret[name] = []
                d_ret[name].append(value)
   
    #TODO .. left as future work:
    #for f in forms:
    return d_ret





# check injection on page results
#
# tests: 
# 1. check the injection by regexp on links and forms
# 2. very we didnt have the match _already_ in the inital page
# 3. cross-check: 
#     a) veriry that the decoded version query (%26 -> &) does not produce an injection <- this should low down the false-positives
#     b) the parameter is not used to build a link
def check_injection(recvData, p, orig_value, v, l_orig_links, l_orig_forms, cross_check_query):
    
    # the "*" means to NOT check the domain
    (baseurl, params, l_links, l_forms, body) = parse(recvData, "*")           # parse the page content

    try:
        my_regexp = "(^|&)%s=%s(&|$)"%(p,v)
        for l in l_links:
            linkparams = urlparse.urlsplit(l)[3]
            if re.search(my_regexp, linkparams):   # injection on the link parameters
                if l not in l_orig_links:   # the result of the injection (the link) should not have been already present                    
                    
                    ############# cross-check block ##############
                    if orig_value!=None and l.startswith(urllib.unquote(orig_value))==True:      # B
                        log.myprint( "  D! FP injection on link thanks to startswith:%s"%l) 
                        return (False, None)

                    d = netObj.send_and_receive(cross_check_query)              # A
                    if d!=-1:
                        inj_links = parse(d, "*")[2]
                        if l in inj_links:
                            log.myprint( "  D! FP injection on link by cross-checking with the decoded version:%s"%l) 
                            return (False, None)
                    #############################################                                    
                    
                    return (True, "Link: href=%s"%l)
        
        
        # TODO : implement the check on l_orig_forms
        my_regexp = "(^|&)%s=%s(&|$)"%(p,v)
        for f in l_forms:
            if re.search(my_regexp, f.action):  # injection on the action
                
                ############# cross-check block ##############
                d = netObj.send_and_receive(cross_check_query)
                if d!=-1:
                    inj_forms = parse(d, "*")[3]
                    for jf in inj_forms:
                        if re.search(my_regexp, jf.action):
                            log.myprint( "  D! FP injection on action:%s of form_id:%s"%(f.action, f.form_id))
                            return (False, None)
                #############################################            
                    
                return (True, "Form: id=%s, action=%s"%(f.form_id, f.action))


            for i in f.l_inputs:                # injection on the inputs
                if i[0]=="hidden" and re.search (my_regexp, i[2]):      # check injection on hidden fields

                    ############# cross-check block ##############
                    d = netObj.send_and_receive(cross_check_query)
                    if d!=-1:
                        inj_forms = parse(d, "*")[3]
                        for jf in inj_forms:
                            for jf_i in jf.l_inputs:
                                if i[0]=="hidden" and re.search (my_regexp, jf_i[2]):
                                    log.myprint( "  D! FP injection on hidden input field:%s=%s of form_id:%s"%(i[1], i[2], f.form_id))
                                    return (False, None)
                    #############################################                                    

                    return (True, "Form: id=%s, hidden-field=%s, value=%s"%(f.form_id, i[1], i[2]))

    except Exception, e:
        f = open(ERRORFILE_PROBER, 'a')
        f.write('-'*60 + '\n')
        traceback.print_exc(file=f)
        f.close()
        return (False, None)

    return (False, None)
    
    

# this is used to verify that we have already tested a similar page
# e.g.:                ['storytopic'] ['categoryid', 'uid', 'cat', 'start', 'storytopic', 'storyid', 'id'] 
#       is a subset of ['storytopic'] ['categoryid', 'uid', 'cat', 'storytopic', 'storyid', 'id']
def check_params_inclusion(this_page_par, l_l_past):

    for l_par in l_l_past:          # go through the old pages
        n_saw = 0
        
        for p in this_page_par:     # check if all the params have been already saw
            if p in l_par:
                n_saw +=1           # add 1 every time the par has been saw in the current list
                
        if n_saw == len(this_page_par):
            return True
            
    return False
    
        
        
# check if a page with that specific occurance has been already tested
# we consider the baseurl + s_params (only parameters) e d_inpage_params (only parameters)
def check_already_killed (baseurl, s_params, d_inpage_params):
    l_url_parnames = re.findall('([^&=]+)=[^&]+', s_params)
    l_page_parnames = d_inpage_params.keys()
    
    #print baseurl, l_url_parnames, l_page_parnames #DEBUG
    try:
        v = d_already_tested[baseurl + str(l_url_parnames)]
        if not check_params_inclusion(l_page_parnames, v): v.append(l_page_parnames)
        else: return True
    except KeyError:
        d_already_tested[baseurl + str(l_url_parnames)] = []
        d_already_tested[baseurl + str(l_url_parnames)].append(l_page_parnames)
        
    return False
        
        
    
## define the injected value from the original value of the parameter
## (usually this one come from a random() on the list of all the values associated to that param)
## see kill_the_beast()
#def get_value_toinject(seed):
#    new_value = "foolab"  # default tested keyword
#
#    if seed.isdigit():        # a random number of the same length
#        l = len(seed)
#        new_value = str(random.randint (10**(l-1), 10**l-1))
#    else:
#        new_value = "xa" + seed[2:]   
#    
#    # test: let's put a minimum of 3 char
#    if len(new_value)==1: 
#        new_value+="99"
#    elif len(new_value)==2: 
#        new_value+="9"
#    
#    return new_value    
    
        
# go with injection
def kill_the_beast (baseurl, s_params, d_inpage_params, precedence, site):
    n_inj = 0  # this is to limit the injections to MAXINJ
    
    if check_already_killed(baseurl, s_params, d_inpage_params):
        return False
     
    log.myprint( " Injecting on page baseurl : %s"%baseurl)
    log.myprint( "   s_params                : %s"%s_params)
    log.myprint( "   d_inpage_params.keys()  : %s"%d_inpage_params.keys())
    log.myprint( "   predence                : %s"%precedence)
    
    # save the original page for comparing the results (check that the injected parameter was not already present)
    recvData = netObj.send_and_receive(baseurl + "?" + s_params)
    if recvData == -1:
        return False
    (foo1, foo2, l_orig_links, l_orig_forms, foo3) = parse(recvData, "*")           # parse the page content        
    
    tokenized_s_params = re.findall('([^&=]+)=([^&]*)', s_params)

    # we try to inject "%26foo%3Dbar"
    inj_param = "foo"
    inj_value = "bar"

    # base injection: inject on s_params that are in d_inpage
    log.myprint( " Running base injection")
    for p,v in tokenized_s_params:     # inject on each param   
        if p in d_inpage_params.keys():            
            if n_inj>MAXINJ: 
                return False
            else: 
                n_inj+=1
                   
            inj_v = v + "%26" + inj_param + "%3D" + inj_value 
            query  = baseurl + "?" + s_params.replace("%s=%s"%(p,v), "%s=%s"%(p,inj_v))
            log.myprint( "  D! " + s_params + " -> " + query)
                        
            recvData = netObj.send_and_receive(query)
            if recvData == -1: 
                continue

            # the cross_check query is to screen out the false positives -- that is we check that the parameter does _not_ appear when we use the decoded version
            cross_check_inj_v = v + "&" + inj_param + "=" + inj_value
            cross_check_query  = baseurl + "?" + s_params.replace("%s=%s"%(p,v), "%s=%s"%(p,cross_check_inj_v)) 
            ret = check_injection(recvData, inj_param, v, inj_value, l_orig_links, l_orig_forms, cross_check_query)
            if ret[0] == True:
                log.myprint("Found injection on " + ret[1])
                site.add_vulnerable_page(baseurl, ret[1], query)
                return True
                
    # simple injection: inject on s_params that are NOT in d_inpage
    log.myprint( " Running simple injection")
    for p,v in tokenized_s_params:     # inject on each param
        if p not in d_inpage_params.keys():
            if n_inj>MAXINJ: 
                return False
            else: 
                n_inj+=1
            
            inj_v = v + "%26" + inj_param + "%3D" + inj_value 
            query  = baseurl + "?" +  s_params.replace("%s=%s"%(p,v), "%s=%s"%(p,inj_v))
            log.myprint( "  D! " + s_params + " -> " + query)
                        
            recvData = netObj.send_and_receive(query)
            if recvData == -1:
                continue
                
            # the cross_check query is to screen out the false positives -- that is we check that the parameter does _not_ appear when we use the decoded version
            cross_check_inj_v = v + "&" + inj_param + "=" + inj_value
            cross_check_query  = baseurl + "?" + s_params.replace("%s=%s"%(p,v), "%s=%s"%(p,cross_check_inj_v))                 
            ret = check_injection(recvData, inj_param, v, inj_value, l_orig_links, l_orig_forms, cross_check_query)
            if ret[0] == True: 
                log.myprint("Found injection on " + ret[1])            
                site.add_vulnerable_page(baseurl, ret[1], query)            
                return True

    # guessed injection. guess possible parameters adding new params from the body             
    if extensiveMode == True:
        log.myprint( " Running guessed injection")
        for new_param, new_l_values in d_inpage_params.items():
            if s_params.find("%s="%new_param) != -1: 
                continue  # we want to add new params

            if n_inj>MAXINJ: 
                return False
            else: 
                n_inj+=1
            
            g_params = s_params + "&" + new_param + "=" + random.choice(new_l_values)  # http://www.foo.it?existing=value&new=value
            query  = baseurl + "?" + g_params + "%26" + inj_param + "%3D" + inj_value
            log.myprint( "  D! " + s_params + " -> " + query)
            
            recvData = netObj.send_and_receive(query)
            if recvData == -1: 
                continue

            # the cross_check query is to screen out the false positives -- that is we check that the parameter does _not_ appear when we use the decoded version
            cross_check_query  = baseurl + "?" + g_params + "&" + inj_param + "=" + inj_value                 
            ret = check_injection(recvData, inj_param, None, inj_value, l_orig_links, l_orig_forms, cross_check_query)
            if ret[0] == True:
                log.myprint("Found injection on " + ret[1])            
                site.add_vulnerable_page(baseurl, ret[1], query)
                return True

    return False


# we want to submit forms to the same FIRST LEVEL domain (tradeoff between don't have a check, or consider the whole domain tree)
def submit_form(f, site_domain):
    action = f.action
    action_domain = urlparse.urlsplit(action)[1]    
    
    if __get_fld(action_domain) == __get_fld(site_domain):
        method = f.method
        postString = f.to_string()
        log.myprint("Posting form %s to %s [%s]"%(f.form_id, action, method))
        
        
        if method=="post":
            recvData = netObj.send_and_receive(action+" "+postString, True)      # my XUL accepts the data to post with a white space syntax -- ignore Redirect enabled
        elif method=="get":       
            if action.find("?") == -1:                                           # in this case we post the data as GET on the action
                recvData = netObj.send_and_receive(action+"?"+postString)        # action does _not_ contain other parameters
            else:
                recvData = netObj.send_and_receive(action+"&"+postString)        # action contains already other parameters
        else:
            return -1
            
        return recvData

    else:
        log.myprint("Skipping cross-domain posting: %s -> %s"%(site_domain, action_domain))
        return 4

    
# the main crawling routine, called recursively
#
# retcode :
# 1 vulnerable page
# 0 not vulnerable page
# -1 error in testing the page (timeout, redirection..)
# 
# 2 page already tested
# 4 page skipped for limiting (MAXINSTANCES, TIME...)
#
#
#def _firstlevel_stat_fix(url, code, site, deep_level):      #nb.  This is a dirty shortcut, but we keep it as this since we already began the experiments
#    if deep_level == 0:
#        site.update_stats(code, url) 


# site_name = original name given from user
# site = a site object           
def crawl(site_name, url, form, site, deep_level):
    global site_is_vulnerable

    site.update_stats(0, url)
    
    # MAXTIMESITE
    if time.time()-site.get_beginTime() > MAXTIMESITE:
        log.myprint("!Hit the MAXTIMESITE")
        site.update_stats(4, url)        
        return 4
     
    # the SLEEP TIME
    if SLEEP_TIME!=0:
        time.sleep(SLEEP_TIME)
        
    site_domain = urlparse.urlsplit(site.get_name())[1]    
    log.myprint("")    
    
    # submit a form 
    if url==None and form!=None:        
        recvData = submit_form(form, site_domain)
        if recvData == -1 or recvData == 4:
            site.update_stats(recvData, url)
            return recvData
        url = re.search('URL:([^\|]+)\|', recvData, re.M).group(1)

        # check if the returned page is in the scope
        if url.startswith(site_name) == True:
            log.myprint("Analyzing %s [%d level]"%(url, deep_level))
        else:
            log.myprint("Skipping redirect in post to %s"%url)
            site.update_stats(4, url)
            return -1            
        
        # check if we already scanned this page+instance
        if site.has_page(url) or url in l_trash:
            log.myprint( "Duplicated page")
            site.update_stats(2, url)
            return 2

        # limit the scan of a single page to MAXINSTANCES
        t = urlparse.urlsplit(url)
        baseurl = t[0]+'://'+t[1]+t[2]    
        if site.get_n_instances(baseurl) >= MAXINSTANCES:
            log.myprint( "Skipped: Hit the MAXINSTANCES (%d) for page %s"%(MAXINSTANCES, baseurl))
            site.update_stats(4, url)            
            return 4
                    
    # visit a link
    elif url!=None and form==None:    
        log.myprint( "Visiting %s [%d level]"%(url, deep_level))        
        
        # check if we already scanned this page+instance
        if site.has_page(url) or url in l_trash:
            log.myprint( "Duplicated page %s [%d level]"%(url, deep_level))
            site.update_stats(2, url)            
            return 2

        # limit the scan of a single page to MAXINSTANCES
        t = urlparse.urlsplit(url)
        baseurl = t[0]+'://'+t[1]+t[2]    
        if site.get_n_instances(baseurl) >= MAXINSTANCES:
            log.myprint( "Skipped: Hit the MAXINSTANCES (%d) for page %s"%(MAXINSTANCES, baseurl))
            site.update_stats(4, url)            
            return 4

        # let's go
        recvData = netObj.send_and_receive(url)
        if recvData == -1:
            log.myprint( "I need to trash this page %s"%url)
            l_trash.append(url)
            site.update_stats(-1, url)            
            return -1

    # check page precedence
    if enablePScan == True:
        precedence = check_url_precedence(url)
        log.myprint("Precedence is : " + precedence)
    else:
        precedence = "-1"
       
    # parse the page
    if deep_level == 0:     # the homepage?
        (baseurl, params, l_links, l_forms, body) = parse(recvData, site_name, False)     # the last param here is the parametrized links - for homepage take all links
    else:
        (baseurl, params, l_links, l_forms, body) = parse(recvData, site_name, True)
    
    if site.add_page(baseurl, params, l_links, l_forms, strip_html(body), precedence) == -1:          # add the page to the site
        # page existing
        log.myprint("Page existing")
        site.update_stats(-1, url)     
        return -1   
   
    # scan for the vulnerability
    if enableVScan == True:
        # build the list of pairs for the kill_the_beast test :)    
        d = unique_contained_data(l_links, l_forms)
        if len(d)>0:
            vulnerable = kill_the_beast(baseurl, params, d, precedence, site)
            
            if vulnerable == True:
                log.myprint( "*** Yeah!!! ***")
                site_is_vulnerable == True                                # this maybe is now useless
                site.update_stats(1, url)                                 # add the fullURL to the list of the vulnerable ones
                site.set_instance_as_vulnerable(baseurl, params)          # this set that instance as vulnerable
                
    # limit the crawling to MAX_DEPTH 
    if deep_level < MAX_DEPTH:
        deep_level += 1         # GO TO NEXT LEVEL -- now use the saved one for this child
        
        for l in l_links:
            if excludeRegexp=="" or (excludeRegexp!="" and re.search(excludeRegexp,l,re.I)==None):
                crawl(site_name, l, None, site, deep_level)  # recurse on the page's links until we reach our MAX_DEPTH
                            
        for f in l_forms:
            crawl(site_name, None, f, site, deep_level)  # recurse on the page's forms until we reach our MAX_DEPTH
            
    return 0


# test a full site
def test_site(site_name):
    global site_is_vulnerable
    
    log.myprint("--------------------------------------------------------------------------")
    
    log.myprint( "[%s] Testing %s"%(strftime("%H:%M:%S %d/%m/%Y", localtime()), site_name))
    
    # preload the site
    recvData = netObj.send_and_receive(site_name, True)
    if recvData == -1:      # error (timeout reaching site)
        print >>fd_prober, "[%s] X %s"%(strftime("%H:%M:%S %d/%m/%Y", localtime()), site_name)
        return -1   # EXIT: timeout   
        
    
    page_url = re.search('URL:([^\|]+)\|', recvData, re.M).group(1)
  
    if page_url!=site_name:           
        if ((urlparse.urlsplit(site_name)[1] == urlparse.urlsplit(page_url)[1]) and page_url.startswith(site_name)):
            log.myprint("Internal redirection to [%s]. Updating sitename and continuing"%page_url)
            home_page = page_url
        else:
            log.myprint("External redirection to [%s]. Exit"%page_url)
            print >>fd_prober, "[%s] X %s"%(strftime("%H:%M:%S %d/%m/%Y", localtime()), site_name)
            return -1   # EXIT : cross-domain redirection
    else:
        home_page = site_name     

    # begin           
    s = site(site_name)                                               # create a new site() object    
    s.set_beginTime(time.time())
    
    site_is_vulnerable = False
    crawl(site_name, home_page, None, s, 0)
    if site_is_vulnerable == True:   
        log.myprint( "*** %s seems to be vulnerable"%site_name)
        print >>fd_prober, "[%s] V %s"%(strftime("%H:%M:%S %d/%m/%Y", localtime()), site_name)
    else:
        print >>fd_prober, "[%s] - %s"%(strftime("%H:%M:%S %d/%m/%Y", localtime()), site_name)
    
    fd_prober.flush()
    s.print_stats()
    return s
    

    
# e.g. reboot_ffx("localhost", 4444, dev)   - This should be sync with the configuration        
def reboot_ffx(server, server_port, profile):
    FFX_PATH = "/home/hpp/firefox"      # Set to your Firefox path installation

    if server == "localhost" or server == "127.0.0.1":
        cmd = 'ps -eo pid:6,command | /bin/egrep "[0-9]+ %s/firefox-bin -no-remote -P %s$" | cut -c 1-6'%(FFX_PATH, profile)
        print cmd
        pid = os.popen(cmd).readline()
        if pid != "":
            os.popen('kill -9 %s'%pid.strip()).readline()
            time.sleep(1)
            
        os.popen('%s/firefox -no-remote -P %s >/dev/null 2>&1 &'%(FFX_PATH, profile))
        time.sleep(5)

        netObj = net(server, server_port)        
        if netObj.connect()==-1:
            log.myprint("Could not start FFX on %s:%d. Waiting for a second try."%(server, server_port))
            time.sleep(5)
            
            netObj = net(server, server_port)      # connect again
            if netObj.connect()==-1:
                log.myprint("ERROR: FFX seems to hang %s:%d. Quit"%(server, server_port))
                return -1
        return netObj
        
    else:
        print "* Hard Reboot not supported in remote connections"
        return -1
    
    
def mailResultsTo(log, email, url):
    print "* Mailing to %s..."%email,
    msg = MIMEText(log)
    msg['Subject'] = "PAPAS Report for %s"%url
    msg['From'] = "EMAIL_ADDRESS_HERE"
    msg['To'] = email    
    
    try:    
        server = smtplib.SMTP_SSL("MAIL_SERVER_HERE", 465) # 465 is SMTP_SSL port
    except (smtplib.SMTPException, socket.error):
        print "error: cannot connect to the mailserver"
        email_saved = "emailerror_" + email + "_" + str(random.randint(1, 10)) + ".txt"
        print "saving mail content as %s"%email_savedemail_fd
        email_fd = open(email_saved, "w")
        email_fd.write(log)
        email_fd.close()
    else:
        try:
            server.login(MAIL['user'], MAIL['passwd'])
            server.sendmail("EMAIL_ADDRESS_HERE", email, msg.as_string())
        except (smtplib.SMTPAuthenticationError, smtplib.SMTPRecipientsRefused, smtplib.SMTPException):
            print "error: cannot send the mail"
        else:
            print "sent"
            
        server.quit()

        
# generate the token: a string of random 128 digits      
def generate_token():
    t = ""
    values = ('0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f')
    random.seed()
    for i in xrange(64):
        t+=values[random.randint(0,len(values)-1)]
    return t
 
    
# for accessing the DB
def load_dbauth(DBFILE):
    lines = open(DBFILE, 'r').readlines()
    p = [l.strip().split(':')[1] for l in lines]
    d={'name':p[0], 'host':p[1], 'user':p[2], 'passwd':p[3]}
    return d         
    
    
########
# main #
########

if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("-i", "--siteID",  help="the site_id in the PAPAS database", type="string", dest="siteID")
    parser.add_option("-p", "--xulPort", help="the port for the xul plug-in", type="int", dest="xulPort", default=0)
    parser.add_option("-n", "--profileName", help="the ffx profile", type="string", dest="profileName", default="papas1")    

    parser.add_option("-u", "--singleUrl", help="a single URL to scan", type="string", dest="singleUrl")
    parser.add_option("-m", "--mailTo",    help="mail the result to this address", type="string", dest="mailTo")
    parser.add_option("-o", "--owner",     help="the owner of the site", type="string", dest="siteOwner", default="")        

    parser.add_option("-P", "--enablePScan", help="enable the scan of the precedence", action="store_true", dest="enablePScan")        
    parser.add_option("-V", "--enableVScan", help="enable the scan of the vulnerabilities", action="store_true", dest="enableVScan")        
                
    parser.add_option("-e", "--extensiveMode", help="enable the extensive mode", action="store_true", dest="extensiveMode")        
    parser.add_option("-x", "--excludeUrl", help="regexp to exclude portions of URL (e.g. logout)", type="string", dest="excludeRegexp", default="")        

    parser.add_option("-d", "--depth", help="depth", type="int", dest="depth", default=3) 
    parser.add_option("-s", "--sleepTime", help="the sleep time between requests", type="int", dest="sleepTime", default=0)            

    (options, args) = parser.parse_args()

    # stdout and stderr redirection
    sys.stdout = open(STDOUT, "a")
    sys.stderr = open(STDERR, "a")
    print 64*"-"
    print >>sys.stderr, 64*"-"
    # 
    
    fd_prober  = open(LOGFILE_PROBER, 'a')
       
    if options.xulPort == 0:
        print "ERROR: port is missing"
        print "-h for HELP"
        sys.exit(-1)

    if options.singleUrl == "":
        print "ERROR: specify the site with -u. Bye"
        print "-h for HELP"
        sys.exit(-1)
    
    # the site
    u = options.singleUrl
    
    print >>fd_prober, "---------- Running %s %s - Logging to %s ----------"%(APPNAME, APPVERSION, DATADIR) 
    print "\n* Running %s %s - Logging to %s"%(APPNAME, APPVERSION, DATADIR) 
    print "CMD : ", sys.argv

       
    # connect to ffx
    print "* FFX is %s:%d - Profile is \"%s\""%(FFX_HOST, options.xulPort, options.profileName)
      
    netObj = reboot_ffx(FFX_HOST, options.xulPort, options.profileName)
    if netObj==-1:
        sys.exit(-1)
   

    t = urlparse.urlsplit(u)
    # routine to assign the filename
    # for UNIX : reverse / into _
    fname=basename=DATADIR+"/"+t[0]+':__' +t[1]+t[2].replace('/', '_')
    if os.path.exists(fname+".txt"):
        i=2
        while os.path.exists(fname+".txt"):
            fname=basename+".%d"%i
            i+=1
            
    # this for the HTML output
    tok = generate_token()
    html_name = DATADIR_HTML + "/" + t[1] + "." + tok + ".html"
    
    
    # the old txt output 
    log.init(fname+".txt")      
            
            
    log.myprint("++++++++++++++++++++++++++")
    log.myprint("+  Running %s %s  +"%(APPNAME, APPVERSION))
    log.myprint("++++++++++++++++++++++++++")    
    log.myprint("")
    
    
    # configurations 
    log.myprint("Configuration:")
    
    if options.enablePScan == True:
        log.myprint("* P-Scan Enabled")
        enablePScan = True
    else:
        log.myprint("* P-Scan Disabled")
        enablePScan = False

    if options.enableVScan == True:
        log.myprint("* V-Scan Enabled")
        enableVScan = True
    else:
        log.myprint("* V-Scan Disabled")
        enableVScan = False

    if options.extensiveMode == True:
        log.myprint("* Extensive Mode Enabled")
        extensiveMode = True
    else:
        log.myprint("* Extensive Mode Disabled")
        extensiveMode = False
    
    excludeRegexp = options.excludeRegexp
    if excludeRegexp != "":   
        log.myprint("* Exclude Regexp : " + excludeRegexp)
    else:
        log.myprint("* NO Exclude Regexp")
          
    # depth - sleep time - 
    MAX_DEPTH = options.depth
    if MAX_DEPTH<1 or MAX_DEPTH>9: MAX_DEPTH=3      # security check
    log.myprint("* Scanning to depth %d"%MAX_DEPTH)
             
    SLEEP_TIME = options.sleepTime
    if SLEEP_TIME<0 or SLEEP_TIME>60: SLEEP_TIME=0  # security check
    log.myprint("* Sleeping %d sec. between pages"%SLEEP_TIME)                              
    
    log.myprint("* HTML Report %s"%(t[1] + "." + tok + ".html"))                              
      
    # prepare the html output for the user
    h = html.get_scheleton(u)
    h += html.add_section('Scan Parameters', (
                          ('Version',APPVERSION), ('P-Scan',enablePScan), ('V-Scan',enableVScan), ('Extensive Mode',extensiveMode), 
                          ('Exclude Regexp',excludeRegexp), ('Max Depth',MAX_DEPTH), ('Sleep Time',"%d sec(s)"%SLEEP_TIME)))

    log.myprint("")                                                                
                              
    # s is the tested site to serialize
    s = test_site(u)
    if s == -1: # homepage cannot be reached
        log.myprint("!Could not reach homepage")
    else:
        h += s.get_html_stats()         # general statistics
        if enableVScan: h += s.get_html_vulnerable()    # list of vulnerable sites
        if enablePScan: h += s.get_html_precedence()    # list of precedences for page/instance
            
    fd = open(fname+".pyobj", 'wb') # the serialized object
    pickle.dump(s, fd, 2)    # Protocol version 2 was introduced in Python 2.3. It provides much more efficient pickling of new-style classe
    fd.close()
    del s    
               
    # shutdown server
    log.end()
    netObj.kill()
    fd_prober.close()
    
    
    # finalize the report report
    h += html.get_full_log()        # the full log        
    h += html.get_down()
    html_report = open(html_name, "w")
    if html_report:
        html_report.write(h)
        html_report.close()
        
    if options.mailTo:
        mail = '''
               Hi %s, the scan is completed!
               
               Your report is now available at:
               FULL_WEBSITE_URL/%s
                              
               Have a nice day. MB                              
               '''%(options.siteOwner, t[1] + "." + tok + ".html")
                  
        mailResultsTo(mail, options.mailTo, u)
    
    
    # papas is ready again
    DB = load_dbauth("/home/hpp/db.auth")       # Set the credentials of the database for logging
    db = pg.connect(dbname=DB['name'], host=DB['host'], user=DB['user'], passwd=DB['passwd'])
    if options.siteID: db.query ("UPDATE sites SET status = 'completed' WHERE id = '%s'"%options.siteID)
    db.query ("UPDATE instances SET status = 'ready' WHERE name = '%s'"%options.profileName)
    db.close()
    
