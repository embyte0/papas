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

import log

def get_scheleton(sitename):
    return '''                       
  <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
          "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>
   <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
   <link rel="stylesheet" type="text/css" href="/papas.css" /> 
   <link rel="shortcut icon" href="/images/papas.ico" />
   <meta name="description" content="PAPAS: PArameter Pollution Analysis System" />
   <meta name="keywords" content="web security, hpp, http parameter pollution, PAPAS" />
    
   <title>PAPAS Report for %s</title>

   <style type="text/css">
                                .headerLeft {
                                background-image: url(/images/left.jpg);
                                background-repeat: no-repeat;
                                background-position: left;
                                padding: 0px;
                                width: 13px;
                                }
                                .headerCenter {
                                background-image: url(/images/center.jpg);
                                background-repeat: repeat-x;
                                background-position: center;
                                }
                                .headerRight {
                                background-image: url(/images/right.jpg);
                                background-repeat: no-repeat;
                                background-position: right;
                                padding: 0px;
                                width: 12px;
                                }
   </style>


   <script type="text/javascript">
                                var left = "url(/images/left.jpg)";
                                var right = "url(/images/right.jpg)";
                                var leftCollapsed = "url(/images/leftCollapsed.jpg)";
                                var rightCollapsed = "url(/images/rightCollapsed.jpg)";
                                 var hintScriptUrl = "/info.js";
   </script>
 
   <script src="/script.js" type="text/javascript" /></script>
   <script src="/info.js" type="text/javascript" /></script>
    
</head>

<body  style='margin: 0px'>
  <div class="header">
    <div class="headermiddle">
      PAPAS: PArameter Pollution Analysis System
      <table border="0" cellpadding="0" cellspacing="0" class="header">
        <tbody>
          <tr align="center" valign="middle" style='height: 26px'>
            <td class="menulevel0">
              <a href="/cgi-bin/index.py" class="navlink">Home</a>
            </td>
            <td class="menulevel0">
              <a href="/cgi-bin/submission.py" class="navlink">Submission</a>
            </td>
            <td class="menulevel0">
              <a href="/cgi-bin/verify.py" class="navlink">Validation</a>
            </td>
            <td class="menulevel0">
              <a href="http://papas.iseclab.org/reports/www.eurecom.fr.38965d8f98693bac0e532cc8525c70d60350ac55629250623ddbf9cc372126ca.html" class="navlink">Examples</a>
            </td>
            <td class="menulevel0last">
              <a href="/cgi-bin/resources.py" class="navlink">Resources</a>
            </td>

        </tbody>
      </table>

    </div>
    <div class="headershadow"></div>
  </div>

<!-- BEGIN -->


<table class="bodytable" border="0" cellpadding='0' cellspacing='0' 
       width="100%%">
  <tbody>
    <tr>
      <td class="left" valign="top">
        <br />
      </td>

      <td class="middle">
      
      <h1>Analysis Report for %s</h1>
'''%(sitename,sitename)
            
           
            
def get_down():
    return '''
    <!-- END -->
<br><br>
<hr style="width:100%;" />
      </td>
      <td class="right" style="width: 150px;"><br /></td>
    </tr>
  </tbody>
</table>

<div class="footertext"><a href="http://www.iseclab.org/people/embyte/">&copy; 2010 Marco `embyte` Balduzzi</a> @ <a href="http://www.iseclab.org">International Secure Systems Lab</a> <br />

<script type="text/javascript">
var gaJsHost = (("https:" == document.location.protocol) ? "https://ssl." : "http://www.");
document.write(unescape("%3Cscript src='" + gaJsHost + "google-analytics.com/ga.js' type='text/javascript'%3E%3C/script%3E"));
</script>
<script type="text/javascript">
try {
var pageTracker = _gat._getTracker("UA-11111381-1");
pageTracker._trackPageview();
} catch(err) {}</script>
</div>

</body>
</html>
'''


def add_section(name, table):
    section = '''
                <br><br>
                <table width="100%%" border="0" cellpadding="0" cellspacing="0">
                <tbody>
                <tr>
                 <td>
                  <table width="100%%" border="0" cellpadding="0" cellspacing="0">
                    <tbody><tr style="height: 29px;">
                      <th class="headerLeft">&nbsp;</th>
                      <th class="headerCenter"><a onclick="JavaScript: change (this)" class="click" name="open">-&nbsp;%s</a></th>
                      <th class="headerRight">&nbsp;</th>
                    </tr>
                    </tbody>
                  </table>
                 </td>
                </tr>
                
                <tr>
                <td>
                  <table style="background-color: rgb(208, 216, 228);" width="100%%" border="0" cellpadding="2" cellspacing="0">
                    <tbody>
              '''%name

    for line in table:
        section += '''
                    <tr>
                      <td WIDTH="75%%" class="TableCell">%s</td>
                      <td class="TableCell">%s</td>
                    </tr>
              '''%(line[0], line[1])            

    section += ''' 
                 </tbody></table>
                 </td>
                 </tr>
               </tbody></table> '''
    
    return section


# custom section for the vulnerable pages
def add_vuln_section(name, table):
    section = '''
                <br><br>
                <table width="100%%" border="0" cellpadding="0" cellspacing="0">
                <tbody>
                <tr>
                 <td>
                  <table width="100%%" border="0" cellpadding="0" cellspacing="0">
                    <tbody><tr style="height: 29px;">
                      <th class="headerLeft">&nbsp;</th>
                      <th class="headerCenter"><a onclick="JavaScript: change (this)" class="click" name="open">-&nbsp;%s</a></th>
                      <th class="headerRight">&nbsp;</th>
                    </tr>
                    </tbody>
                  </table>
                 </td>
                </tr>
                
                <tr>
                <td>
                  <table style="background-color: rgb(208, 216, 228);" width="100%%" border="0" cellpadding="2" cellspacing="0">
                    <tbody>
                    <tr>
                      <td class="TableCell"><i>Vulnerable Page</i></td>
                      <td class="TableCell"><i>Injection</i></td>
                      <td class="TableCell"><i>Exploit URL</i></td>
                    </tr>
              '''%name

    for line in table:
        section += '''
                    <tr>
                      <td class="TableCell">%s</td>
                      <td class="TableCell">%s</td>
                      <td class="TableCell">%s</td>
                    </tr>
              '''%(line[0], line[1], line[2])            

    section += ''' 
                 </tbody></table>
                 </td>
                 </tr>
               </tbody></table> '''
    
    return section




def add_fixedsize_section(name, table):
    section = '''
                <br><br>
                <table width="100%%" border="0" cellpadding="0" cellspacing="0">
                <tbody>
                <tr>
                 <td>
                  <table width="100%%" border="0" cellpadding="0" cellspacing="0">
                    <tbody><tr style="height: 29px;">
                      <th class="headerLeft">&nbsp;</th>
                      <th class="headerCenter"><a onclick="JavaScript: change (this)" class="click" name="open">-&nbsp;%s</a></th>
                      <th class="headerRight">&nbsp;</th>
                    </tr>
                    </tbody>
                  </table>
                 </td>
                </tr>
                
                <tr>
                <td>
                  <div style="max-height: 288px; overflow: auto;">
                  <table style="background-color: rgb(208, 216, 228);" width="100%%" border="0" cellpadding="2" cellspacing="0">
                    <tbody>
              '''%name

    for line in table:
        section += '''
                    <tr>
                      <td WIDTH="75%%" class="TableCell">%s</td>
                      <td class="TableCell">%s</td>
                    </tr>
              '''%(line[0], line[1])            

    section += ''' 
                 </tbody></table>
                 </div>
                 </td>
                 </tr>
               </tbody></table> '''
    
    return section
    
    
    
def get_full_log():
    full_log = log.get_full_log()
    
    section = '''
                <br><br>
                <table width="100%%" border="0" cellpadding="0" cellspacing="0">
                <tbody>
                <tr>
                 <td>
                  <table width="100%%" border="0" cellpadding="0" cellspacing="0">
                    <tbody><tr style="height: 29px;">
                      <th style="background-image: url(/images/leftCollapsed.jpg);" class="headerLeft">&nbsp;</th>
                      <th class="headerCenter"><a onclick="JavaScript: change (this)" class="click" name="autoCollapse">+&nbsp;Full Log</a></th>
                      <th style="background-image: url(/images/rightCollapsed.jpg);" class="headerRight">&nbsp;</th>
                    </tr>
                    </tbody>
                  </table>
                 </td>
                </tr>
                
                <tr style="display: none;">
                <td>
                  <div style="max-height: 288px; overflow: auto;">
                  <table style="background-color: rgb(208, 216, 228);" width="100%%" border="0" cellpadding="2" cellspacing="0">
                    <tbody>
              '''

    for line in full_log:
        section += '''
                    <tr>
                      <td WIDTH="100%%" class="TableCell" style="border: 0px;">%s</td>
                    </tr>
              '''%line            

    section += ''' 
                 </tbody></table>
                 </div>
                 </td>
                 </tr>
               </tbody></table> '''
    
    return section
