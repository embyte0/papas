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

import sys

fd = None
full_log = []       # for HTML output

def init(fname):
    global fd
    try:
        fd = open(fname, 'w')
    except IOError:
        fd = None
        print "init(). IOError catched while writing on logfile %s"%fname

#def dualprint(what):
#    global fd
#    if fd!=None:
#        print >>fd, what
#        fd.flush()
#    print what
#    sys.stdout.flush()
    
def myprint(what):
    global fd
    global full_log
    
    if fd!=None:
        print >>fd, what
        fd.flush()
        
    full_log.append(what)

    
def get_full_log():
    global full_log
    return full_log
    
def end():
    global fd
    if fd!=None:
        fd.close()
        fd = None
        
