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

import re

# Thanks to Bernardo Damele for these regexps
# taken from https://svn.sqlmap.org/sqlmap/trunk/sqlmap/xml/errors.xml
def check(body):

    if  re.search("(?i)SQL syntax.*?MySQL", body) or \
        re.search("(?i)Warning.*?mysql_.*?", body) or \
        re.search("(?i)valid MySQL result", body) or \
        re.search("(?i)MySqlClient\.", body):
        return "error_sql_mysql"

    elif  re.search("(?i)PostgreSQL.*?ERROR", body) or \
        re.search("(?i)Warning.*?pg_.*?", body) or \
        re.search("(?i)valid PostgreSQL result", body) or \
        re.search("(?i)Npgsql\.", body):
        return "error_sql_postgresql"

    elif  re.search("(?i)Driver.*?SQL[\-\_\ ]*Server", body) or \
        re.search("(?i)OLE DB.*?SQL Server", body) or \
        re.search("(?i)SQL Server.*?Driver", body) or \
        re.search("(?i)Warning.*?mssql_.*?", body):
        return "error_sql_mssqlserver"

    elif  re.search("(?i)Access.*?Driver", body) or \
        re.search("(?i)Driver.*?Access", body) or \
        re.search("(?i)JET Database Engine", body) or \
        re.search("(?i)Access Database Engine", body):
        return "error_sql_msaccess"

    elif  re.search("(?i)ORA-[0-9][0-9][0-9][0-9]", body) or \
        re.search("(?i)Oracle error", body) or \
        re.search("(?i)Oracle.*?Driver", body) or \
        re.search("(?i)Warning.*?o(ci|ra)_.*?", body):
        return "error_sql_oracle"

    elif  re.search("(?i)CLI Driver.*?DB2", body) or \
        re.search("(?i)DB2 SQL error", body):
        return "error_sql_db2"

    elif  re.search("(?i)Exception.*?Informix", body):
        return "error_sql_informix"

    elif  re.search("(?i)Dynamic SQL Error", body):
        return "error_sql_firebird"

    elif  re.search("(?i)Warning.*?sqlite_.*?", body) or \
        re.search("(?i)SQLite/JDBCDriver", body) or \
        re.search("(?i)SQLite.Exception", body) or \
        re.search("(?i)System.Data.SQLite.SQLiteException", body):
        return "error_sql_sqlite"

    elif re.search("(?i)sql error", body):
        return "error_sql_generic"
        
    elif re.search("(?i)SQLServer JDBC Driver", body):
        return "error_sql_sqlserverjdbc"

    elif re.search("(?i)microsoft VBScript.*?error", body):
        return "error_vbscript"

    elif re.search("(?i)internal server error", body) or \
         re.search("(?i)No such file or directory", body) or \
         re.search("(?i)error occurred", body) or \
         re.search("(?i) not found", body):
        return "error_generic"
    
    return "-1"
