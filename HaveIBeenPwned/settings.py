email_login = ''
email_pass = ''

#Enter column names of database
tablename = 'compromised_processed' #CHANGE TO CORRESPONDING TABLENAME
id_field = 'id' #DO NOT CHANGE
username_field = 'username' #DO NOT CHANGE
password_field = 'password' #DO NOT CHANGE
domain_field = 'domain' #DO NOT CHANGE
date_added = 'date_added' #DO NOT CHANGE
dump_name = 'dump_name' #DO NOT CHANGE
date_dump = 'date_dump' #DO NOT CHANGE

#Database settings
dialect = '' # 'firebird', 'mssql', 'mysql', 'oracle', 'postgresql', 'sqlite', 'sybase'
sqluser = '' #username
sqlpass = '' #password
sqlserver = '' #host:port
sqldatabase = '' #database name

#LDAP Settings
LDAP_SEARCH_STRING = '' #Fields to search if user exists in LDAP; Example: '( |(uid={0})(mail=*{0}*) )'
LDAP_UID_SEARCH_STRING = '' #Fields to search if user exists in LDAP Example: '(uid={0})'
LDAP_SERVER = '' #LDAP Server
LDAP_DN = '' #LDAP DN
LDAP_FIELDS = [''] #LDAP fields to search
LDAP_BIND_DN = "" #LDAP BIND DN

# How long to wait before performing the next LDAP query or bind
# Probably not an issue for small batches, larger batches we may want to consider being nicer
# to the ldap server.
LDAP_ACTION_DELAY = 0.1
