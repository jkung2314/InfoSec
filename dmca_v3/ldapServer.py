"""
Brian Hall
UCSC
Updated: 3/23/2017

Handles ldap interactions
Expectation is that another class would use this and trap/catch any exceptions.
It's possible for lots of things to fail here, no connection to host, invalid credentials, etc.
The user of this class should decide how those should be dealt with in their environment.

"""

import ldap #python-ldap
import credentials
import json

class ldapServer:
   _LDAP_SERVER = ''
   _LDAP_DN = ''
   _LDAP_FIELDS = []
   _connection = None

   def __init__(self, LDAP_SERVER="", LDAP_DN="", LDAP_FIELDS=""):
       _LDAP_SERVER = LDAP_SERVER
       _LDAP_DN = LDAP_DN
       _LDAP_FIELDS = LDAP_FIELDS

   def setServer(self):
       self._LDAP_SERVER = credentials.UCSC_LDAP_SERVER
       self._LDAP_DN = credentials.UCSC_LDAP_DN
       self._LDAP_FIELDS = credentials.UCSC_LDAP_FIELDS

   def connect(self):
       self._connection = ldap.initialize(self._LDAP_SERVER)


   def search(self, uservalue):
       """ search for exact match on uid or mail field with wild card """
       if self._connection is None:
           self.connect()

       results = self._connection.search_s(self._LDAP_DN, ldap.SCOPE_SUBTREE, '(|(uid={0})(mail=*{0}*))'.format(uservalue), self._LDAP_FIELDS )
       return results

   def uid_search(self, username):
       """ search by uid field only with an exact match"""
       if self._connection is None:
           self.connect()

       results = self._connection.search_s(self._LDAP_DN, ldap.SCOPE_SUBTREE, '(uid={0})'.format(username), self._LDAP_FIELDS )
       return results

   def bind(self, username, password):

       if self._connection is None:
           self.connect()
       self._connection.simple_bind_s(credentials.UCSC_LDAP_BIND_DN.format(username), password)
       return True

   def unbind(self):
       self._connection.unbind()
       self._connection = None
       return True
