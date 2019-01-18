"""
    Jonathan Kung <jhkung@ucsc.edu>
    University of California, Santa Cruz

    Automates the identification of user(s), given an ip and timestamp.
"""
import credentials
import datetime
import pytz
from elasticsearch import Elasticsearch
import json
import sys
import ldap
from ldapServer import ldapServer

class trueUser:
    # Elasticsearch object
    es = None

    # ldap object
    ldapObj = None

    # Get current timezone UTC offset
    pacific_now = datetime.datetime.now(pytz.timezone('US/Pacific'))
    timezone = "-0{0}:00".format(str(pacific_now.utcoffset().total_seconds()/60/60)[1])

    def __init__(self):
        self.es = Elasticsearch(
           [credentials.es_server],
           http_auth=(credentials.es_username, credentials.es_password),
           port=credentials.es_port,
           use_ssl=True,
           verify_certs=False,
           # You must have a copy of the CA cert present to use in this code
           ca_certs=credentials.ca_certs
        )
        # Connect to UCSC ldap server
        self.ldapObj = ldapServer()
        self.ldapObj.setServer()
        try:
           self.ldapObj.connect()
           self.ldapObj.bind(credentials.LDAP_USERNAME, credentials.LDAP_PASSWORD)
        except ldap.INVALID_CREDENTIALS as e:
           print("Invalid credentials")
        except Exception as e:
           print(e)


    # Searches Elasticsearch for trueIP, given NATTED IP, port, start, and end time
    # Returns trueIP if exists
    def getTrueIP(self, infringementPort, infringementIP, queryStartTime, queryEndTime):
        pacific_now = datetime.datetime.now(pytz.timezone('US/Pacific'))
        timezone = "-0{0}:00".format(str(pacific_now.utcoffset().total_seconds()/60/60)[1])
        netflowQuery = json.dumps({
        "query": {
            "bool": {
              "must": [{
                "query_string": {
                  "query": "netflow.xlate_src_port: {0} AND netflow.xlate_src_addr_ipv4: {1} AND netflow.natEvent: 1".format(infringementPort, infringementIP),
                  "analyze_wildcard": True,
                  "default_field": "*"
                }
              }, {
                "range": {
                    "@timestamp": {
                      "gte": queryStartTime,
                      "lte": queryEndTime,
                      "format": "yyyy-MM-dd HH:mm",
                      "time_zone": self.timezone
                    }
                  }
              }],
              "filter": [],
              "should": [],
              "must_not": []
            }
          }
        })
        results = self.es.search(index='logstash-netflow-*', body=netflowQuery, size=2000)
        if len(results['hits']['hits']) == 0:
            print("True IP not found, terminating...")
            sys.exit(0)
        else:
            trueIP = results['hits']['hits'][0]['_source']['srcip']
            return trueIP

    # Searches Elasticsearch for user, given trueIP, start, and end time
    # Prints all authentications with matching ip and timerange
    # Returned values:
        # boolean value for user found, identified users list (may be empty),
        # macaddress list (may be empty), and results list (may be empty)
    def getUser(self, trueIP, queryStartTime, queryEndTime):
        queryUser = json.dumps({
            "query": {
            "bool": {
              "must": [
                {
                  "match": {"srcip": trueIP}
                },
                {
                  "range": {
                    "@timestamp": {
                      "gte": queryStartTime,
                      "lte": queryEndTime,
                      "format": "yyyy-MM-dd HH:mm",
                      "time_zone": self.timezone
                    }
                  }
                }
              ],
              "filter": [],
              "should": []
            }
          }
        })
        results = self.es.search(index='logstash-auth-*', body=queryUser, size=2000)
        foundUser = False
        foundUsersList = []
        macaddressList = []
        resultsList = []
        for hit in results['hits']['hits']:
            data = hit['_source']
            username = data['username']
            if username != 'null':
                foundUsersList.append(username)
                foundUser = True
            timestamp = data['@timestamp']
            try:
                macaddress = data['macaddress']
            except:
                macaddress = None
            authsource = data['authsource']
            if username == 'null':
                userAffiliation = None
                if macaddress not in macaddressList:
                    macaddressList.append(macaddress)
            else:
                try:
                    userAffiliation = ldapObj.uid_search(username)[0][1]['eduPersonAffiliation'][0].decode('utf-8')
                except:
                    userAffiliation = None
            result = [timestamp, username, userAffiliation, macaddress, authsource]
            resultsList.append(result)
        return foundUser, foundUsersList, macaddressList, resultsList

    # Searches Elasticsearch for user, given macaddress, start, and end time
    # Returns list with all authentications with matching macaddress(es) and timerange (may be empty)
    def searchMacaddress(self, macaddressList, queryStartTime, queryEndTime):
        for macaddress in macaddressList:
            query_macaddress = json.dumps({
                "query": {
                "bool": {
                  "must": [
                    {
                      "match": {"macaddress": macaddress}
                    },
                    {
                      "range": {
                        "@timestamp": {
                          "gte": queryStartTime,
                          "lte": queryEndTime,
                          "format": "yyyy-MM-dd HH:mm",
                          "time_zone": self.timezone
                        }
                      }
                    }
                  ],
                  "filter": [],
                  "should": []
                }
              }
            })
            result = self.es.search(index='logstash-auth-*', body=query_macaddress, size=2000)
            resultsList = []
            for hit in result['hits']['hits']:
                data = hit['_source']
                username = data['username']
                if data['macaddress'] == macaddress:
                    if username != 'null':
                        timestamp = data['@timestamp']
                        realMacaddress = data['macaddress']
                        try:
                            city = data['geoip']['city_name']
                            region = data['geoip']['region_name']
                        except:
                            city = None
                            region = None
                        authsource = data['authsource']
                        try:
                            userAffiliation = ldapObj.uid_search(username)[0][1]['eduPersonAffiliation'][0].decode('utf-8')
                        except:
                            userAffiliation = None
                        result = [timestamp, username, userAffiliation, realMacaddress, city, region, authsource]
                        resultsList.append(result)
            return resultsList
