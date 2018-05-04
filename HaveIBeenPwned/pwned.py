"""
    Jonathan Kung <jhkung@ucsc.edu>
    University of California, Santa Cruz Infrastructure Security Team
"""
import settings
import ldapServer
from DB import compromisedDB
from kafka import KafkaProducer
from kafka import KafkaConsumer
import json
import imaplib
import email
import re
import urllib2
import requests
import datetime

database = compromisedDB()
#start connection
try:
    database.connect()
except:
    print ("Unable to connect to database.")

ldapObj = ldapServer.ldapServer() #New ldap object
ldapObj.connect() #Connect to server

# Connect KafkaProducer
kafkaserver = ["itsec-prod-elk-3.ucsc.edu:9092", "itsec-prod-elk-8.ucsc.edu:9092", "itsec-prod-elk-9.ucsc.edu:9092"]
topic = 'secinc'
try:
    kproducer = KafkaProducer(bootstrap_servers = kafkaserver)
except Exception as ex:
    raise Exception(ex)

#Login to email
M = imaplib.IMAP4_SSL('imap.gmail.com')
M.login(settings.email_login, settings.email_pass)
M.select('inbox')

#Search for any emails within the last day from "Have I Been Pwned"
date = (datetime.datetime.now().date() - datetime.timedelta(days=1)).strftime("%d-%b-%Y")
rv, data = M.search(None, 'From', "Have I Been Pwned", 'Since', date)

data[0] = data[0].split()
try:
    #Get last email
    mail = data[0][-1]
except IndexError:
    print("No new mail from HaveIBeenPwned in the last day")
    exit(1)

#Fetch message data
typ, msg_data = M.fetch(str(mail), '(RFC822)')
msg = email.message_from_string(msg_data[0][1])
msg_id = msg.get('Message-ID')
subject = msg.get('Subject')
subject = subject.replace(" ", "_")

print ("PROCESSING <{0}>: <{1}>").format(datetime.datetime.now(), subject)

#Determine if email has been previously processed
history = open("processed_emails.txt", "r")
if msg_id in history.read():
    history.close()
    exit(1)
else:
    history = open("processed_emails.txt", "a")
    history.write(str(msg_id) + "\n")
    history.close()

#Decode and get Pastebin link
msg = str(msg.get_payload()[0])
try:
    code = re.findall(r'<https://pastebin.com/(.*?)>', str(msg))[0]
    M.close()
except IndexError:
    M.close()
    print("Pastebin Link Not Found")
    exit(1)

url = 'https://pastebin.com/raw/' + str(code)
try:
    userList = urllib2.urlopen(url).read()
except:
    print("Pastebin link expired.")
    exit(1)

today = datetime.datetime.now().date()
today = str(date).replace("-", "_")

#Write to log file
r = requests.get(url, verify=False)
fName = "haveibeenpwneddump_" + today + subject + ".log"
open(fName, 'wb').write(r.content)
fName.close()

#Send json data to kafka
def kafkaSend(username, row):
    data = {}
    data['username'] = username
    data['category'] = 'compromised account'
    data['reason'] = 'Have I Been Pwned - Valid Credentials'
    data['detection_timestamp'] = datetime.datetime.today().strftime("%Y-%m-%d %H:%M:%S")
    data['logrow'] = row
    # Format JSON
    json_data = json.dumps(data)

    # Send to Kafka
    kproducer.send(topic, json_data.encode('utf-8'))
    kproducer.flush()

#Function for Binding
def Bind(username, password, user, row):
    result = ldapObj.bind(username, password)

    if result == True:
        print ("[{0}] *** Bind Successful: Valid credentials ***".format(username))
        kafkaSend(username, row)
    else:
        print ("[{0}] *** Bind Failed: Invalid credentials ***".format(username))

#LDAP function for email:password format
def Fldap(username, user, password, row):
    result = ldapObj.uid_search(username)

    if len(result) < 1:
        print ("{0} is not in campus LDAP".format(username))
    else:
        print ([result[0][0], username, user])
        Bind(username, password, user, row)

    # sleep for a little bit to avoid hammering the ldap
    time.sleep(0.1)

#LDAP function for username only format
def Uldap(username, row):
    result = ldapObj.uid_search(username)

    if len(result) < 1:
        print ("{0} is not in campus LDAP".format(username))
    else:
        print (result)

#Check if in Postgres database
def inDatabase(username, password):
    row = database.searchUsername(username)
    if row[0] == 0:
        return False
    else:
        if password == None:
            return True
        else:
            data = database.searchUsernamePassword(username, password)
            if data[0] == 0:
                return False
            return True

#finish
def done():
    database.close() #commit and close
    exit(1)

#Process file
try:
    userList = userList.strip().rsplit('\n')
except IOError as e:
    print (e)
for user in userList:
    row = user
    if str(user).find("@") > 0:
        username = user[0:str(user).find("@")]
    else:
        username = user
    if "ucsc" in str(user):
        if ":" in str(user):
            password = user.split(":")
            password = password[1]
            domain = user.split("@")
            domain = domain[1].split(":")
            domain = domain[0]
        else:
            password = None
            domain = user.split("@")
            domain = domain[1]
        kafkaSend(username, row)
        if inDatabase(username, password) == False:
            dumpName = 'Have I Been Pwned'
            dateAdded = None
            database.insert(username, password, domain, current_time, dumpName, dateAdded)
            if password != None:
                Fldap(username, user, password, row)
            else:
                Uldap(username, row)
        else:
            print (username + " LOCATED in database, ignoring...")

done()
