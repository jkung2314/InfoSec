import psycopg2 as p
from datetime import datetime, timedelta
import time

#added = datetime.now() #current time
try:
    con_source = p.connect ("dbname = 'phoenixdb' host = 'localhost'")
    con_destination = p.connect ("dbname = 'rtbh' host = 'localhost'")
except:
    print "Unable to connect to database."

thirty_days = int(time.time()) - 2592000 #30days from today
print thirty_days
cur_source = con_source.cursor()
cur_source.execute("SELECT * FROM ph_user_id_loc")
rows = cur_source.fetchall()

cur_destination = con_destination.cursor()
for i in range(len(rows)):
    domain_user_id = "<" + str(rows[i][7]) + ">"
    domain_user_id = domain_user_id.replace('\u0000","type":"syslog","tags":["campussyslog","_grokparsefailure"]}', "")
    inet_domain = "<" + str(rows[i][6]) + ">"
    creation_time = "<" + str(rows[i][1]) + ">"
    cidr = rows[i][10] #ip address
    why = "Login from " + inet_domain + " by " + domain_user_id + " on " + creation_time
    added = datetime.now() #current time
    who_id = 10142480 #RANDOM.ORG Random Number

con_source.close()
cur_source.close()
con_destination.close()
cur_destination.close()
