import psycopg2 as p
from datetime import datetime, timedelta
import time

#added = datetime.now() #current time
try:
    con_source = p.connect ("dbname = 'phoenixdb' host = 'localhost'")
    con_destination = p.connect ("dbname = 'rtbh' host = 'localhost'")
except:
    print "Unable to connect to database."

cur_destination = con_destination.cursor()
cur_destination.execute("DELETE FROM bhr_whitelistentry WHERE who_id = 10142480")
con_destination.commit()

thirty_days = int(time.time()) - 2592000 #30days from today
cur_source = con_source.cursor()
cur_source.execute("SELECT * FROM ph_user_id_loc")
rows = cur_source.fetchall()

for i in range(len(rows)):
    domain_user_id = "<" + str(rows[i][7]) + ">"
    domain_user_id = domain_user_id.replace('\u0000","type":"syslog","tags":["campussyslog","_grokparsefailure"]}', "")
    inet_domain = "<" + str(rows[i][6]) + ">"
    creation_time = "<" + str(rows[i][1]) + ">"
    cidr = rows[i][10] #ip address
    why = "Login from " + inet_domain + " by " + domain_user_id + " on " + creation_time
    added = datetime.now() #current time
    who_id = 10142480 #RANDOM.ORG Random Number
    sql = "INSERT INTO bhr_whitelistentry (cidr, why, added, who_id) VALUES (%s, %s, %s, %s)"
    data = (cidr, why, added, who_id)
    cur_destination.execute(sql, data)
    con_destination.commit()

#cur_destination.commit()
con_source.close()
cur_source.close()
con_destination.close()
cur_destination.close()
