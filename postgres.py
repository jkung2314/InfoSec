import psycopg2 as p
try:
    con = p.connect ("dbname = 'phoenixdb' host = 'localhost'")
except:
    print "Unable to connect to database."

cur = con.cursor()
cur.execute("SELECT * FROM ph_user_id_loc")
rows = cur.fetchall()
for i in range(len(rows)):
    domain_user_id = str(rows[i][7])
    domain_user_id = domain_user_id.replace('\u0000","type":"syslog","tags":["campussyslog","_grokparsefailure"]}', "")
    inet_domain = str(rows[i][6])

#for i in rows:
#    print i
