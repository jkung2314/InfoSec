import csv

ipaddr, username, rule, startdatetime, enddatetime = ([], [], [], [], [])

with open('urgency.csv') as csvfile:
    readCSV = csv.reader(csvfile, delimiter = ',')
    next(readCSV)
    for row in readCSV:
        ipaddr.append(row[0])
        username.append(row[1])
        rule.append(row[2])
        startdatetime.append(row[3])
        enddatetime.append(row[4])

print(ipaddr)
print(username)
print(rule)
print(startdatetime)
print(enddatetime)
