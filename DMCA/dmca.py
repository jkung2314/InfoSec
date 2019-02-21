import datetime
import pytz
from ipaddress import ip_network, ip_address
from trueUser import trueUser

# Initialize trueUser object
trueUserObj = trueUser()

infringementTime = '2018-12-12T04:32:52Z'
infringementIP = '128.114.255.11'
infringementPort = '15111'

# NAT IP Range
network = ip_network("128.114.255.0/28")

# Create python date object
pythonizedInfringementTime = datetime.datetime.strptime(infringementTime, "%Y-%m-%dT%H:%M:%SZ")

# Specify and add timezone
utc = pytz.timezone('UTC')
infringementTime = utc.localize(pythonizedInfringementTime)

# Convert to pacific time
infringementTime = infringementTime.astimezone(pytz.timezone('US/Pacific'))

# Specify timerange and correctly format for netflow query (-10 minutes from infringementTime and +10 minutes)
netflowStartTime = datetime.datetime.strftime(infringementTime - datetime.timedelta(minutes=10), "%Y-%m-%d %H:%M")
netflowEndTime = datetime.datetime.strftime(infringementTime + datetime.timedelta(minutes=10), "%Y-%m-%d %H:%M")

# Get trueIP from netflow if IP is NATTED
if ip_address(infringementIP) in network:
    trueIP = trueUserObj.getTrueIP(infringementPort, infringementIP, netflowStartTime, netflowEndTime)
else:
    trueIP = infringementIP

# Specify timerange and correctly format for user query (-4 hours from infringementTime and +2 hours)
userQueryStartTime = datetime.datetime.strftime(infringementTime - datetime.timedelta(minutes=240), "%Y-%m-%d %H:%M")
userQueryEndTime = datetime.datetime.strftime(infringementTime + datetime.timedelta(minutes=120), "%Y-%m-%d %H:%M")

# Get user from trueIP, prints results if results are found
user = trueUserObj.getUser(trueIP, userQueryStartTime, userQueryEndTime)
if len(user[3]) != 0:
    for result in user[3]:
        print (result)

# If user is not found, search through macaddress list (user[2] contains list)
if user[0] != True:
    # Specify timerange and correctly format for macaddress query (-7 days from infringementTime)
    macaddrQueryStartTime = datetime.datetime.strftime(infringementTime - datetime.timedelta(minutes=10080), "%Y-%m-%d %H:%M")
    macaddrQueryEndTime = datetime.datetime.strftime(infringementTime, "%Y-%m-%d %H:%M")

    # Prints results if results are found
    resultsList = trueUserObj.searchMacaddress(user[2], macaddrQueryStartTime, macaddrQueryEndTime)
    if len(resultsList) != 0:
        for result in resultsList:
            print (result)
