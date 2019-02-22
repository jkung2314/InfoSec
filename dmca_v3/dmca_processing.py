import base64
import credentials as c
import connectEmail
import sys
import re
import datetime
import pytz
import time
from xmljson import badgerfish as bf
from xml.etree.ElementTree import fromstring
from json import dumps
from json import loads
from ipaddress import ip_network, ip_address
from trueUser import trueUser

def to_pst(dateconvert):

        if not re.search(r"[0-9]+-[0-9]+-[0-9]+ [0-9]+:[0-9]+:[0-9]+.[0-9]+ GMT", \
                         dateconvert) is None:
            fmt = '%Y-%m-%d %H:%M:%S.%f GMT'
        elif not re.search(r"[0-9]+-[0-9]+-[0-9]+T[0-9]+:[0-9]+:[0-9]+Z", \
                           dateconvert) is None:
            fmt = '%Y-%m-%dT%H:%M:%SZ'
        else:
            fmt = '%Y-%m-%dT%H:%M:%S.%fZ'

        # convert GMT/ZULU to PST
        # create 'naive' datetime object
        utc_dt = datetime.datetime.strptime(dateconvert, str(fmt))

        # make datetime object 'aware'
        utc_dt = pytz.utc.localize(utc_dt)

        # create PST time zone
        pa_tz = pytz.timezone('US/Pacific')

        # convert UTC to PST
        pa_dt = pa_tz.normalize(utc_dt.astimezone(pa_tz))

        # convert PST datetime object to a string
        dateconvert = str(pa_dt)

        # cut off excess time info
        dateconvert = re.split('-[0-9]{2}:[0-9]{2}$', dateconvert)[0]

        # check for ending decimal format
        if not re.search('[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}.[0-9]+', dateconvert) is None:
            dateconvert = re.split('.[0-9]+$', dateconvert)[0]

        return dateconvert


def to_timestamp(date):
    # convert pst date to unix timestamp
    ts = time.mktime(datetime.datetime.strptime(date, "%Y-%m-%d %H:%M:%S").timetuple())

    return ts


def formatEmailBodyToJson(emailBody):
    ## Flatten this email text into a single line of text suitable for translaction into json

    # emails come out of google with a line limit and the continuation character is an equals sign
    # look for an equals sign followed by a new line and remove that.
    emailBody = emailBody.replace(b'=\n', b'')

    # This data from google also has some html escape artifacts, %3D would be an equals sign, instead we
    # are just left with 3D. Remove it.
    emailBody = emailBody.replace(b'3D', b'')

    # The media companies also pollute their xml with a bunch of garbage that makes conversion to json impossible
    # Remove it. This is all found inside the <Infringement> tag.
    emailBody = emailBody[:emailBody.find(b'xmlns=')] + emailBody[emailBody.find(b'.xsd\"') + 5:]

    # At this stage we still have the entire email. We only want the XML data. Look for the start of the XML.
    # Typically the XML ends with the closing Infringement tag so look for that to signify the end of the XML.
    xmlstart = emailBody.find(b"<?xml")
    xmlend = emailBody.find(b"</Infringement>") + len(b"</Infringement>")

    # slice the email text into just the XML now that we have found starting and ending positions.
    emailBody = emailBody[xmlstart:xmlend]

    # Convert this XML into json data.
    jsondata = loads(dumps((bf.data(fromstring(emailBody)))))

    return jsondata


def send_email(results, start_time):
    subjectLine = '**DMCA Report**'
    message = results
    message += '\n\n' + \
               ("DMCA script finished in %s seconds" % (time.time() - start_time + 1.5))

    connectEmail.sendEmail(c.dmcauser, base64.b64decode(c.dmcapass), ['brian@ucsc.edu','liz@ucsc.edu','tjwright@ucsc.edu'], subjectLine, message)


def main():
    start_time = time.time()
    dataholder = {}

    # Initialize trueUser identification class
    trueUserObj = trueUser()

    # Get emails from the dmca email account
    bodiesOfEmails = connectEmail.connect(c.dmcauser, base64.urlsafe_b64decode(c.dmcapass.encode()).decode(), 1, 'dmca')

    # Parse each email body storing similar IPs into the dataholder variable
    print("numberofemails: {}".format(len(bodiesOfEmails)))
    for body in bodiesOfEmails:

        # convert and truncate the email body to usable json case data
        jsondata = formatEmailBodyToJson(body)

        # store the fields we need from the infringement case
        caseid = str(jsondata['Infringement']['Case']['ID'].get('$'))
        ip = str(jsondata['Infringement']['Source']['IP_Address'].get('$'))
        port = str(jsondata['Infringement']['Source']['Port'].get('$'))
        tstamp = str(jsondata['Infringement']['Source']['TimeStamp'].get('$'))
        fname = str(jsondata['Infringement']['Content']['Item']['FileName'].get('$'))
        title = str(jsondata['Infringement']['Content']['Item']['Title'].get('$'))

        # We use this so we can 'rollup' the case data with each unique IP.
        # if we already have an entry in the holder for this IP append the new case to the array stored in the
        # holder dictionary
        # else, create a new array associated with the ip in the dictionary and populate the array with the array
        # of case values.
        if ip in dataholder:
            dataholder[ip].append([caseid, ip, port, tstamp, fname, title])
        else:
            dataholder[ip] = [[caseid, ip, port, tstamp, fname, title]]


    # Build the email and also look for users
    msg = ''
    for ip in dataholder:
        msg = msg + ip # item is the IP address
        msg = msg + "\n" + "---------------------------------------------------------------------------------------------\n"

        for case in dataholder[ip]:
            # Pythonized time object in PST
            pythonizedInfringementTime = datetime.datetime.strptime(case[3], "%Y-%m-%dT%H:%M:%SZ")
            utc = pytz.timezone('UTC')
            infringementTime = utc.localize(pythonizedInfringementTime)
            infringementTime = infringementTime.astimezone(pytz.timezone('US/Pacific'))

            natted = False
            # Get correct ip
            network = ip_network("128.114.255.0/28")
            infringementIP = case[1]
            if ip_address(infringementIP) in network:
                # Get netflow start + end times
                netflowStartTime = datetime.datetime.strftime(infringementTime - datetime.timedelta(minutes=10), "%Y-%m-%d %H:%M")
                netflowEndTime = datetime.datetime.strftime(infringementTime + datetime.timedelta(minutes=10), "%Y-%m-%d %H:%M")
                trueIP = trueUserObj.getTrueIP(case[2], case[1], netflowStartTime, netflowEndTime)
                natted = True
                # If can't locate trueIP
                if trueIP == None:
                    msg = msg + "CASE ID: {0}\n".format(case[0])
                    msg = msg + "IP: \t{0}\n".format(case[1])
                    msg = msg + "TRUE IP: NOT FOUND\n".format(trueIP)
                    msg = msg + "Port: \t{0}\n".format(case[2])
                    msg = msg + "TIMESTAMP: {0} Pacific\n".format(to_pst(case[3]))
                    msg = msg + "FILENAME: {0}\n".format(case[4])
                    msg = msg + "TITLE: \t{0}\n".format(case[5])
                    msg = msg + "USERS: \n"
                    msg = msg + "TRUE IP NOT FOUND, CONTINUING TO NEXT CASE..."
                    continue
            else:
                trueIP = infringementIP

            msg = msg + "CASE ID: {0}\n".format(case[0])
            msg = msg + "IP: \t{0}\n".format(case[1])
            if natted:
                msg = msg + "TRUE IP: {0}\n".format(trueIP)
            msg = msg + "Port: \t{0}\n".format(case[2])
            msg = msg + "TIMESTAMP: {0} Pacific\n".format(to_pst(case[3]))
            msg = msg + "FILENAME: {0}\n".format(case[4])
            msg = msg + "TITLE: \t{0}\n".format(case[5])
            msg = msg + "USERS: \n"

            # User identification
            userQueryStartTime = datetime.datetime.strftime(infringementTime - datetime.timedelta(minutes=240), "%Y-%m-%d %H:%M")
            userQueryEndTime = datetime.datetime.strftime(infringementTime + datetime.timedelta(minutes=120), "%Y-%m-%d %H:%M")
            users = trueUserObj.getUser(trueIP, userQueryStartTime, userQueryEndTime)

            # If results are found but user is null, run macaddress search
            if len(users[2]) != 0 and users[0] != True:
                # Print found results from user identification query, if exists
                if len(users[3]) != 0:
                    for user in users[3]:
                        msg = msg + "username: {0}, userAffiliation: {1}, authsource: {2}, macaddress: {3}, authtime: {4}\n".format(user[1], user[2], user[4], user[3], user[0])
                macaddrQueryStartTime = datetime.datetime.strftime(infringementTime - datetime.timedelta(minutes=10080), "%Y-%m-%d %H:%M")
                macaddrQueryEndTime = datetime.datetime.strftime(infringementTime, "%Y-%m-%d %H:%M")
                resultsList = trueUserObj.searchMacaddress(users[2], macaddrQueryStartTime, macaddrQueryEndTime)
                if resultsList is not None:
                    for result in resultsList:
                        msg = msg + "username: {0}, userAffiliation: {1}, authsource: {2}, macaddress: {3}, authtime: {4}\n".format(result[1], result[2], result[6], result[3], result[0])
                    msg = msg + "\n\n"
            # If results are found and there exists one non-null user identified, print rows
            elif len(users[3]) != 0 and users[0] == True:
                for user in users[3]:
                    msg = msg + "username: {0}, userAffiliation: {1}, authsource: {2}, macaddress: {3}, authtime: {4}\n".format(user[1], user[2], user[4], user[3], user[0])
                msg = msg + "\n\n"
            # If no results found from user or macaddress search
            else:
                msg = msg + "No login entries for any users found\n\n"
    send_email(msg, start_time)


main()
print("done...")
