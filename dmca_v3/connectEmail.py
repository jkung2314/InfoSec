"""
author: Maria Vizcaino (mvizcain)
Updated by: Jonathan Kung (jhkung)
connectEmail.py (Updated for Python 3)

Connect to an email address & return emails within a time frame
"""
import sys
import imaplib
import datetime
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

#***********************************************************
#Function "connect"
# takes in email and plaintxt password
# optionally takes in number of days to go back in emails and
#    which inbox to look for emails, default is '1' and 'Inbox'
# returns body's of emails in a list
# default server is gmail

def connect(email, password, days = 1, inbox = 'Inbox'):

  #Set up connection
  mail = imaplib.IMAP4_SSL('imap.gmail.com')

  #Try to login with credentials, exits if unable to auth
  try:
    mail.login(email, password)
  except:
    print (sys.exc_info()[1])
    sys.exit(1)

  #Select which inbox to get emails from
  mail.select(inbox)

  #Set the dates
  today = (datetime.date.today() -
      datetime.timedelta(0)).strftime("%d-%b-%Y")
  pastDate = (datetime.date.today() -
      datetime.timedelta(days)).strftime("%d-%b-%Y")

  #Get positions of ZZemails in time frame
  result, data = mail.search\
      (None,'(SINCE {yesterday} BEFORE {today})'.format\
      (yesterday=pastDate,today=today))

  #Store emails
  emails = data[0].split()

  #Initialize structures to store email bodies (& headers)
  bodies = []
  #headers = []

  #Loop through emails to get the bodies (& headers)
  for email in emails:
    result, body = mail.fetch(email, '(RFC822)')
    bodies.append(body[0][1].replace(b'\r', b''))
    #result, header = mail.fetch(email, '(BODY.PEEK[HEADER])')
    #headers.append(header[0][1].replace('\r', '')

  mail.close()
  return bodies

  #if you want to return header and body, comment line above
  #and uncomment line below
  #return headers, bodies

#***********************************************************

#***********************************************************
#Function "sendEmail"
# take in email, password to that email, list of people to
# email, subject and message of email
# returns nothing
# Sends email to chbright & abuse

def sendEmail(email, password, toList, subject, message):

  intro = 'The following are a list of DMCA notices received '\
          'via email from yesterday.\n\n\n'
  # We can use localhost to send mail as google smtp is blocked by the departmental firewall
  smtpserver=('localhost')
  header  = 'From: %s\n' % email
  header += 'To: %s\n' % ','.join(toList)
  header += 'Subject: %s\n\n' % subject
  message = header + intro +  message
  print (header)

  server = smtplib.SMTP(smtpserver)
  # if localhost is used we don't estalbish TLS or user login.
  #server = smtplib.SMTP('smtp.gmail.com', 587)
  #server.starttls()
  #server.login(email, password.decode())
  problems = server.sendmail(email, toList, message)
  server.quit()

#***********************************************************
