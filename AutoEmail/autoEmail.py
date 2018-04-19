import credentials
import sys
import smtplib

# email = email to send from
# password = email password
def connect(email, password):
    try:
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.ehlo()
        server.login(email, password)
    except:
        print (sys.exc_info()[1])
    return server

# to = array of emails to send to
# cc = array of emails to cc to
# subject = email subject
# body = email body
def send(server, email, to, cc, subject, body):
    msg  = "From: " + email + "\n"
    msg += "To: " + ",".join(to) + "\n"
    msg += "CC: " + ",".join(cc) + "\n"
    msg += "Subject: " + subject + "\n\n"
    msg += body

    server.sendmail(email, to, msg)
    server.quit()

to = []
cc = []
server = connect(credentials.gmail_user, credentials.gmail_pass)
send(server, credentials.gmail_user, to, cc, "Hello", "Herro")
