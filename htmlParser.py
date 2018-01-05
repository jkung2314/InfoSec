import bs4 as bs
import csv
import urllib2
import re

def process(url, name, action):
    resp = urllib2.urlopen(url).read()

    #search for Syslog Message Codes
    codes = re.findall(r'<h3 class="topictitle3">(.*?)</h3>', str(resp))
    numArray = []
    for i in codes:
        numArray.append(i)

    #search for Explanations
    expArray = []
    soup = bs.BeautifulSoup(resp, 'lxml')
    p = soup.find_all('p')
    explanations = re.findall(r'Explanation(.*?)</p>', str(p))
    for i in explanations:
        a = str(i)
        a = a.replace('</strong>', '').replace('</span>', ' ').replace('<span class="uicontrol">',' ').replace('\\t','').replace('\\n',' ')
        expArray.append(a)

    #write to CSV
    with open (name, action) as document:
        writeFile = csv.writer(document)
        for i in range(len(numArray)):
            code = numArray[i]
            explanation = expArray[i]
            writeFile.writerow([code, explanation])
    document.close()

    print "Added", len(numArray), "rows"

url = 'https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/b_syslog/syslogs10.html'
name = "cisco.csv"
action = "a" #append
process(url, name, action)
