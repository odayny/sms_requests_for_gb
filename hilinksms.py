# A simple script to request additional 2GB for KPN unlimited plan using (Netherlands)
# It should be scheduled somehow.
# Logic:
# 1. Check if there are unread SMS
# 2. (Mark them as read)
# 3. If there is one which says that 80% of package is used:
# 4. Send sms to request another 2GB

# Limitations:
# - It developed for Huawei E3372 with software version 22.328.62.00.1217
# - Password authorization is not implemented (Password can be disabled http://192.168.8.1/html/modifypassword.html)

# Thanks to:
# https://github.com/lmoodie/huawei-3G-SMS-API

import traceback
import requests
import xmltodict
from datetime import datetime
import os

SMS_LIST_TEMPLATE = '''<request>
    <PageIndex>1</PageIndex>
    <ReadCount>20</ReadCount>
    <BoxType>1</BoxType>
    <SortType>0</SortType>
    <Ascending>0</Ascending>
    <UnreadPreferred>1</UnreadPreferred>
    </request>'''

LOGGING = True


def getHeaders(device_ip):
    token = None
    sessionID = None
    r = requests.get(url='http://' + device_ip + '/api/webserver/SesTokInfo')
    d = xmltodict.parse(r.text, xml_attribs=True)
    if 'response' in d and 'TokInfo' in d['response']:
        token = d['response']['TokInfo']
    d = xmltodict.parse(r.text, xml_attribs=True)
    if 'response' in d and 'SesInfo' in d['response']:
        sessionID = d['response']['SesInfo']
    headers = {'__RequestVerificationToken': token, 'Cookie': sessionID}
    return headers


def getUnread(device_ip):
    headers = getHeaders(device_ip)
    r = requests.get(url = 'http://' + device_ip + '/api/monitoring/check-notifications', headers = headers)
    d = xmltodict.parse(r.text, xml_attribs=True)
    unread = int(d['response']['UnreadMessage'])
    return unread


def getContent(data, numMessages):
    messages = []
    for i in range(numMessages):
        message = data[i]
        number = message['Phone']
        content = message['Content']
        date = message['Date']
        messages.append('Message from ' + number + ' recieved ' + date + ' : ' + str(content))
    return messages


def getSMS(device_ip):
    headers = getHeaders(device_ip)
    r = requests.post(url = 'http://' + device_ip + '/api/sms/sms-list', data = SMS_LIST_TEMPLATE, headers = headers)
    d = xmltodict.parse(r.text, xml_attribs=True)
    numMessages = int(d['response']['Count'])
    messagesR = d['response']['Messages']['Message']
    if numMessages == 1:
        temp = messagesR
        messagesR = [temp]
    return messagesR


def setRead(device_ip, sms_id):
    headers = getHeaders(device_ip)
    r = requests.post(url = 'http://' + device_ip + '/api/sms/set-read', data = f"<request><Index>{sms_id}</Index></request>", headers = headers)
    d = xmltodict.parse(r.text, xml_attribs=True)
    return (d['response'])


def sendSms(device_ip, number, content):
    template = f"""<request>
    <Index>-1</Index>
    <Phones><Phone>{number}</Phone></Phones>
    <Sca></Sca>
    <Content>{content}</Content>
    <Length>{len(content)}</Length>
    <Reserved>1</Reserved>
    <Date>{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</Date>
    </request>"""

    headers = getHeaders(device_ip)
    r = requests.post(url = 'http://' + device_ip + '/api/sms/send-sms',
                      data = template, headers = headers)
    d = xmltodict.parse(r.text, xml_attribs=True)
    return (d['response'])

def log(message, tag):
    if LOGGING:
        os.system(f'logger -p {tag} -t hilinkssms "{message}"')


if __name__ == '__main__':
    log("Checking for messages...", "notice")
    try:
        device_ip = '192.168.8.1'
        unread = getUnread(device_ip)
        needToRenew = False
        if unread != 0:
            log("Fetching sms list", "notice")
            messages = getSMS(device_ip)
            for message in messages:
                if message["Smstat"] == "0":
                    if message["Content"].__contains__("NL2000 AAN") and message["Content"].__contains__("80%"):
                        needToRenew = True
                        log("Found 80% notification", "notice")
                    setRead(device_ip, message["Index"])
        if needToRenew:
            log("Requesting package", "notice")
            sendSms(device_ip, "1266", "NL2000 AAN")
    except Exception as e:
        log(traceback.format_exc(), "err")
    log("Finished", "notice")

