import os
import traceback
from datetime import datetime

import requests
import xmltodict

USE_LOGGER = True
DEVICE_IP = '192.168.8.1'


def getHeaders():
    """
    Request headers for any further requests.
    Sometimes headers became invalid for some reason so it's better to request them again for each request.
    :return: headers dict
    """
    token = None
    session_id = None
    resp = requests.get(url=f'http://{DEVICE_IP}/api/webserver/SesTokInfo')
    resp_body = xmltodict.parse(resp.text, xml_attribs=True)
    if 'response' in resp_body:
        if 'TokInfo' in resp_body['response']:
            token = resp_body['response']['TokInfo']
        if 'SesInfo' in resp_body['response']:
            session_id = resp_body['response']['SesInfo']
        headers = {'__RequestVerificationToken': token, 'Cookie': session_id}
        return headers
    else:
        raise Exception("Bad token request response")


def getUnreadCount():
    headers = getHeaders()
    response = requests.get(url=f'http://{DEVICE_IP}/api/monitoring/check-notifications', headers=headers)
    response_body = xmltodict.parse(response.text, xml_attribs=True)
    unread = int(response_body['response']['UnreadMessage'])
    return unread


def getSMS():
    sms_list_template = '''<request>
        <PageIndex>1</PageIndex>
        <ReadCount>20</ReadCount>
        <BoxType>1</BoxType>
        <SortType>0</SortType>
        <Ascending>0</Ascending>
        <UnreadPreferred>1</UnreadPreferred>
        </request>'''
    headers = getHeaders()
    response = requests.post(url=f'http://{DEVICE_IP}/api/sms/sms-list', data=sms_list_template, headers=headers)
    response_body = xmltodict.parse(response.text, xml_attribs=True)
    messages_count = int(response_body['response']['Count'])
    messages = response_body['response']['Messages']['Message']
    if messages_count == 1:
        temp = messages
        messages = [temp]
    return messages


def setRead(sms_id):
    """
    Mark SMS as read to skip it in the future.
    :param sms_id: sms id (Index)
    """
    headers = getHeaders()
    response = requests.post(url=f'http://{DEVICE_IP}/api/sms/set-read',
                             data=f"<request><Index>{sms_id}</Index></request>", headers=headers)
    response_body = xmltodict.parse(response.text, xml_attribs=True)
    if response_body['response'] != "OK":
        log(f"Cannot mark SMS {sms_id} as read. Hope it won't cause any issues in the future", "err")


def sendSms(number, content):
    template = f"""<request>
    <Index>-1</Index>
    <Phones><Phone>{number}</Phone></Phones>
    <Sca></Sca>
    <Content>{content}</Content>
    <Length>{len(content)}</Length>
    <Reserved>1</Reserved>
    <Date>{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</Date>
    </request>"""

    headers = getHeaders()
    response = requests.post(url=f'http://{DEVICE_IP}/api/sms/send-sms',
                             data=template, headers=headers)
    response_body = xmltodict.parse(response.text, xml_attribs=True)
    if response_body['response'] != "OK":
        log(f"Cannot send SMS {content} to {number}.", "err")


def log(message, tag):
    if USE_LOGGER:
        os.system(f'logger -p {tag} -t hilinkssms "{message}"')
    else:
        print(f"{tag}: {message}")


def main():
    log("Checking for messages...", "notice")
    try:
        unread = getUnreadCount()
        if unread != 0:
            need_to_renew = False
            log("Fetching SMS list", "notice")
            messages = getSMS()
            for message in messages:
                if message["Smstat"] == "0":  # if unread
                    if message["Content"].__contains__("NL2000 AAN") and message["Content"].__contains__("80%"):
                        need_to_renew = True
                        log("Found 80% notification", "notice")
                    setRead(message["Index"])
            if need_to_renew:
                log("Requesting package", "notice")
                sendSms("1266", "NL2000 AAN")
    except Exception as e:
        log(traceback.format_exc(), "err")
    log("Finished", "notice")


if __name__ == '__main__':
    main()
