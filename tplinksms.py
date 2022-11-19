import base64
import calendar
import hashlib
import os
import random
import re
import time
import traceback

import requests

import tp_link_crypto


def generateAes():
    current_gmt = time.gmtime()
    time_stamp = calendar.timegm(current_gmt)
    random_n = random.uniform(0, 1) * 1000000000
    aes_key = f"{time_stamp}{random_n}"[:16]

    time_stamp = calendar.timegm(current_gmt)
    random_n = random.uniform(0, 1) * 1000000000
    aes_iv = f"{time_stamp}{random_n}"[:16]

    return aes_key.encode("utf-8"), aes_iv.encode("utf-8")


DEVICE_IP = '192.168.1.1'
USERNAME = "admin"  # this is a default invisible username
PASSWORD = 'admin'
USE_LOGGER = False

AES_KEY, AES_IV = generateAes()
SESSION = requests.Session()
GENERIC_HEADERS = {"Referer": f"http://{DEVICE_IP}"}


def log(message, tag):
    if USE_LOGGER:
        os.system(f'logger -p {tag} -t tplinksms "{message}"')
    else:
        print(f"{tag}: {message}")


def isBusy():
    """
    Checks is someone else is logged is to the web interface
    :return:
    """
    resp = SESSION.post(f"http://{DEVICE_IP}/cgi/getBusy", headers=GENERIC_HEADERS)

    # On success, response should look like the following:
    #
    # var isLogined=1;
    # var isBusy=1;
    # $.ret=0;

    match = re.search("isLogined=(\d)", resp.text)
    if not match:
        log("Could not get isLogined", "err")
        return True
    is_logged_in = bool(int(match.group(1)))

    match = re.search("isBusy=(\d)", resp.text)
    if not match:
        log("Could not get isBusy", "err")
        return True
    is_busy = bool(int(match.group(1)))

    return is_logged_in and is_busy


def get_rsa_public_key():
    """
    Requests RSA public keys from a router and stores it in a global scope

    :return:
    """
    global EXPONENT, MODULUS, SEQUENCE

    resp = SESSION.post(f"http://{DEVICE_IP}/cgi/getParm", headers=GENERIC_HEADERS)

    # On success, response should look like the following:
    #
    # [cgi]0
    # var ee="010001";
    # var nn="CB8FD67593B228445BBB882ED34B0787AF19AF3F6BE73793AC64BC64D3C4C41EBD149599F5801848DF92C244749DB07834789060B420979377D24DF7C7E437EB";
    # var seq="690699493";
    # $.ret=0;

    match = re.search("nn=\"(.+)\"", resp.text)
    if not match:
        raise Exception("Could not find RSA n value in get RSA public key response")
    n_bytes = match.group(1)

    match = re.search("ee=\"(.+)\"", resp.text)
    if not match:
        raise Exception("Could not find RSA e value in get RSA public key response")
    e_bytes = match.group(1)

    match = re.search("seq=\"(.+)\"", resp.text)
    if not match:
        raise Exception("Could not find seq value in get RSA public key response")
    seq_bytes = match.group(1)

    EXPONENT = int(e_bytes, 16)
    MODULUS = int(n_bytes, 16)
    SEQUENCE = int(seq_bytes, 10)


def encrypt(message):
    """
    Encrypts the message to router.
    :param message: message to encrypt
    :return: data and sigh fieds
    """
    enc_data = tp_link_crypto.aes_encrypt(AES_KEY, AES_IV, message.encode())
    data = base64.b64encode(enc_data).decode()

    seq_with_data_len = SEQUENCE + len(data)
    auth_hash = hashlib.md5(f"{USERNAME}{PASSWORD}".encode()).digest()
    plaintext = f"key={AES_KEY.decode()}&iv={AES_IV.decode()}&h={auth_hash.hex()}&s={seq_with_data_len}"
    sign = tp_link_crypto.rsa_encrypt(EXPONENT, MODULUS, plaintext.encode())
    return data, sign.hex()


def get_jsessionid():
    """
    Requests jsession id from router (basically: just logins)
    :return:
    """
    global JSESSIONID

    data, sign = encrypt(f"{USERNAME}\n{PASSWORD}")
    resp = SESSION.post(f"http://{DEVICE_IP}/cgi/login?data={data}&sign={sign}&Action=1&LoginStatus=0",
                        headers=GENERIC_HEADERS)
    cookie = resp.headers["Set-Cookie"]
    # Example of the cookie field:
    #
    # JSESSIONID=fc1e35a7a860e860be66d44bc7b34e; Path=/; HttpOnly

    if cookie is None:
        raise Exception("Login response did not include a Set-Cookie field in the header")

    match = re.search(r"JSESSIONID=([a-z0-9]+)", cookie)
    if not match:
        raise Exception(f"Could not find the JSESSIONID in the Set-Cookie filed of the login response {cookie}")
    JSESSIONID = match.group(1)
    if JSESSIONID == "deleted":
        raise Exception(f"Bad JSESSIONID: {JSESSIONID}")


def get_token():
    """
    Requests token used by client. It's hidden somewhere on the main page.
    """
    headers = {
        "Referer": f"http://{DEVICE_IP}",
        "Cookie": f"JSESSIONID={JSESSIONID}"
    }
    resp = SESSION.get(f"http://{DEVICE_IP}/", headers=headers)
    match = re.search("token=\"(.+)\";", resp.text)
    if not match:
        raise Exception("Could not find token in response")
    global TOKEN
    TOKEN = match.group(1)


def prep_headers():
    return {
        "Referer": f"http://{DEVICE_IP}",
        "Cookie": f"JSESSIONID={JSESSIONID}",
        "TokenID": TOKEN,
        "Content-Type": "text/plain"
    }


def getUnreadCount():
    query = '1\r\n[LTE_SMS_UNREADMSGBOX#0,0,0,0,0,0#0,0,0,0,0,0]0,1\r\ntotalNumber\r\n'
    data, sign = encrypt(query)
    resp = SESSION.post(f"http://{DEVICE_IP}/cgi_gdpr", headers=prep_headers(),
                        data=f"sign={sign}\r\ndata={data}\r\n")
    encrypted_response = base64.b64decode(resp.text)
    decrypted_response = tp_link_crypto.aes_decrypt(AES_KEY, AES_IV, encrypted_response)
    # Example of success response
    #
    # '[0,0,0,0,0,0]0\ntotalNumber=0\n[error]0\n\n\n\n\n\n\n\n\n\n\n'

    validateForError(decrypted_response.decode())
    match = re.search("totalNumber=(.+)\n", decrypted_response.decode())
    return int(match.group(1), 10)


def getUnreadSMS():
    """
    Requests unread sms list.
    Seems like first a page number need to be defined.
    :return: list of unread sms
    """
    query = "2&5\r\n[LTE_SMS_UNREADMSGBOX#0,0,0,0,0,0#0,0,0,0,0,0]0,1\r\npageNumber=1\r\n[LTE_SMS_UNREADMSGENTRY#0,0,0,0,0,0#0,0,0,0,0,0]1,5\r\nindex\r\nfrom\r\ncontent\r\nreceivedTime\r\nunread\r\n"
    data, sign = encrypt(query)
    resp = SESSION.post(f"http://{DEVICE_IP}/cgi_gdpr", headers=prep_headers(), data=f"sign={sign}\r\ndata={data}\r\n")
    encrypted = base64.b64decode(resp.text)
    decrypted = tp_link_crypto.aes_decrypt(AES_KEY, AES_IV, encrypted)
    # Example:
    # [1,0,0,0,0,0]1
    # index=11
    # from=1234
    # content=Hello
    # receivedTime=2022-11-18 21:02:50
    # unread=1
    # [2,0,0,0,0,0]1
    # index=10
    # from=4321
    # content=Darkness my old friend
    # receivedTime=2022-11-17 21:47:55
    # unread=1
    # [error]0
    # (and bunch of \n)
    validateForError(decrypted.decode())
    matches = re.findall("\[(.*)\]1\nindex=(.*)\nfrom=(.*)\ncontent=(.*)\nreceivedTime=(.*)\nunread=(.*)",
                         decrypted.decode())
    res = []
    for match in matches:
        msg = {
            "stack": match[0],  # this is needed to mark as read
            "id": match[1],  # this is not needed
            "from": match[2],  # sender
            "content": match[3],  # text
            "received": match[4],  # when received (not needed as well)
            "unread": match[5]  # always 1 in this case
        }
        res.append(msg)
    return res


def validateForError(decrypted):
    match = re.search("\[error\](.*)\n", decrypted)
    if not match or int(match.group(1), 10) != 0:
        raise Exception(f"Error not present or non 0: {decrypted}")


def setRead(msg_stack):
    """
    Mark a message as read.
    Message identified by stack value (same as in web-ui)
    Why not id? Have no idea.

    If you want to reuse it: pay attention to scope: LTE_SMS_RECVMSGENTRY and LTE_SMS_UNREADMSGENTRY are not the same!

    :param msg_stack: message's stack
    """

    query = f"2\r\n[LTE_SMS_UNREADMSGENTRY#{msg_stack}#0,0,0,0,0,0]0,1\r\nunread=0\r\n"
    data, sign = encrypt(query)
    resp = SESSION.post(f"http://{DEVICE_IP}/cgi_gdpr", headers=prep_headers(), data=f"sign={sign}\r\ndata={data}\r\n")
    encrypted = base64.b64decode(resp.text)
    decrypted = tp_link_crypto.aes_decrypt(AES_KEY, AES_IV, encrypted)
    validateForError(decrypted.decode())


def sendSms(number, text):
    query = f"2\r\n[LTE_SMS_SENDNEWMSG#0,0,0,0,0,0#0,0,0,0,0,0]0,3\r\nindex=1\r\nto={number}\r\ntextContent={text}\r\n"
    data, sign = encrypt(query)
    resp = SESSION.post(f"http://{DEVICE_IP}/cgi_gdpr", headers=prep_headers(), data=f"sign={sign}\r\ndata={data}\r\n")
    encrypted = base64.b64decode(resp.text)
    decrypted = tp_link_crypto.aes_decrypt(AES_KEY, AES_IV, encrypted)
    validateForError(decrypted.decode())


def logout():
    query = "8\r\n[/cgi/clearBusy#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n"
    data, sign = encrypt(query)
    resp = SESSION.post(f"http://{DEVICE_IP}/cgi_gdpr", headers=prep_headers(), data=f"sign={sign}\r\ndata={data}\r\n")
    encrypted = base64.b64decode(resp.text)
    decrypted = tp_link_crypto.aes_decrypt(AES_KEY, AES_IV, encrypted)
    validateForError(decrypted.decode())

    query = "8\r\n[/cgi/logout#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n"
    data, sign = encrypt(query)
    resp = SESSION.post(f"http://{DEVICE_IP}/cgi_gdpr", headers=prep_headers(), data=f"sign={sign}\r\ndata={data}\r\n")
    encrypted = base64.b64decode(resp.text)
    decrypted = tp_link_crypto.aes_decrypt(AES_KEY, AES_IV, encrypted)
    validateForError(decrypted.decode())


def main():
    global e, n
    log("Checking for messages...", "notice")
    try:
        if isBusy():
            log("Router is busy. Skipping for this time", "err")
            exit(94)
        get_rsa_public_key()
        get_jsessionid()
        get_token()
        unread = getUnreadCount()
        need_to_renew = False
        if unread != 0:
            log("Fetching sms list", "notice")
            messages = getUnreadSMS()
            for message in messages:
                if message["content"].__contains__("NL2000 AAN") and message["content"].__contains__("80%"):
                    need_to_renew = True
                    log("Found 80% notification", "notice")
                setRead(message["stack"])
        if need_to_renew:
            log("Requesting package", "notice")
            sendSms("1266", "NL2000 AAN")
        logout()
    except Exception as e:
        log(traceback.format_exc(), "err")
    log("Finished", "notice")


if __name__ == '__main__':
    main()
