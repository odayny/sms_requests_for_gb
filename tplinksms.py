# A simple script to request additional 2GB for KPN unlimited plan using (Netherlands)
# It should be scheduled somehow.
# Logic:
# 1. Check if there are unread SMS
# 2. (Mark them as read)
# 3. If there is one which says that 80% of package is used:
# 4. Send sms to request another 2GB

# Limitations:
# - It developed for TpLink TL-MR100 v1 00000001 with software version 1.4.0 0.9.1 v0001.0 Build 210601 Rel.32393n

# Thanks to:
# https://github.com/hertzg/node-tplink-api
# https://github.com/0xf15h/tp_link_gdpr
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

LOGGING = True

AES_KEY: str = "A" * 16
AES_IV: str = "B" * 16


def log(message, tag):
    if LOGGING:
        os.system(f'logger -p {tag} -t tplinksms "{message}"')


def isBusy(session, ip_addr):
    headers = {
        "Referer": f"http://{ip_addr}",
    }
    resp = session.post(f"http://{ip_addr}/cgi/getBusy", headers=headers)
    match = re.search("isLogined=(\d)", resp.text)
    # On success, response should look like the following:
    #
    # var isLogined = 1;
    # var isBusy = 1;
    # $.ret = 0;
    if not match:
        log("Could not get isLogined", "err")
        return True
    isLogined = bool(int(match.group(1)))
    match = re.search("isBusy=(\d)", resp.text)
    if not match:
        log("Could not get isBusy", "err")
        return True
    isBusy = bool(int(match.group(1)))

    return isLogined and isBusy


def get_rsa_public_key(session, ip_addr):
    headers = {
        "Referer": f"http://{ip_addr}",
    }
    resp = session.post(f"http://{ip_addr}/cgi/getParm", headers=headers)

    # On success, response should look like the following:
    #
    # ```
    # [cgi]0
    # var ee="010001";
    # var nn="CB8FD67593B228445BBB882ED34B0787AF19AF3F6BE73793AC64BC64D3C4C41EBD149599F5801848DF92C244749DB07834789060B420979377D24DF7C7E437EB";
    # var seq="690699493";
    # $.ret=0;
    # [error]0
    # ```

    # Get the RSA public key (i.e. n and e values)
    match = re.search("nn=\"(.+)\"", resp.text)
    if not match:
        log("Could not find RSA n value in get RSA public key response", "err")
        return None
    # n_bytes = "9BAC4AA03461C3EBA7B22C10469F45F481E1AF4FB32F48D5E1850AAC9A2E803E1D02424418F8ACB3797E3A58FA4633350680019E10C309D649C9F044C2C7659F"
    n_bytes = match.group(1)
    match = re.search("ee=\"(.+)\"", resp.text)
    if not match:
        log("Could not find RSA e value in get RSA public key response", "err")
        return None
    # e_bytes = "010001"
    e_bytes = match.group(1)

    # Get the sequence. This is set to sequence += data_len and verified server-side.
    match = re.search("seq=\"(.+)\"", resp.text)
    if not match:
        log("Could not find seq value in get RSA public key response", err)
        return None
    # seq_bytes = "533202298"
    seq_bytes = match.group(1)
    exponent = int(e_bytes, 16)
    modulus = int(n_bytes, 16)
    sequence = int(seq_bytes, 10)
    return exponent, modulus, sequence


def encrypt(message, username, password, aes_key, aes_iv, sequence):
    enc_data = tp_link_crypto.aes_encrypt(aes_key, aes_iv, message.encode())  # This one seems ok
    data = base64.b64encode(enc_data).decode()
    seq_with_data_len = sequence + len(data)
    auth_hash = hashlib.md5(f"{username}{password}".encode()).digest()
    plaintext = f"key={aes_key.decode()}&iv={aes_iv.decode()}&h={auth_hash.hex()}&s={seq_with_data_len}"
    sign = tp_link_crypto.rsa_encrypt(e, n, plaintext.encode())
    return data, sign.hex()


def get_jsessionid(session, ip_addr, e, n, seq, username, password, aes_key, aes_iv):
    headers = {
        "Referer": f"http://{ip_addr}",
    }
    data, sign = encrypt(f"{username}\n{password}", username, password, aes_key, aes_iv, seq)
    resp = session.post(f"http://{ip_addr}/cgi/login?data={data}&sign={sign}&Action=1&LoginStatus=0", headers=headers)
    cookie = resp.headers["Set-Cookie"]
    if cookie is None:
        log("Login response did not include a Set-Cookie field in the header", "err")
        return None
    # Example of the cookie field:
    # ```
    # JSESSIONID=fc1e35a7a860e860be66d44bc7b34e; Path=/; HttpOnly
    # ```
    # Get the JSESSIONID field because it's used during other requests.
    match = re.search(r"JSESSIONID=([a-z0-9]+)", cookie)
    if not match:
        log("Could not find the JSESSIONID in the Set-Cookie filed of the login response", "err")
        return None
    jsessionid = match.group(1)
    return jsessionid


def generateAes():
    current_GMT = time.gmtime()
    time_stamp = calendar.timegm(current_GMT)
    random_n = random.uniform(0, 1) * 1000000000
    aes_key = f"{time_stamp}{random_n}"[:16]

    time_stamp = calendar.timegm(current_GMT)
    random_n = random.uniform(0, 1) * 1000000000
    aes_iv = f"{time_stamp}{random_n}"[:16]

    # aes_key = AES_KEY
    # aes_iv = AES_IV

    return aes_key.encode("utf-8"), aes_iv.encode("utf-8")


def get_token(session, device_ip, jsessionid):
    headers = {
        "Referer": f"http://{device_ip}",
        "Cookie": f"JSESSIONID={jsessionid}"
    }
    resp = session.get(f"http://{device_ip}/", headers=headers)
    match = re.search("token=\"(.+)\";", resp.text)
    if not match:
        log("Could not find token in response", "err")
        return None
    token = match.group(1)
    return token


def getUnread(device_ip, jsessionid, token, username, password, aes_key, aes_iv, sequence):
    headers = {
        "Referer": f"http://{device_ip}",
        "Cookie": f"JSESSIONID={jsessionid}",
        "TokenID": token,
        "Content-Type": "text/plain"
    }
    query = '1\r\n[LTE_SMS_UNREADMSGBOX#0,0,0,0,0,0#0,0,0,0,0,0]0,1\r\ntotalNumber\r\n'
    data, sign = encrypt(query, username, password, aes_key, aes_iv, sequence)
    resp = session.post(f"http://{device_ip}/cgi_gdpr", headers=headers, data=f"sign={sign}\r\ndata={data}\r\n")
    encrypted = base64.b64decode(resp.text)
    decrypted = tp_link_crypto.aes_decrypt(aes_key, aes_iv, encrypted)
    match = re.search("totalNumber=(.+)\n", decrypted.decode())
    return int(match.group(1), 10)


def getUnreadSMS(device_ip, jsessionid, token, username, password, aes_key, aes_iv, sequence):
    headers = {
        "Referer": f"http://{device_ip}",
        "Cookie": f"JSESSIONID={jsessionid}",
        "TokenID": token,
        "Content-Type": "text/plain"
    }
    query = "2&5\r\n[LTE_SMS_UNREADMSGBOX#0,0,0,0,0,0#0,0,0,0,0,0]0,1\r\npageNumber=1\r\n[LTE_SMS_UNREADMSGENTRY#0,0,0,0,0,0#0,0,0,0,0,0]1,5\r\nindex\r\nfrom\r\ncontent\r\nreceivedTime\r\nunread\r\n"
    data, sign = encrypt(query, username, password, aes_key, aes_iv, sequence)
    resp = session.post(f"http://{device_ip}/cgi_gdpr", headers=headers, data=f"sign={sign}\r\ndata={data}\r\n")
    encrypted = base64.b64decode(resp.text)
    decrypted = tp_link_crypto.aes_decrypt(aes_key, aes_iv, encrypted)
    matches = re.findall("\[(.*)\]1\nindex=(.*)\nfrom=(.*)\ncontent=(.*)\nreceivedTime=(.*)\nunread=(.*)", decrypted.decode())
    res = []
    for match in matches:
        msg = {}
        msg["stack"] = match[0]
        msg["id"] = match[1]
        msg["from"] = match[2]
        msg["content"] = match[3]
        msg["received"] = match[4]
        msg["unread"] = match[5]
        res.append(msg)
    return res


def setRead(device_ip, stack, jsessionid, token, username, password, aes_key, aes_iv, sequence):
    headers = {
        "Referer": f"http://{device_ip}",
        "Cookie": f"JSESSIONID={jsessionid}",
        "TokenID": token,
        "Content-Type": "text/plain"
    }
    # query = f"2\r\n[LTE_SMS_RECVMSGENTRY#{stack}#0,0,0,0,0,0]0,1\r\nunread=0\r\n"
    # query = f"2&1\r\n[LTE_SMS_RECVMSGENTRY#{stack}#0,0,0,0,0,0]0,1\r\nunread=0\r\n[LTE_SMS_RECVMSGBOX#0,0,0,0,0,0#0,0,0,0,0,0]1,0\r\n"
    query = f"2\r\n[LTE_SMS_UNREADMSGENTRY#{stack}#0,0,0,0,0,0]0,1\r\nunread=0\r\n"
    data, sign = encrypt(query, username, password, aes_key, aes_iv, sequence)
    resp = session.post(f"http://{device_ip}/cgi_gdpr", headers=headers, data=f"sign={sign}\r\ndata={data}\r\n")
    encrypted = base64.b64decode(resp.text)
    decrypted = tp_link_crypto.aes_decrypt(aes_key, aes_iv, encrypted)


def sendSms(device_ip, number, text, jsessionid, token, username, password, aes_key, aes_iv, sequence):
    headers = {
        "Referer": f"http://{device_ip}",
        "Cookie": f"JSESSIONID={jsessionid}",
        "TokenID": token,
        "Content-Type": "text/plain"
    }
    # query = f"2\r\n[LTE_SMS_RECVMSGENTRY#{stack}#0,0,0,0,0,0]0,1\r\nunread=0\r\n"
    # query = f"2&1\r\n[LTE_SMS_RECVMSGENTRY#{stack}#0,0,0,0,0,0]0,1\r\nunread=0\r\n[LTE_SMS_RECVMSGBOX#0,0,0,0,0,0#0,0,0,0,0,0]1,0\r\n"
    query = f"2\r\n[LTE_SMS_SENDNEWMSG#0,0,0,0,0,0#0,0,0,0,0,0]0,3\r\nindex=1\r\nto={number}\r\ntextContent={text}\r\n"
    data, sign = encrypt(query, username, password, aes_key, aes_iv, sequence)
    resp = session.post(f"http://{device_ip}/cgi_gdpr", headers=headers, data=f"sign={sign}\r\ndata={data}\r\n")
    encrypted = base64.b64decode(resp.text)
    decrypted = tp_link_crypto.aes_decrypt(aes_key, aes_iv, encrypted)


def logout(device_ip, jsessionid, token, username, password, aes_key, aes_iv, sequence):
    headers = {
        "Referer": f"http://{device_ip}",
        "Cookie": f"JSESSIONID={jsessionid}",
        "TokenID": token,
        "Content-Type": "text/plain"
    }
    # query = f"2\r\n[LTE_SMS_RECVMSGENTRY#{stack}#0,0,0,0,0,0]0,1\r\nunread=0\r\n"
    # query = f"2&1\r\n[LTE_SMS_RECVMSGENTRY#{stack}#0,0,0,0,0,0]0,1\r\nunread=0\r\n[LTE_SMS_RECVMSGBOX#0,0,0,0,0,0#0,0,0,0,0,0]1,0\r\n"
    query = "8\r\n[/cgi/clearBusy#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n"
    data, sign = encrypt(query, username, password, aes_key, aes_iv, sequence)
    resp = session.post(f"http://{device_ip}/cgi_gdpr", headers=headers, data=f"sign={sign}\r\ndata={data}\r\n")
    encrypted = base64.b64decode(resp.text)
    decrypted = tp_link_crypto.aes_decrypt(aes_key, aes_iv, encrypted)
    query = "8\r\n[/cgi/logout#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n"
    data, sign = encrypt(query, username, password, aes_key, aes_iv, sequence)
    resp = session.post(f"http://{device_ip}/cgi_gdpr", headers=headers, data=f"sign={sign}\r\ndata={data}\r\n")
    encrypted = base64.b64decode(resp.text)
    decrypted = tp_link_crypto.aes_decrypt(aes_key, aes_iv, encrypted)

if __name__ == '__main__':
    log("Checking for messages...", "notice")
    try:
        session = requests.Session()
        device_ip = '192.168.1.1'
        aes_key, aes_iv = generateAes();
        if isBusy(session, device_ip) :
            log("Router is busy. Skipping this time", "err")
            exit(94)
        # Get the RSA public key parameters and the sequence
        rsa_vals = get_rsa_public_key(session, device_ip)
        if rsa_vals is None:
            log("Failed to get RSA public key and sequence values", "err")
            exit(20)
        e, n, seq = rsa_vals
        password = 'admin'
        jsessionid = get_jsessionid(session, device_ip, e, n, seq, "admin", password, aes_key, aes_iv)
        if jsessionid is None or jsessionid == "deleted":
            log("Failed to get jsessionid", "err")
            exit(78)
        token = get_token(session, device_ip, jsessionid)
        unread = getUnread(device_ip, jsessionid, token, "admin", password, aes_key, aes_iv, seq)
        needToRenew = False
        if unread != 0:
            log("Fetching sms list", "notice")
            messages = getUnreadSMS(device_ip, jsessionid, token, "admin", password, aes_key, aes_iv, seq)
            for message in messages:
                if message["content"].__contains__("NL2000 AAN") and message["content"].__contains__("80%"):
                    needToRenew = True
                    log("Found 80% notification", "notice")
                setRead(device_ip, message["stack"], jsessionid, token, "admin", password, aes_key, aes_iv, seq)
        if needToRenew:
            log("Requesting package", "notice")
            sendSms(device_ip, "1266", "NL2000 AAN", jsessionid, token, "admin", password, aes_key, aes_iv, seq)

        logout(device_ip, jsessionid, token, "admin", password, aes_key, aes_iv, seq)
    except Exception as e:
        log(traceback.format_exc(), "err")
    log("Finished", "notice")
