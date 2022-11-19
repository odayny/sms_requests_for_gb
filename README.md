[![SWUbanner](https://raw.githubusercontent.com/vshymanskyy/StandWithUkraine/main/banner-direct-single.svg)](https://stand-with-ukraine.pp.ua/)

# Requesting additional data package from my provider

## Problem

I'm using a couple of 4G devices with unlimited data plan, but my provider has a data cap 10GB per day after which another 2GB may be requested via SMS.

Luckily my provider also notifies user about 80% and 100% usage of daily data or additional packages and my 4G devices can send/receive messages.

So the plan is something like this:
```
┌───────────────────┐
│ Login to a device │
└─────────┬─────────┘
          │
┌─────────▼────────────────┐ No
│ Is there any unread SMS? ├─────────┐
└────┬─────────────────────┘         │
  Yes│                               │
┌────▼──────────────────────┐ No     │
│ Is it a 80% notification? ├────────┤
└────┬──────────────────────┘        │
  Yes│                               │
┌────▼───────────────────────────┐   │
│ Send a request for another 2GB │   │
└────────┬───────────────────────┘   │
         │                           │
┌────────▼────────────────────────┐  │
│ (And mark all messages as read) │  │
└────────┬────────────────────────┘  │
         │                           │
┌────────▼────────────┐              │
│ (And logout please) │              │
└─────┬───────────────┘              │
      │                              │
┌─────▼───┐                          │
│ OK, bye │◄─────────────────────────┘
└─────────┘
```

## Implementation

### Huawei E3372 (HiLink)

The first device is a [USB-dongle which pretends to be a router](https://consumer.huawei.com/en/routers/e3372/).
Fortunately, the guys from Huawei didn't bother to make things complicated and even provide an ability to disable password. 

Endpoints are clear and understandable, only requirement is to request headers to use with each request.
Sometimes headers became invalid, so my solution was pretty straightforward: just request new pair before each request.

Kudos to [lmoodie](https://github.com/lmoodie) for the [implementation](https://github.com/lmoodie/huawei-3G-SMS-API) of the most part of this project.

You can find my implementation in ``hilinksms.py``.
```
Tested on E3372 with sowftware version 22.328.62.00.1217.
Seems like it works just fine.
```

### TpLink TL-MR100 (cgi_gdpr)

_This one was hard._

It's some [old 4G router](https://www.tp-link.com/my/home-networking/mifi/tl-mr100/) which just does its job. 

Someone in TpLink decided to make things complicated and encrypt communication between web interface and API.
To communicate with a router you need to know password, request rsa keys, authorize and get jsession id, request token.
When you get those artifacts it's time to use them properly and reverse their API to do something.
Also, do not forget to log out and avoid doing something while having active session in a browser. 

Kudos to [0xf15h](https://github.com/0xf15h) for implementing [crypto for this device](https://github.com/0xf15h/tp_link_gdpr/blob/main/tp_link_crypto.py) in python which is reused here.

Kudos to [hertzg](https://github.com/hertzg) for his [implementation of API](https://github.com/hertzg/node-tplink-api) using Node.js.

My implementation (``tplinksms.py``) does not cover proper payload formation and consists of intercepted messages from web-client.
Maybe in future I'll fix it, but most probably I won't =).

```
Tested on TpLink TL-MR100 v1 00000001 with software version 1.4.0 0.9.1 v0001.0 Build 210601 Rel.32393n

It may eventually fail while requesting jsession id or (much rare case, actually) rsa keys.
But works again on a retry.

Another issue: SMS may be fetched after 1-2 minutes after receiving. 

Also, if someone curious how web-ui communicates with API:
 - look to /js/proxy.js from router's web-client
 - function called tpAjax
 - outcoming message encrypted by Iencryptor.AESEncrypt
 - incoming response in decrypted by Iencryptor.AESDecrypt
```

## How to use

1. Install dependencies
2. Hardcode your IP addresses and/or password (or add parameters)
3. Modify SMS content if needed.
