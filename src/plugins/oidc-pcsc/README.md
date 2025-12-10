# PCSC NFC Quick start IDP configuration

oidc-pcsc somehow fakes openid-connect handshake. It relies on pcscd-client library and pcscd daemon to access nfc tokens/smartcards. When an application is redirected onto oidc-pcscd for authentication, sgate starts a thread that monitors the reader and waits for a card to be inserted. As soon as a valid card is inserted oidc-pscd tries to read scard content. When successful it then applies federation authentication as it would do with any other openid-connect authority. The authentication thread remains active until the card is removed from the reader, at this point sgate resets the session and notifies client application that the session is locked.

Note: pcsc is implemented as an external plugin and released under MIT licence. Reference implementation relies on:

* Mifare-classic NFC scard and you probably should hack the code to interface any other token/scard.
* CCID ACR122U NFC reader. Changing to another CCID reader should hopefully only require configuration change. Changing for a non supported reader more or less imposes one to fully rewrite oidc-pcsc. 

## 1- provision your card

Except if you only use token/scard UUID within a slave profile you should provision your token/scard with adequate datas. If you need a provision tool check pscd-client (here)[/xxxxx]

Note: when card is declared as 'slave' it can only federate with a pre-existing account. If primary federate identity does not exist when using a slave idp profile, oidc will switch from primary identity creation to grand authentication, but will not link primary with slave identity. As a result in order to use a scard/token as second factor authentication, not only should you declare your profile as 'slave' but you should also link both accounts. This link may happen either by static provisioning or dynamically from scard card 'secret' content or other mechanisms that fit your security requirements. 

## 2- configure your plugin

oidc-pscd is loaded at run time and you should provide plugin path+name in order for sgate to find it. Note that if */etc/ld.so.conf.d/* or *LD_LIBRARY_PATH* are correctly configured you should not have to provide plugin fullpath within your config.

```json
    "uid": "nfc-scard",
    "type": "pcsc",
    "info": "NFC Mifare/Classic smartcard authentication (check ",
    "plugin": {
        "ldpath": "libidp-sgate-pcscd-auth.so",
        "config": {
        ....    
```

Complete your configuration:
* check pcsc-client configuration for NFC/scard command and key definition.
* other part of the config static,wellknown,profile... are common to any other idps.

## 3- mapping scard attributes as sgate security attributes

In order to map openid and security attributes to data store in token/scard with map pscsd command 'uid' onto scope or attributes security labels.

In the following example 'fedid','pseudo',... should map on valid pcsc commands as described in later full config sample.

```json
"profiles": [
    {"uid":"linked","loa":1, "scope":"fedid", "slave":true},
    {"uid":"admin", "loa":2, "scope":"fedid,pseudo,name,email,company", "attrs":"roles,apps"}
    ]
```

Note: 
* token/scard have multiple constraints and limitations. Mifare-classic useful data within a sector is 48bytes which constrains attributes maximum length. 
* slave profile cannot register a new user. In previous 'linked' profile config sample, either token/scard UUID should be pre-provision or user should double authenticate and prove its identity with second authority, as it is typically the case with second factor authentication. 

## 4 Minimalist pcsc full config.

A minimalist configuration may look like the following one. Check for config chapter for full config options.

```json
{
    "uid": "nfc-scard",
    "type": "pcsc",
    "info": "NFC Mifare/Classic smartcard authentication (check ",
    "plugin": {
        "ldpath": "libidp-sgate-pcscd-auth.so",
        "config":     {
            "info" : "Mifare/Classic command samples",
            "reader": "acr122",
            "keys": [
                {"uid":"key-a", "idx": 0, "value":["0x01","0x02","0x03","0x04","0x05","0x06"]},
                {"uid":"key-b", "idx": 1, "value":["0x0A","0x0B","0x0C","0x0D","0x0E","0x0F"]}      
            ],
            "cmds": [ 
                // card should be pre-provision with right keys/acls (pcsc-client --help)          
                {"uid":"fedid"   , "action":"uuid"},
                {"uid":"pseudo"  , "action":"read","sec": 1, "key":"key-a", "len":48},
                {"uid":"email"   , "action":"read","sec": 2, "key":"key-a", "len":48},
                {"uid":"name"    , "action":"read","sec": 3, "key":"key-a", "len":48},
                {"uid":"company" , "action":"read","sec": 4, "key":"key-a", "len":48},
                {"uid":"roles"   , "action":"read","sec": 5, "key":"key-a", "len":48},
                {"uid":"apps"    , "action":"read","sec": 6, "key":"key-a", "len":48}
            ]
        }
    },
    "statics": {
        "login": "/sgate/nfc-auth/login",
        "logo": "/sgate/nfc-auth/logo-64px.png",
        "timeout": 900
    },
    "wellknown": {
        "tokenid": "/sgate/nfc-auth/login.html"
    },
    "profiles": [
        {"uid":"linked","loa":1, "scope":"fedid", "slave":true},
        {"uid":"admin", "loa":2, "scope":"fedid,pseudo,name,email,company", "attrs":"roles,apps"}
    ]
}
```
