# oidc-pcsc plugin

## Object

This plugin provides a sample implementation for Smartcard/NFC-token authentication based on [pcsc-lite](https://pcsclite.apdu.fr/).

## Dependencies

Relies on use-space pcscd resource manager to read/write NFC scard/token.

* Libraries (with xxx-devel when building from sources)
  * pcsc-lite
  * pcsc-*ccid
  * afb-libafb
* Blacklist default NFC kernel module
  * sudo cp $SOURCES/libs/pcscd-client/test/nfc-blacklist.conf /etc/modprobe.d
  * rmmod nfc and dependencies (or reboot)
  * systemctl enable pcscd.service
* Run pcscd manager
  * foreground: sudo /usr/sbin/pcscd -f
  * background: systemctl start pcscd.service

## Supported readers/cards

The code was tested with Mifare classic tokens but pcsc-lite supports most of CCID compliant tokens. Nevertheless note that each scard/token has it own flavor or API and data organization which may require config/code customization.

* <https://ccid.apdu.fr/ccid/supported.html>

## References

* NXP Mifare <https://www.nxp.com/docs/en/data-sheet/MF1S70YYX_V1.pdf>
* online acl <http://calc.gmss.ru/Mifare1k/>
* ACR 122 reader <http://downloads.acs.com.hk/drivers/en/API-ACR122U-2.02.pdf>
* Card IDs  <http://pcscworkgroup.com/Download/Specifications/pcsc3_v2.01.09_sup.pdf>

## Testing

The simplest way to test your reader/token is to use pcsc-client with a custom config.json. Note that pcsc-client should be available for major Linux distributions.

```dotnetcli
 ~/$SOURCES/sec-gate-oidc/build> ./package/bin/pcsc-client --config=../src/idps-plugins/oidc-pcsc/test/simple-pcsc.json --group=0 --async --verbose
 -- Waiting: 1s events for reader=ACS ACR122U PICC Interface 00 00 (ctrl-C to quit)
 -- async: reader=ACS ACR122U PICC Interface 00 00 status=0x5e0012
 -- event: reader=ACS ACR122U PICC Interface 00 00 removed (waiting for new card)
 ^C
 Ctrl-C received
 On Signal Exit
```

## Config.json

Json configuration is organized in sections:

* **reader**: a subset of reader full name
* **keys**: defined keys used when a command requires authentication
* **cmds**: your commands list
* **verbose**: level of verbosity when not passed from API with --verbose

### Reader

It is a subset of reader name. When multiple readers respond to the subset first reader found is used. When no reader name is provided, oidc-pcsc uses first available reader. As a result if your have only one reader you do not have to know its name.

```json
    // "ACR122U" for "ACS ACR122U PICC Interface 00 00"
    "reader": "ACR122U",
```

### Keys

Keys are only needed when your commands require authentication. This is typically the case when using scard/token data for authentication.

```json
    "keys": [
        {"uid":"dfltA", "idx": 0, "value":["0xFF","0xFF","0xFF","0xFF","0xFF","0xFF"]},
        {"uid":"key-a", "idx": 0, "value":["0x01","0x02","0x03","0x04","0x05","0x06"]},
        {"uid":"key-b", "idx": 1, "value":["0x0A","0x0B","0x0C","0x0D","0x0E","0x0F"]}
    ],
```

* **key-A** -> idx:0
* **key-B** -> idx:1
* **value**: ASCII or Hexa key value.

Mifare-Classic support two keys A/B where both should have 6 bytes. Default keys on new cards is 0xFFFFFF for both keys. When a command does not specify a key default keysA is used for both read and write operation. Default should work with any new card.

### Commands

Each scard model has a private physical organization (page, sector, blocs, ...) as well as it own authentication and API capabilities. As said before oidc-pcsc was tested with Mifare-Classic, if you need to support a different card model you may have to tweak configuration and code. Note that commands are stored in order and pcsc-client execute then from config order.

```json
    "cmds": [
        {"uid":"cmd-1" , "group": 0, "action":"read", "blk": 1, "len": 16},
        {"uid":"cmd-2" , "group": 0, "action":"read", "blk": 3, "len": 16},
        ....
        {"uid":"cmd-n" , "group":x, "action":xxxx, "blk":xx, "len":xx},
    ]
```

Each command should have:

* **uid**: [mandatory] information used to identify command within your config
* **group**: [optional] used to class command in config. pscsc-test command use --group=xx to only execute command from a given group. (default:0)
* **action**: [mandatory]
  * **read**: read one/multiple blocs
  * **write** read one/multiple blocs
  * **trailer**: write access control bit and authentication keys for a given sector.
* **sec**: [optional] With Mifare/classic sector is map to 4 blocks also (sec:1,block:1) is equivalent to (block:5). Some token as NFC/type-2 requires a sector index. (default:0)
* **blk**: [mandatory] block index for read and write commands.
* **len**: [mandatory/read, optional/write] specify amount of data to read. With write action, 'len' is the maximum of data written, any remaining input is silently ignored. *Warning: it is the application responsibility to provide a buffer big enough to hold read data.*
* **value**: [mandatory for write/trailer] provides information to write on the scard. The information may by provided in hexa or ascii form. Warning: depending on token/scard model writable size diverge. Mifare only supports 0x10,0x20,x30 value length. Last bloc written with trailer command is reserved for access control bits/keys.

## Trailer

Trailer is a specialized version of write command used to simplify access control bit/keys writing.

```json
{"uid":"set-acls", "group": 2, "action":"trailer", "blk": 27, "key":"dfltA", "trailer": {"keyA": "key-a","keyB":"key-b","acls":["0xF0","0xF7","0x80","0x00"]}},
```

***WARNING: trailer command can brick you scard/token.*** Writing a wrong ACL/keys will kill concerned block. Double, triple check your command on a single block/card before provisioning a set of cards.

* **group**: [recommended] while not mandatory 'trailer' commands are usually isolated in a private group, as they change access control and usually cannot be executed twice.
* **blk**: [mandatory] with Myfare/classic block index should match the last bloc of a given sector/page with blocIdx modulo 4 == 3.
* **key**: [optional] authentication key. When not provided trailer command uses default (0xFFFFFF) which should work with any new Mifare/classic card. After changing ACLs authentication key depends on your config.
* **key-a/b**: [mandatory] The new access control key. Key-a/b should match a predefined key-uid from your 'keys' config section. Key-a/b are written with your acls bloc and will be required for further action on concerned blocs.
* **acls**: [mandatory] The acls control bits of you trailer block. **WARNING** invalid acls data will brick all blocks from targeted page/sector. Check further note to create a valid acls blocs.
  * references: <https://www.nxp.com/docs/en/data-sheet/MF1S70YYX_V1.pdf>
  * online acl: <http://calc.gmss.ru/Mifare1k/>
  * example: "acls":["0x08","0x77","0x8F","0x00"]} key-A readable, key-B writable

## ACLs control bits

Trailer access control is composed of 4 bytes.

* The 3 first bytes store the access control as such. Acls are stored in both normal and inverted bit values.
* Last byte is free and available as user-data.
* *Any error in acls data will brick the 4 blocs of concerned page**

**Acls are too complex/risky for normal human**: use  <http://calc.gmss.ru/Mifare1k>

Here after default configuration for a new scard.

```bash
    // ---
    // blk-0:   (C10 C20 C30)= 000 (|C10|C20|C30)= 111 (transport config)
    // blk-1:   (C11 C21 C31)= 000 (|C11|C21|C31)= 111
    // blk-2:   (C12 C22 C32)= 000 (|C12|C22|C32)= 111
    // trailer: (C13 C23 C33)= 001 (|C13|C23|C33)= 110 (transport config)
    // ---
    // Byte-6 |C23|C22|C21|C20 0xFF 1111-1111  |C13|C12|C11|C10
    // Byte-7  C13,C12,C11,C10 0x07 0000-0111  |C33|C32|C31|C30
    // Byte-8  C33,C32,C31,C30 0x80 1000-0000   C23,C22,C21,C20
    // ----
```

For further information: check NXP Mifare chaper 8.7.2 [MF1S70YYX](https://www.nxp.com/docs/en/data-sheet/MF1S70YYX_V1.pdf)

## Sample full config

Note: the 'set-acls' command (group=2) should work for a new card. But after 1st usage do not forget that 'key-b' will be required to write concerned trailer bloc.

```json
{
    "info" : "Basic PCSC test for Mifare Classic",
    "reader": "ACR122U",
    "keys": [
        {"uid":"dfltA", "idx": 0, "value":["0xFF","0xFF","0xFF","0xFF","0xFF","0xFF"]},
        {"uid":"key-a", "idx": 0, "value":["0x01","0x02","0x03","0x04","0x05","0x06"]},
        {"uid":"key-b", "idx": 1, "value":["0x0A","0x0B","0x0C","0x0D","0x0E","0x0F"]}
    ],
    "cmds": [
        // group :0 public access (default keys)
        {"uid":"public-read" , "group": 0, "action":"read", "blk": 1, "len": 16},
        {"uid":"public-write", "group": 0, "action":"write","blk": 2, "data": "abcdefghijklmnop"},
        {"uid":"public-read" , "group": 0, "action":"read", "blk": 2, "len": 16},

        // group:2 write acls on a new key
        {"uid":"set-acls"   , "group": 2, "action":"trailer", "blk": 27, "key":"dfltA", "trailer": {"keyA": "key-a","keyB":"key-b","acls":["0xF0","0xF7","0x80","0x00"]}},

        // group:1 read/write key after acls was written
        {"uid":"keyB-write"  , "group": 1, "action":"write","blk": 26, "key":"key-b", "data": "abcdefghijklmnop"},
        {"uid":"keyA-read"   , "group": 1, "action":"read","blk": 26, "key":"key-a", "len": 16},
    ]
}
```

## OIDC-pcsc C/APIs

## Config APIs

High level API, hopefully match most application requirements.

```c
 #include <pcsc-config.h>
 pcscConfigT *pcscParseConfig (json_object *configJ, const int verbosity);
 pcscCmdT *pcscCmdByUid (pcscConfigT *config, const char *cmdUid);
 int pcscExecOneCmd(pcscHandleT *handle, const pcscCmdT *cmd, u_int8_t *data);
```

* **pcscParseConfig**: parse a config.json as defined in previous chapters.
* **pcscCmdByUid**: find a command from its 'uid' and return command handle
* **pcscExecOneCmd**: execute a command from its handle

## Pcsc APIs

### Connecting to pcsc reader

```c
 #include <pcsc-glue.h>
 pcscHandleT *pcscConnect (const char uid, const char *readerName);
 int pcscDisconnect (pcscHandleT *handle);
 int pcscSetOpt (pcscHandleT *handle, pcscOptsE opt, ulong value);
 const char* pcscErrorMsg (pcscHandleT *handle);
```

* **pcscConnect**: connect to a given reader: "readername" should be a subset of full reader name. When NULL first reader available is used. "uid" is a free *human-readable* string used to track debug messages.
* **pcscDisconnect**: close and free reader connection.
* **pcscSetOpt**: pcsc handle is opaque and options require a setter (
  * PCSC_OPT_TIMEOUT
  * PCSC_OPT_VERBOSE,
* **pcscErrorMsg**: last command error message

### Connecting to scard/token in synchronous or asynchronous mode

```c
 #include <pcsc-glue.h>
 int pcscReaderCheck (pcscHandleT *handle, int ticks);
 ulong pcscMonitorReader (pcscHandleT *handle, pcscStatusCbT callback, void *ctx);
 int pcscMonitorWait (pcscHandleT *handle, pcscMonitorActionE action);
 void* pcscGetCtx (pcscHandleT *handle);

 typedef int (*pcscStatusCbT) (pcscHandleT *handle, ulong state);
 u_int64_t pcscGetCardUuid (pcscHandleT *handle);
```

* **pcscReaderCheck**: in synchronous mode wait xx ticks for reader to be ready. Default ticks is 60s, and can be changed with timeout option.
* **pcscMonitorReader**: start monitoring thread and register callback and context. Unfortunately pcsc-lite does not support asynchronous operation and application should register a dedicated thread to run pcsc operations in background.
* **pcscMonitorWait**: wait for monitor thread to finish. `Action=PCSC_MONITOR_WAIT|PCSC_MONITOR_CANCEL`
* **pcscGetCtx**: return handle context provided by pcscMonitorReader.
* **pcscGetCardUuid**: check scard ATR and return UUID. If card is not supported this returns an error.
* **pcscStatusCbT** monitoring callback signature register by pcscMonitorReader. This callback is called each time reader status changes. Typically when a scard is inserted/removed. As callback gets pcsc handle it can run any commands. Check main-pcsc.c for sample.

### Reading/Writing to scard/token

Low level commands, most users may prefer to rather pcscExecOneCmd.

```c
 #include <pcsc-glue.h>
 const pcscKeyT *pcscNewKey (const char *uid, u_int8_t *value, size_t len);
 int pcsWriteBlock (pcscHandleT *handle, const char *uid, u_int8_t secIdx, u_int8_t blkIdx, u_int8_t *dataBuf, ulong dataLen, const pcscKeyT *key);
 int pcscReadBlock (pcscHandleT *handle, const char *uid, u_int8_t secIdx, u_int8_t blkIdx, u_int8_t *data, ulong *dlen, const pcscKeyT *key);
 int pcsWriteTrailer (pcscHandleT *handle, const char *uid, u_int8_t secIdx, u_int8_t blkIdx, const pcscKeyT *key, const pcscTrailerT *trailer);
```

* **pcscNewKey**: create a new key.
  * value: uint8 array, buffer should remain valid after api call.
  * len: buffer len, if len=0 then strlen(value) is used.
* **pcsWriteBlock**: write bloc on scard/token.
  * uuid: is used only for debug purpose.
  * secIdx: sector index. Use with NFC-type2 but not with MiFare
  * blkIdx: block index. Note that with Mifare/classic sector/page is equivalent to blocIdx/4.
  * dataBut: the buffer to write
  * dataLen: the length to write. Depending on your scard/token length as contrains. With Mifare/classic you should write full block len=0x10,0x20,x30 and should not break page/sector boundary. Do not forget that you may write by block, but then authentication is by sector/page.
  * key: key handle to be used for operation authentication.

* **pcscReadBlock**: read bloc on scard/token.
  * uuid: is used only for debug purposes.
  * secIdx: sector index. Use with NFC-type2 but not with MiFare
  * blkIdx: block index.
  * dataBut: buffer address where to place result
  * dataLen: input dataBuf size, return amount of effective data read.
  * key: key handle to be used for operation authentication.

* **pcsWriteTrailer**: write a bloc on scard/token.
  * uuid: is used only for debug purposes.
  * secIdx: sector index. Use with NFC-type2 but not with MiFare
  * blkIdx: block index. Block index should match last bloc of a given page/sector.
  * key: key handle to be used for operation authentication.
  * trailer: trailer handle as created from pcscNewKey api.
