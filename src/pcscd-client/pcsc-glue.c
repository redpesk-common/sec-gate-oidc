/*
 * Copyright (C) 2015-2026 IoT.bzh Company
 * Author: "Fulup Ar Foll" <fulup@iot.bzh>
 * Author: <jose.bollo@iot.bzh>
 * Author: <dev-team@iot.bzh>
 *
 * $RP_BEGIN_LICENSE$
 * Commercial License Usage
 *  Licensees holding valid commercial IoT.bzh licenses may use this file in
 *  accordance with the commercial license agreement provided with the
 *  Software or, alternatively, in accordance with the terms contained in
 *  a written agreement between you and The IoT.bzh Company. For licensing terms
 *  and conditions see https://www.iot.bzh/terms-conditions. For further
 *  information use the contact form at https://www.iot.bzh/contact.
 *
 * GNU General Public License Usage
 *  Alternatively, this file may be used under the terms of the GNU General
 *  Public license version 3. This license is as published by the Free Software
 *  Foundation and appearing in the file LICENSE.GPLv3 included in the packaging
 *  of this file. Please review the following information to ensure the GNU
 *  General Public License requirements will be met
 *  https://www.gnu.org/licenses/gpl-3.0.html.
 * $RP_END_LICENSE$
 *
 * general utilities to read/write smart card with pcsc-lite
 *  ATR http://pcscworkgroup.com/Download/Specifications/pcsc3_v2.01.09_sup.pdf
 *  CMD
 * https://docs.springcard.com/books/SpringCore/PCSC_Operation/APDU_Interpreter/Standard_instructions/UPDATE_BINARY
 *  MiFare https://www.nxp.com/docs/en/data-sheet/MF1S70YYX_V1.pdf (for trailer
 * #8.6.3 & #8.7.2) Default keyA='FFFF-FFFF-FFFF' Access-bits='FF0780'
 */
#define _GNU_SOURCE

#include "pcsc-glue.h"

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <pcsclite.h>
#include <winscard.h>

#include <rp-utils/rp-verbose.h>

typedef struct
{
    pthread_t tid;
    pcscHandleT *pcsc;
    void *userData;
    pcscStatusCbT callback;
} pcscThreadT;

// map 16 bits blockindex on two bytes
typedef union {
    u_int16_t u16;
    u_int8_t u8[2];
} mifareSecBlkT;

static BYTE defaultKey[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static BYTE pcPsRid[] = {0xA0, 0x00, 0x00, 0x03, 0x06};

typedef union {
    u_int16_t id;
    BYTE data[2];
} atrIsoCardid;

typedef struct
{
    atrCardidEnumT uid;
    atrIsoCardid cardid;
} isoAtrCardIdMapT;

static isoAtrCardIdMapT isoArtCardIds[] = {
    {.uid = ATR_MIFARE_1K, .cardid = {.data = {0x00, 0x01}}},
    {.uid = ATR_MIFARE_4K, .cardid = {.data = {0x00, 0x02}}},
    {.uid = ATR_MIFARE_UL, .cardid = {.data = {0x00, 0x03}}},
    {.uid = ATR_MIFARE_MINI, .cardid = {.data = {0x00, 0x26}}},
    {.uid = ATR_FELICA_212K, .cardid = {.data = {0xF0, 0x11}}},
    {.uid = ATR_FELICA_424K, .cardid = {.data = {0xF0, 0x12}}},

    {.uid = ATR_UNKNOWN}  // trailer
};

typedef union {
    BYTE data[20];
    struct
    {
        BYTE Header;
        BYTE T0;
        BYTE TD1;
        BYTE TD2;
        BYTE T1;
        BYTE Tk;
        BYTE length;
        BYTE rid[5];
        BYTE Standard;
        BYTE cardid[2];
        BYTE rfu[4];
        BYTE checkSum;
    } value;
} isoAtrDataP3T;

typedef struct pcscHandleS
{
    const char *uid;
    ulong magic;
    const char *readerName;
    int readerId;
    atrCardidEnumT cardId;
    u_int64_t uuid;
    BYTE keyA[6];
    BYTE keyB[6];
    SCARDCONTEXT hContext;
    SCARDHANDLE hCard;
    const SCARD_IO_REQUEST *pioSendPci;
    DWORD activeProtocol;
    ulong timeout;
    ulong verbose;
    const char *error;
    ulong tid;
    void *ctx;
} pcscHandleT;

static long pcscSendCmd(pcscHandleT *handle,
                        const char *cmdUid,
                        const char *action,
                        const u_int8_t *cmdBuf,
                        long cmdLen,
                        u_int8_t *dataBuf,
                        long unsigned *dataLen)
{
    assert(handle->magic == PCSC_HANDLE_MAGIC);
    long unsigned bufferLen = *dataLen;
    long rv;

    if (handle->verbose) {
        printf("\n -- action=%s\n -- len=%lu sending:[", action, cmdLen);
        for (int i = 0; i < cmdLen; i++)
            printf("0x%02X,", cmdBuf[i]);
        printf("]\n");
    }

    rv = SCardTransmit(handle->hCard, handle->pioSendPci, cmdBuf, cmdLen, NULL,
                       dataBuf, dataLen);
    if (rv != SCARD_S_SUCCESS) {
        handle->error = pcsc_stringify_error(rv);
        goto OnErrorExit;
    }

    if (handle->verbose) {
        int ascii = 0;
        printf(" -- len=%lu/%lu received: [", *dataLen, bufferLen);
        for (int idx = 0; idx < *dataLen; idx++) {
            if (!dataBuf[idx])
                break;
            if (dataBuf[idx] >= ' ' && dataBuf[idx] <= '~') {
                fwrite(&dataBuf[idx], sizeof(char), 1, stdout);
                ascii = 1;
            }
        }
        if (ascii)
            printf("] [");
        for (int idx = 0; idx < *dataLen; idx++)
            printf("0x%02X,", dataBuf[idx]);
        printf("]\n");
    }
    // checked smartcard is happy response and by 0x90,x00
    if (dataBuf[*dataLen - 2] != 0x90 || dataBuf[*dataLen - 1] != 0x00) {
        handle->error = "Smartcard CMD refused (auth?)";
        rv = SCARD_STATE_INUSE;
        goto OnErrorExit;
    }
    // close buffer in case it would be used as ascii and remove Mifare status
    // from readlen
    dataBuf[*dataLen - PCSC_MIFARE_STATUS_LEN] = '\0';

    return rv;

OnErrorExit:
    RP_DEBUG("[pcsc-transmit-error] uid=%s action=%s error=%s (pcscSendCmd)\n",
             cmdUid, action, handle->error);
    return rv;
}

// search cardId within supported ATR
static atrCardidEnumT isoAtrParseCard(pcscHandleT *handle,
                                      BYTE *buffer,
                                      DWORD len)
{
    isoAtrDataP3T *atr;
    atrCardidEnumT atrUid = ATR_UNKNOWN;
    atrIsoCardid cardid;
    // reference
    // http://ludovic.rousseau.free.fr/softwares/pcsc-tools/smartcard_list.txt
    switch (len) {
    case sizeof(isoAtrDataP3T):
        // mirefare1K=
        // .data={0x3B,0x8F,0x80,0x01,0x80,0x4F,0x0C,0xA0,0x00,0x00,0x03,0x06,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x6A}
        atr = (isoAtrDataP3T *)buffer;

        // check we are facing a MyFare RID
        if (memcmp(atr->value.rid, pcPsRid, sizeof(pcPsRid)))
            goto OnErrorExit;

        // move cardid as int16 in case value is not aligned
        memcpy(cardid.data, atr->value.cardid, sizeof(cardid));

        // search for cardid within supported list
        for (int idx = 0; isoArtCardIds[idx].uid != ATR_UNKNOWN; idx++) {
            if (isoArtCardIds[idx].cardid.id == cardid.id) {
                atrUid = isoArtCardIds[idx].uid;
                break;
            }
        }
        break;

    case 9:
        // loosely handle bank card
        atr = (isoAtrDataP3T *)buffer;
        atrUid = ATR_BANK_FR;
        break;

    default:
        goto OnErrorExit;
    }

    return atrUid;

OnErrorExit:
    handle->error = "pcsc unsupported ATR smartcard model";
    return ATR_UNKNOWN;
}

// get card UUID (block 0 read only execpt on Chineese smartcard)
int pcscReadUuid(pcscHandleT *handle,
                 const char *uid,
                 u_int8_t *data,
                 ulong *dlen)
{
    assert(handle->magic == PCSC_HANDLE_MAGIC);
    BYTE cmdData[] = {0xFF, 0xCA, 0x00, 0x00, 0x00};
    long rv;

    rv = pcscSendCmd(handle, uid, "read-uuid", cmdData, sizeof(cmdData), data,
                     dlen);
    if (rv != SCARD_S_SUCCESS)
        goto OnErrorExit;
    return 0;

OnErrorExit:
    return -1;
}

// get card UUID (block 0 read only execpt on Chineese smartcard)
static u_int64_t pcscGetCardUuidNum(pcscHandleT *handle)
{
    assert(handle->magic == PCSC_HANDLE_MAGIC);
    UCHAR receiveBuffer[16];
    DWORD receiveLength = sizeof(receiveBuffer);
    u_int64_t uuid = 0;
    long rv;

    rv = pcscReadUuid(handle, "uuid", receiveBuffer, &receiveLength);
    if (rv != SCARD_S_SUCCESS)
        goto OnErrorExit;
    for (int idx = 0; idx != receiveLength - 2; idx++) {
        uuid <<= 8;
        uuid |= (u_int64_t)receiveBuffer[idx];
    }
    return uuid;

OnErrorExit:
    return 0;
}

static long pcscAuthSCard(pcscHandleT *handle,
                          const char *uid,
                          u_int8_t secIdx,
                          u_int8_t blkIdx,
                          ulong dataLen,
                          const pcscKeyT *key,
                          ulong *blkSector,
                          ulong *blkLength)
{
    long rv;
    u_int8_t *keyVal;
    u_int8_t keyIdx;
    BYTE status[32];

    switch (handle->cardId) {
    case ATR_MIFARE_1K:
    case ATR_MIFARE_4K:

        *blkSector = 4L;   // mifare classic block/sector organisation
        *blkLength = 16L;  // fixe block size

        // mifare only use block index
        if (secIdx) {
            // blkIdx= (u_int8_t)((secIdx*4) + blkIdx);
            blkIdx = (u_int8_t)(secIdx * 4);  // authent is per page
            secIdx = 0;
        }
        // assert request is possible
        if (dataLen > 48 || dataLen % 16) {
            handle->error =
                "Invalid MIFARE_CLASSIC dlen should 16*x where x=1-3.";
            goto OnErrorExit;
        }

        if (!key) {
            keyVal = defaultKey;
            keyIdx = 0;  // keyA
        }
        else {
            if (key->klen != 6) {
                handle->error = "Invalid MIFARE_CLASSIC keyken should 6";
                goto OnErrorExit;
            }
            keyVal = key->kval;
            keyIdx = key->kidx;
        }
        BYTE keyCmd[] = {0xFF,      0x82,      0x00,      0x00,
                         0x06,      keyVal[0], keyVal[1], keyVal[2],
                         keyVal[3], keyVal[4], keyVal[5]};
        ulong keyStatusLen = sizeof(status);
        rv = pcscSendCmd(handle, uid, "key", keyCmd, sizeof(keyCmd), status,
                         &keyStatusLen);
        if (rv != SCARD_S_SUCCESS)
            goto OnErrorExit;

        // send authentication block
        BYTE authCmd[] = {0xFF, 0x86,   0x00,   0x00,          0x05,
                          0x01, secIdx, blkIdx, 0x60 | keyIdx, 0x00};
        ulong authStatusLen = sizeof(status);
        rv = pcscSendCmd(handle, uid, "authent", authCmd, sizeof(authCmd),
                         status, &authStatusLen);
        if (rv != SCARD_S_SUCCESS)
            goto OnErrorExit;

        break;

    case ATR_MIFARE_UL:
        *blkSector = 4L;  // mifare UL block/sector organisation
        *blkLength = 4L;  // fixe block size

        // no authentication
        if ((blkIdx * 4 + dataLen) > 38 * 4L || (dataLen != 4L)) {
            handle->error = "Invalid MIFARE_UL (dlen should be mod/4)";
            goto OnErrorExit;
        }
        break;

    default:
        handle->error = "Unsupported smartcard model";
        goto OnErrorExit;
    }
    return SCARD_S_SUCCESS;

OnErrorExit:
    return -1;
}

// try to read data bloc
int pcscReadBlock(pcscHandleT *handle,
                  const char *uid,
                  u_int8_t secIdx,
                  u_int8_t blkIdx,
                  u_int8_t *data,
                  ulong dataLen,
                  const pcscKeyT *key)
{
    assert(handle->magic == PCSC_HANDLE_MAGIC);
    long rv = 0;
    ulong blkSector, blkLength;
    ulong dlen;

    if (handle->verbose)
        fprintf(stderr,
                "\n# pcscReadBlock reader=%s cmd=%s scard=%ld sec=%d blk=%d "
                "dlen=%ld",
                handle->readerName, uid, handle->uuid, secIdx, blkIdx, dataLen);

    rv = pcscAuthSCard(handle, uid, secIdx, blkIdx,
                       dataLen - PCSC_MIFARE_STATUS_LEN, key, &blkSector,
                       &blkLength);
    if (rv != SCARD_S_SUCCESS)
        goto OnErrorExit;

    // try to read bloc
    ulong dataIdx = 0;
    for (ulong idx = blkIdx % blkSector;
         (idx < blkSector && dataIdx < dataLen - PCSC_MIFARE_STATUS_LEN);
         idx++) {
        mifareSecBlkT sIdx;
        sIdx.u16 = (u_int16_t)(secIdx * 4 + blkIdx + idx);

        dlen = blkLength +
               PCSC_MIFARE_STATUS_LEN;  // add cmd status to buffer size
        u_int8_t readBlk[] = {0xFF, 0xB0, sIdx.u8[1], sIdx.u8[0],
                              (u_int8_t)blkLength};
        rv = pcscSendCmd(handle, uid, "read", readBlk, sizeof(readBlk),
                         &data[dataIdx], &dlen);
        if (rv != SCARD_S_SUCCESS)
            goto OnErrorExit;

        // move to new block if any
        dataIdx += blkLength;
    }
    if (handle->verbose) {
        fprintf(stderr, "recieved=%ld data:[", dataIdx);
        for (int idx = 0; idx < dataIdx; idx++) {
            if (!data[idx])
                break;
            if (data[idx] >= ' ' && data[idx] <= '~') {
                fwrite(&data[idx], sizeof(char), 1, stderr);
            }
        }
        fprintf(stderr, "]\n");
    }

    return 0;

OnErrorExit:
    if (handle->verbose)
        fprintf(stderr, " error=%s\n", handle->error);
    RP_DEBUG("[pcsc-readblk-fail] cmd=%s action:read err=%s", uid,
             handle->error);
    return -1;
}

// try to read data bloc
int pcsWriteBlock(pcscHandleT *handle,
                  const char *uid,
                  u_int8_t secIdx,
                  u_int8_t blkIdx,
                  u_int8_t *dataBuf,
                  ulong dataLen,
                  const pcscKeyT *key)
{
    assert(handle->magic == PCSC_HANDLE_MAGIC);
    long rv = 0;
    ulong blkSector, blkLength;

    if (handle->verbose)
        fprintf(stderr,
                "\n# pcsWriteBlock reader=%s cmd=%s scard=%ld sec=%d blk=%d "
                "dlen=%ld\n",
                handle->readerName, uid, handle->uuid, secIdx, blkIdx, dataLen);
    rv = pcscAuthSCard(handle, uid, secIdx, blkIdx, dataLen, key, &blkSector,
                       &blkLength);
    if (rv != SCARD_S_SUCCESS)
        goto OnErrorExit;

    // Write is done by block within one sector
    ulong dataIdx = 0;
    for (ulong idx = blkIdx % blkSector; (idx < blkSector && dataIdx < dataLen);
         idx++) {
        mifareSecBlkT sIdx;
        sIdx.u16 = (u_int16_t)(secIdx * 4 + idx);

        BYTE writeCmd[] = {0xFF, 0xD6, sIdx.u8[1], sIdx.u8[0],
                           (u_int8_t)blkLength};
        BYTE bufferRqt[blkLength + sizeof(writeCmd)];
        memcpy(&bufferRqt[0], writeCmd, sizeof(writeCmd));
        memcpy(&bufferRqt[sizeof(writeCmd)], &dataBuf[dataIdx], blkLength);
        ulong length = blkLength + sizeof(writeCmd);

        rv = pcscSendCmd(handle, uid, "write", bufferRqt, sizeof(bufferRqt),
                         dataBuf, &length);
        if (rv != SCARD_S_SUCCESS)
            goto OnErrorExit;

        // move to new block if any
        dataIdx += blkLength;
    }

    return 0;

OnErrorExit:
    RP_DEBUG("[pcsc-writeblk-fail] cmd=%s action=write err=%s", uid,
             handle->error);
    return -1;
}

int pcscCardCheckAtr(pcscHandleT *handle)
{
    assert(handle->magic == PCSC_HANDLE_MAGIC);
    char readerName[MAX_READERNAME] = "";
    BYTE atrData[MAX_ATR_SIZE] = "";
    DWORD readerLen = sizeof(readerName);
    DWORD atrLen = sizeof(atrData);
    DWORD readerState;
    long rv = -1;

    // make sure reader as a card
    if (!handle->hCard) {
        RP_ERROR(
            "[pcsc-reader-status] should 1st use pcscReaderCheck to reader=%s "
            "presence",
            handle->readerName);
        goto OnErrorExit;
    }
    // use status to retreive smart cart ATR
    rv = SCardStatus(handle->hCard, readerName, &readerLen, &readerState,
                     &handle->activeProtocol, atrData, &atrLen);
    if (rv != SCARD_S_SUCCESS) {
        handle->error = pcsc_stringify_error(rv);
        goto OnErrorExit;
    }

    handle->cardId = isoAtrParseCard(handle, atrData, atrLen);
    if (handle->cardId == ATR_UNKNOWN)
        goto OnErrorExit;

    return 0;

OnErrorExit:
    RP_ERROR(
        "[pcsc-sccard-atr] Fail get smart card atr reader=%s. "
        "(pcscCardCheckAtr=%s)",
        handle->readerName, pcsc_stringify_error(rv));
    return -1;
}

// wait for reader status and wait for smart card
int pcscReaderCheck(pcscHandleT *handle, int ticks)
{
    assert(handle->magic == PCSC_HANDLE_MAGIC);
    long rv;

    rv = SCardConnect(handle->hContext, handle->readerName, SCARD_SHARE_SHARED,
                      SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &handle->hCard,
                      &handle->activeProtocol);

    if (rv == SCARD_E_NO_SMARTCARD) {
        SCARD_READERSTATE rgReaderStates;
        rgReaderStates.szReader = handle->readerName;  // reader ID to test
        rgReaderStates.dwCurrentState = SCARD_STATE_UNAWARE;

        if (handle->verbose)
            fprintf(stderr, "Please Insert a smartcard in reader=%s\n",
                    handle->readerName);
        for (int idx = 0; idx < ticks; idx++) {
            // wait for card to be inserted
            // wait timeout second for card to be inserted
            rv = SCardGetStatusChange(handle->hContext, 10000, &rgReaderStates,
                                      1);
            if (rv != SCARD_S_SUCCESS)
                goto OnErrorExit;

            if (rgReaderStates.dwCurrentState != rgReaderStates.dwEventState) {
                rgReaderStates.dwCurrentState = rgReaderStates.dwEventState;

                // card is present
                if (rgReaderStates.dwEventState & SCARD_STATE_PRESENT)
                    break;
                if (handle->verbose)
                    fprintf(stderr, ".");
            }
        }
        if (handle->verbose)
            fprintf(stderr, "\n");
        rv = SCardConnect(handle->hContext, handle->readerName,
                          SCARD_SHARE_SHARED,
                          SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &handle->hCard,
                          &handle->activeProtocol);
    }

    if (rv != SCARD_S_SUCCESS)
        goto OnErrorExit;

    // set up the io request
    switch (handle->activeProtocol) {
    case SCARD_PROTOCOL_T0:
        handle->pioSendPci = SCARD_PCI_T0;
        break;
    case SCARD_PROTOCOL_T1:
        handle->pioSendPci = SCARD_PCI_T1;
        break;
    default:
        RP_CRITICAL(
            "[pcsc-sccard-check] SCARD_PCI Unknown protocol (SCardConnect)");
        goto OnErrorExit;
    }

    return 0;

OnErrorExit:
    handle->error = pcsc_stringify_error(rv);
    RP_ERROR(
        "[pcsc-sccard-check] Fail get connect smart card reader=%s. "
        "(SCardConnect=%s)",
        handle->readerName, pcsc_stringify_error(rv));
    return -1;
}

// thread monitoring reader status change
static void *pcscMonitorThread(void *ptr)
{
    pcscThreadT *threadCtx = (pcscThreadT *)ptr;
    pcscHandleT *handle = threadCtx->pcsc;
    assert(handle->magic == PCSC_HANDLE_MAGIC);
    long rv;
    int err;

    SCARD_READERSTATE rgReaderStates;
    rgReaderStates.szReader = handle->readerName;  // reader ID to test
    rgReaderStates.dwCurrentState = SCARD_STATE_UNAWARE;
    RP_DEBUG("[pcsc-thread-monitor] starting new thread tid=0x%lx",
             pthread_self());

    // loop forever until reader is disconnected
    while (1) {
        // wait timeout second for card to be inserted
        rv = SCardGetStatusChange(handle->hContext, handle->timeout * 1000,
                                  &rgReaderStates, 1);

        switch (rv) {
        case SCARD_E_CANCELLED:
            goto OnCancelExit;

        case SCARD_E_TIMEOUT:
            if (!handle->timeout)
                continue;
            break;

        case SCARD_S_SUCCESS:
            if (rgReaderStates.dwCurrentState != rgReaderStates.dwEventState) {
                // update pcsc handle status change
                rgReaderStates.dwCurrentState = rgReaderStates.dwEventState;

                // card was inserted retreive uuid/atr
                if (rgReaderStates.dwEventState & SCARD_STATE_PRESENT) {
                    rv = SCardConnect(handle->hContext, handle->readerName,
                                      SCARD_SHARE_SHARED,
                                      SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                                      &handle->hCard, &handle->activeProtocol);
                    if (rv != SCARD_S_SUCCESS)
                        goto OnErrorExit;

                    // set up the io request
                    switch (handle->activeProtocol) {
                    case SCARD_PROTOCOL_T0:
                        handle->pioSendPci = SCARD_PCI_T0;
                        break;
                    case SCARD_PROTOCOL_T1:
                        handle->pioSendPci = SCARD_PCI_T1;
                        break;
                    default:
                        RP_CRITICAL(
                            "[pcsc-sccard-check] SCARD_PCI Unknown protocol "
                            "(SCardConnect)");
                        goto OnErrorExit;
                    }
                }
                // card was removed cleanup UUID/ATR
                if (rgReaderStates.dwEventState & SCARD_STATE_EMPTY) {
                    handle->uuid = 0;
                    handle->cardId = ATR_UNKNOWN;
                }
            }

            if (handle->verbose)
                fprintf(stderr, "\n -- async: reader=%s status=0x%lx\n",
                        handle->readerName, rgReaderStates.dwEventState);
            err = threadCtx->callback(handle, rgReaderStates.dwEventState,
                                      threadCtx->userData);
            if (err < 0)
                goto OnErrorExit;
            if (err > 0)
                goto OnRequestExit;
            break;
        default:
            goto OnErrorExit;
        }
    }

OnRequestExit:
    RP_DEBUG("[pcsc-thread-monitor] card-remove exit tid=0x%lx",
             pthread_self());
    free(threadCtx);
    handle->tid = 0;
    return NULL;

OnCancelExit:
    RP_DEBUG("[pcsc-thread-monitor] session-cancel exit tid=0x%lx",
             pthread_self());
    free(threadCtx);
    handle->tid = 0;
    return NULL;

OnErrorExit:
    handle->error = pcsc_stringify_error(rv);
    RP_ERROR(
        "[pcsc-thread-monitor] Reader not avaliable tid=0x%lx exited err=%s",
        pthread_self(), handle->error);
    free(threadCtx);
    handle->tid = 0;
    return NULL;
}

// start a posix thread to monitor reader status
ulong pcscMonitorReader(pcscHandleT *handle,
                        pcscStatusCbT callback,
                        void *userData)
{
    assert(handle->magic == PCSC_HANDLE_MAGIC);
    int err;

    if (handle->tid) {
        handle->error = "[pcsc-monitor-fail] monitoring thread already present";
        goto OnErrorExit;
    }

    pcscThreadT *threadCtx = calloc(1, sizeof(pcscThreadT));
    threadCtx->userData = userData;
    threadCtx->pcsc = handle;
    threadCtx->callback = callback;

    err = pthread_create(&threadCtx->tid, NULL, pcscMonitorThread,
                         (void *)threadCtx);
    if (err) {
        handle->error = strerror(errno);
        goto OnErrorExit;
    }
    handle->tid = threadCtx->tid;  // prevent from starting two thread
    return (ulong)threadCtx->tid;

OnErrorExit:
    RP_ERROR(
        "[pcsc-sccard-monitor] Fail monitoring reader=%s. (pcscMonitorReader "
        "err=%s)",
        handle->uid, strerror(errno));
    return 0;
}

// start a posix thread to monitor reader status
int pcscMonitorWait(pcscHandleT *handle, pcscMonitorActionE action, ulong tid)
{
    assert(handle->magic == PCSC_HANDLE_MAGIC);

    switch (action) {
    case PCSC_MONITOR_WAIT:
        RP_DEBUG("[pcsc-thread-join] tid=0x%lx (pcscMonitorWait)", tid);
        pthread_join(tid, NULL);  // infinit wait for monitor to quit
        break;

    case PCSC_MONITOR_CANCEL:
        RP_DEBUG("[pcsc-thread-cancel] tid=0x%lx (pcscMonitorWait)", tid);
        SCardCancel(handle->hContext);
        break;

    default:
        goto OnErrorExit;
    }

    return 0;

OnErrorExit:
    handle->error = strerror(errno);
    RP_ERROR(
        "[pcsc-sccard-monitor] Unknown action on monitor reader=%s. "
        "(pcscMonitorWait err=%s)",
        handle->readerName, strerror(errno));
    return -1;
}

int pcscDisconnect(pcscHandleT *handle)
{
    assert(handle->magic == PCSC_HANDLE_MAGIC);
    long rv;

    // abandon any pending operation
    SCardCancel(handle->hContext);

    // disconnect reader
    rv = SCardReleaseContext(handle->hContext);
    if (rv != SCARD_S_SUCCESS)
        goto OnErrorExit;

    handle->magic = 0;
    free(handle);
    return 0;

OnErrorExit:
    RP_ERROR("[pcsc-disconnect-fail] fail to free pcsc handle err=%s",
             pcsc_stringify_error(rv));
    return -1;
}

pcscHandleT *pcscList(const char **readerList, ulong *readerMax)
{
    pcscHandleT *handle = calloc(1, sizeof(pcscHandleT));
    handle->timeout = PCSC_DFLT_TIMEOUT;
    handle->activeProtocol = -1;
    long rv;

    // connect to pcscd as system user
    rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL,
                               &handle->hContext);
    if (rv != SCARD_S_SUCCESS) {
        RP_CRITICAL(
            "[pcsc-init-fail] to found pcscd ressource manager [check pcscd "
            "-d]. (SCardEstablisscardCtx=%s)",
            pcsc_stringify_error(rv));
        goto OnErrorExit;
    }
    // get reader list (hoops!!! a string with token split by '\0')
    DWORD readerLiStatusLen = SCARD_AUTOALLOCATE;
    LPSTR readerListStr = NULL;
    rv = SCardListReaders(handle->hContext, NULL, (LPSTR)&readerListStr,
                          &readerLiStatusLen);
    if (rv != SCARD_S_SUCCESS) {
        RP_CRITICAL(
            "[pcsc-reader-scan] Fail to list pcscd reader [check pcsc-ccid "
            "supported reader]. (SCardListReaders=%s)",
            pcsc_stringify_error(rv));
        goto OnErrorExit;
    }
    // extract reader name from tokenized string
    int readerCount = 0;
    for (char *ptr = readerListStr; *ptr != '\0'; ptr += strlen(ptr) + 1) {
        if (readerCount == *readerMax) {
            RP_CRITICAL(
                "[pcsc-reader-scan] too many readers increase 'maxdev=%ld' "
                "(remaining ignored)",
                *readerMax);
            break;
        }
        readerList[readerCount++] = ptr;
    }
    *readerMax = readerCount;
    handle->magic = PCSC_HANDLE_MAGIC;
    return handle;

OnErrorExit:
    return NULL;
}

// search for reader and create corresponding pcsc-lite handle
pcscHandleT *pcscConnect(const char *uid, const char *readerName)
{
    // extract reader name from tokenized string
    const char *readerList[PCSC_READER_DEV_MAX];
    ulong readerCount = PCSC_READER_DEV_MAX;
    pcscHandleT *handle = pcscList(readerList, &readerCount);
    if (!handle)
        goto OnErrorExit;

    // if readername == NULL take 1st one from the list else search within the
    // list
    if (readerName) {
        handle->readerId = -1;
        for (int idx = 0; idx < readerCount; idx++) {
            RP_DEBUG("reader[%d]=%s", idx, readerList[idx]);
            if (strcasestr(readerList[idx], readerName)) {
                handle->readerId = idx;
                handle->readerName = strdup(readerList[idx]);
                break;
            }
        }
        if (handle->readerId < 0) {
            RP_CRITICAL("[pcsc-reader-unknown] reader=%s", handle->readerName);
            if (handle->verbose) {
                RP_NOTICE("-- reader list count=%ld", readerCount);
                for (int jdx = 0; jdx < readerCount - 1; jdx++) {
                    RP_NOTICE(" -- reader[%d]=%s", jdx, readerList[jdx]);
                }
            }
            goto OnErrorExit;
        }
    }
    else {
        handle->readerId = 0;
        handle->readerName = strdup(readerList[0]);
    }
    return (handle);

OnErrorExit:
    free(handle);
    return NULL;
}

// setter for reader options
int pcscSetOpt(pcscHandleT *handle, pcscOptsE option, ulong value)
{
    assert(handle->magic == PCSC_HANDLE_MAGIC);

    // if no value keep defaults
    if (value) {
        switch (option) {
        case PCSC_OPT_TIMEOUT:
            handle->timeout = value;
            break;
        case PCSC_OPT_VERBOSE:
            handle->verbose = value;
            break;

        default:
            goto OnErrorExit;
        }
    }
    return 0;

OnErrorExit:
    RP_ERROR("[pcsc-opt-unknown] Invalid option (pcscSetOpt)");
    return -1;
}

// check card UUID
u_int64_t pcscGetCardUuid(pcscHandleT *handle)
{
    assert(handle->magic == PCSC_HANDLE_MAGIC);
    int err;

    // if card atr not decoded, do it now
    if (!handle->cardId) {
        err = pcscCardCheckAtr(handle);
        if (err)
            goto OnErrorExit;
    }
    // if uuid not store check it now
    if (!handle->uuid)
        handle->uuid = pcscGetCardUuidNum(handle);
    return (handle->uuid);

OnErrorExit:
    return 0;
}

// Create access control bit trailer
// https://www.nxp.com/docs/en/data-sheet/MF1S70YYX_V1.pdf
static size_t pcscMifareTrailer(pcscHandleT *handle,
                                const pcscTrailerT *trailer,
                                u_int8_t *dataBuf,
                                size_t dataLen)
{
    static size_t dlen = 2 * PCSC_MIFARE_KEY_LEN + PCSC_MIFARE_ACL_LEN;
    u_int8_t dfltAcls[] = {0xFF, 0x07, 0x80, 0x69};

    if (trailer->keyA->klen != PCSC_MIFARE_KEY_LEN ||
        (trailer->keyB && trailer->keyB->klen != PCSC_MIFARE_KEY_LEN)) {
        handle->error = "Mifare Keylen should equal PCSC_MIFARE_KEY_LEN(len:6)";
        goto OnErrorExit;
    }

    if (dataLen < dlen) {
        handle->error = "Mifare Header data buffer too small (min:16)";
        goto OnErrorExit;
    }

    if (!trailer->keyA) {
        handle->error = "Mifare trailer keyA mandatory";
        goto OnErrorExit;
    }
    // default reset data to NULL and write KEYA
    memset(dataBuf, 0, dlen);
    memcpy(&dataBuf[0], trailer->keyA->kval, PCSC_MIFARE_KEY_LEN);

    if (trailer->acls)
        memcpy(&dataBuf[PCSC_MIFARE_KEY_LEN], trailer->acls,
               PCSC_MIFARE_ACL_LEN);
    else
        memcpy(&dataBuf[PCSC_MIFARE_KEY_LEN], dfltAcls, PCSC_MIFARE_ACL_LEN);

    if (trailer->keyB)
        memcpy(&dataBuf[PCSC_MIFARE_KEY_LEN + PCSC_MIFARE_ACL_LEN],
               trailer->keyB->kval, PCSC_MIFARE_KEY_LEN);

    return dlen;

OnErrorExit:
    RP_ERROR("[pcsc-trailer-fail] cmd=Mifare action=MkTrailer err=%s",
             handle->error);
    return 0;
}

const pcscKeyT *pcscNewKey(const char *uid, u_int8_t *value, size_t len)
{
    pcscKeyT *key = calloc(1, sizeof(pcscKeyT));
    key->uid = uid;
    key->kval = value;
    key->klen = (u_int8_t)len;

    if (!key->klen)
        key->klen = (u_int8_t)strlen((char *)value);
    return key;
}

// Write trailer access control key/bits
int pcsWriteTrailer(pcscHandleT *handle,
                    const char *uid,
                    u_int8_t secIdx,
                    u_int8_t blkIdx,
                    const pcscKeyT *key,
                    const pcscTrailerT *trailer)
{
    assert(handle->magic == PCSC_HANDLE_MAGIC);
    u_int8_t data[16];
    int err;

    if (handle->verbose)
        fprintf(stderr,
                "\n# pcsWriteTrailer reader=%s cmd=%s scard=%ld blk=%d\n",
                handle->readerName, uid, handle->uuid, blkIdx);
    switch (handle->cardId) {
    case ATR_MIFARE_1K:
    case ATR_MIFARE_4K:

        // WARNING !!! invalid keys/acls may bick your smart card check
        // http://calc.gmss.ru/Mifare1k/
        if (!trailer || !trailer->acls || !trailer->keyA || !trailer->keyB) {
            handle->error =
                "Fatal: Trailer with KEYS[A+B]/ACLS mandatory for access "
                "control header\n";
            goto OnErrorExit;
        }
        // check blockIdx is a trailer
        if (blkIdx % 4 != 3) {
            handle->error =
                "Fatal: Trailer Mifare invalid block (should be last sector "
                "one)\n";
            goto OnErrorExit;
        }

        size_t dlen = pcscMifareTrailer(handle, trailer, data, sizeof(data));
        if (dlen == 0)
            goto OnErrorExit;

        err = pcsWriteBlock(handle, uid, secIdx, blkIdx, data, dlen, key);
        if (err)
            goto OnErrorExit;
        break;

    default:
        handle->error = "Trailer access bits unsupported smart card model";
        goto OnErrorExit;
    }
    return 0;

OnErrorExit:
    return -1;
}

const char *pcscReaderName(pcscHandleT *handle)
{
    assert(handle->magic == PCSC_HANDLE_MAGIC);
    return (handle->readerName);
}

const char *pcscErrorMsg(pcscHandleT *handle)
{
    assert(handle->magic == PCSC_HANDLE_MAGIC);
    return (handle->error);
}

void *pcscGetCtx(pcscHandleT *handle)
{
    assert(handle->magic == PCSC_HANDLE_MAGIC);
    return (handle->ctx);
}
