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
 */
#pragma once

#include <sys/types.h>

#define PCSC_HANDLE_MAGIC 852963147
#define PCSC_DFLT_TIMEOUT 60  // default reader change status in seconds
#define PCSC_READER_DEV_MAX 8
#define PCSC_MIFARE_STATUS_LEN \
    2  // number of byte added to read buffer for Mifare status
#define PCSC_MIFARE_KEY_LEN 6  // keyA/B len (byte)
#define PCSC_MIFARE_ACL_LEN \
    3 + 1  // Access Control Bits len (3 bytes + 1 byte userdata)

typedef enum {
    PCSC_OPT_UNKNOWN = 0,
    PCSC_OPT_TIMEOUT,
    PCSC_OPT_VERBOSE,
} pcscOptsE;

typedef enum {
    ATR_UNKNOWN = 0,
    ATR_MIFARE_1K,
    ATR_MIFARE_4K,
    ATR_MIFARE_UL,
    ATR_MIFARE_MINI,
    ATR_FELICA_212K,
    ATR_FELICA_424K,
    ATR_BANK_FR,
} atrCardidEnumT;

typedef enum {
    PCSC_MONITOR_UNKNOWN = 0,
    PCSC_MONITOR_WAIT,
    PCSC_MONITOR_CANCEL,
    PCSC_MONITOR_KILL,
} pcscMonitorActionE;

typedef struct {
    const char* uid;
    u_int8_t* kval;
    u_int8_t klen;
    u_int8_t kidx;
} pcscKeyT;

typedef struct {
    u_int8_t* acls;
    u_int8_t alen;
    pcscKeyT* keyA;
    pcscKeyT* keyB;
} pcscTrailerT;

typedef struct pcscHandleS pcscHandleT;  // opaque handle for client apps
typedef int (*pcscStatusCbT)(pcscHandleT* handle, ulong state, void* ctx);

pcscHandleT* pcscConnect(const char* uid, const char* readerName);
int pcscDisconnect(pcscHandleT* handle);
int pcscSetOpt(pcscHandleT* handle, pcscOptsE opt, ulong value);
const char* pcscReaderName(pcscHandleT* handle);
const char* pcscErrorMsg(pcscHandleT* handle);
u_int64_t pcscGetCardUuid(pcscHandleT* handle);

int pcscReaderCheck(pcscHandleT* handle, int ticks);
ulong pcscMonitorReader(pcscHandleT* handle, pcscStatusCbT callback, void* ctx);
int pcscMonitorWait(pcscHandleT* handle, pcscMonitorActionE action, ulong tid);
pcscHandleT* pcscList(const char** readerList, ulong* readerMax);

const pcscKeyT* pcscNewKey(const char* uid, u_int8_t* value, size_t len);
int pcscReadUuid(pcscHandleT* handle,
                 const char* uid,
                 u_int8_t* data,
                 ulong* dlen);
int pcsWriteTrailer(pcscHandleT* handle,
                    const char* uid,
                    u_int8_t secIdx,
                    u_int8_t blkIdx,
                    const pcscKeyT* key,
                    const pcscTrailerT* trailer);
int pcsWriteBlock(pcscHandleT* handle,
                  const char* uid,
                  u_int8_t secIdx,
                  u_int8_t blkIdx,
                  u_int8_t* dataBuf,
                  ulong dataLen,
                  const pcscKeyT* key);
int pcscReadBlock(pcscHandleT* handle,
                  const char* uid,
                  u_int8_t secIdx,
                  u_int8_t blkIdx,
                  u_int8_t* data,
                  ulong dataLen,
                  const pcscKeyT* key);
