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

#include "pcsc-glue.h"

#include <json-c/json.h>
#include <sys/types.h>
#include <uthash.h>

#define PCSC_MAX_DEV      16  // default max connected readers
#define PCSC_CONFIG_MAGIC 789654123

typedef enum {
    PCSC_ACTION_UNKNOWN = 0,
    PCSC_ACTION_READ,
    PCSC_ACTION_WRITE,
    PCSC_ACTION_TRAILER,
    PCSC_ACTION_UUID,
} pcscActionE;

typedef struct
{
    const char *uid;
    const u_int8_t sec;  // sector number (0 for mifare)
    const u_int8_t blk;  // block number for NFC tag-2
    u_int8_t *data;
    ulong dlen;
    const pcscKeyT *key;
    pcscActionE action;
    pcscTrailerT *trailer;
    int group;
    UT_hash_handle hh;
} pcscCmdT;

typedef struct
{
    const char *uid;
    ulong magic;
    const char *reader;
    ulong timeout;
    int maxdev;
    int verbose;
    const char *info;
    pcscCmdT *cmds;
    pcscKeyT *keys;
    pcscCmdT *hTable;
} pcscConfigT;

pcscConfigT *pcscParseConfig(json_object *configJ, const int verbosity);
pcscCmdT *pcscCmdByUid(pcscConfigT *config, const char *cmdUid);
int pcscExecOneCmd(pcscHandleT *handle, const pcscCmdT *cmd, u_int8_t *data);
