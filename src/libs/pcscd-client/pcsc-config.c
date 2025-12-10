/*
 * Copyright (C) 2015-2021 IoT.bzh Company
 * Author "Fulup Ar Foll"
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

#define _GNU_SOURCE

#include "pcsc-config.h"
#include <libafb/misc/afb-verbose.h>

#include <assert.h>
#include <rp-utils/rp-jsonc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

typedef struct
{
    const char *label;
    const int value;
} pcscKeyEnumT;

static const pcscKeyEnumT pcscActionsE[] = {
    {"read", PCSC_ACTION_READ},
    {"write", PCSC_ACTION_WRITE},
    {"trailer", PCSC_ACTION_TRAILER},
    {"uuid", PCSC_ACTION_UUID},
    {NULL}  // terminator
};

// search for key label within key/value array
static int pcscLabel2Value(const pcscKeyEnumT *keyvals, const char *label)
{
    int value = 0;
    if (!label)
        goto OnDefaultExit;

    for (int idx = 0; keyvals[idx].label; idx++) {
        if (!strcasecmp(label, keyvals[idx].label)) {
            value = keyvals[idx].value;
            break;
        }
    }
    return value;

OnDefaultExit:
    return keyvals[0].value;
}

// search a key from its uid
static pcscKeyT *pcscKeyByUid(pcscConfigT *config, const char *keyUid)
{
    pcscKeyT *key = NULL;

    if (config->keys) {
        for (int idx = 0; config->keys[idx].uid; idx++) {
            if (!strcasecmp(config->keys[idx].uid, keyUid)) {
                key = &config->keys[idx];
                break;
            }
        }
    }
    return key;
}

// parse keys or command data as asci string or hexa array
static int pcscParseOneData(json_object *dataJ, u_int8_t **data, ulong *dlen)
{
    switch (json_object_get_type(dataJ)) {
        const char *byteS, *dataS;
        u_int8_t *valueB;
        int err, byte;
        size_t count;

    case json_type_string:
        dataS = json_object_get_string(dataJ);
        // if no dlen then use data string len
        if (!*dlen) {
            *dlen = strlen(dataS);
            *data = (u_int8_t *)strdup(dataS);
        }
        else {
            *data = malloc(*dlen);
            strncpy((char *)*data, dataS, *dlen);
        }
        break;

    case json_type_array:
        count = json_object_array_length(dataJ);
        valueB = calloc(count + 1, sizeof(u_int8_t));

        for (int idx = 0; idx < count; idx++) {
            byteS =
                json_object_get_string(json_object_array_get_idx(dataJ, idx));
            err = sscanf(byteS, "0x%2x", &byte);
            if (err < 0)
                goto OnErrorExit;
            if (byte > 255)
                goto OnErrorExit;
            valueB[idx] = (u_int8_t)byte;
        }

        *dlen = count;
        *data = valueB;
        break;

    default:
        goto OnErrorExit;
    }
    return 0;

OnErrorExit:
    EXT_CRITICAL(
        "[pcsc-onevalue-fail] key/cmd data should be asci/string or array of "
        "hexa/string (pcscParseOneData)");
    return -1;
}

static int pcscParseOneKey(pcscConfigT *config,
                           json_object *keyJ,
                           pcscKeyT *key)
{
    int err;
    json_object *valueJ = NULL;

    // {"uid":"abc, "idx": 0, "value":"asci value" }
    err = rp_jsonc_unpack(keyJ, "{ss,s?i,so !}", "uid", &key->uid, "idx",
                          &key->kidx, "value", &valueJ);
    if (err) {
        EXT_CRITICAL(
            "[pcsc-onekey-fail] json supported keys:[uid,idx,value] "
            "(pcscParseOneKey)");
        goto OnErrorExit;
    }
    // value should be an asci string or an array of hexa valueB
    ulong klen;
    err = pcscParseOneData(valueJ, &key->kval, &klen);
    if (err)
        goto OnErrorExit;
    key->klen = (uint8_t)klen;

    return 0;

OnErrorExit:
    return -1;
}

static int pcscParseOneTrailer(pcscConfigT *config,
                               json_object *trailerJ,
                               pcscTrailerT **trailer)
{
    int err;
    json_object *valueJ = NULL;
    const char *keyA, *keyB;
    pcscTrailerT *response = calloc(1, sizeof(pcscTrailerT));

    // "trailer": {"keys": ["key-a","keyb"],
    // "acls":["0xF0","0xF7","0x80","0x00"]}
    err = rp_jsonc_unpack(trailerJ, "{ss,ss,so !}", "keyA", &keyA, "keyB",
                          &keyB, "acls", &valueJ);
    if (err) {
        EXT_CRITICAL(
            "[pcsc-onetrailer-fail] json mandatory keys:[keyA,keyA,acls] "
            "(pcscParseOneKey)");
        goto OnErrorExit;
    }

    response->keyA = pcscKeyByUid(config, keyA);
    response->keyB = pcscKeyByUid(config, keyB);
    if (!response->keyA || !response->keyB) {
        EXT_CRITICAL("[pcsc-onetrailer-fail] KeyA=%s keyB=%s not found", keyA,
                     keyB);
        goto OnErrorExit;
    }
    // value should be an asci string or an array of hexa valueB
    ulong alen;
    err = pcscParseOneData(valueJ, &response->acls, &alen);
    if (err || alen != 4)
        goto OnErrorExit;
    response->alen = (uint8_t)alen;

    *trailer = response;
    return 0;

OnErrorExit:
    free(response);
    return -1;
}

static int pcscParseOneCmd(pcscConfigT *config,
                           json_object *cmdJ,
                           pcscCmdT *cmd)
{
    int err;
    json_object *dataJ = NULL, *trailerJ = NULL;
    const char *keyUid = NULL, *cmdAction;

    // {"uid":"zzz", "action":"write", "blk": xx, "key":"kuid","data": ["0xab",
    // "0x01", ....]},
    err = rp_jsonc_unpack(cmdJ, "{ss,ss,s?i,s?i,s?i,s?s,s?o,s?o,s?i !}", "uid",
                          &cmd->uid, "action", &cmdAction, "sec", &cmd->sec,
                          "blk", &cmd->blk, "len", &cmd->dlen, "key", &keyUid,
                          "data", &dataJ, "trailer", &trailerJ, "group",
                          &cmd->group);
    if (err) {
        EXT_CRITICAL(
            "[pcsc-onecmd-fail] json supported "
            "keys:[uid,action,blk,key,data,len] (pcscParseOneCmd)");
        goto OnErrorExit;
    }
    // check action
    cmd->action = pcscLabel2Value(pcscActionsE, cmdAction);
    switch (cmd->action) {
    case PCSC_ACTION_READ:
        if (!cmd->dlen || dataJ) {
            EXT_CRITICAL(
                "[pcsc-onecmd-fail] uid=%s action=%s len:mandatory "
                "data:forbiden (pcscParseOneCmd)",
                cmd->uid, cmdAction);
            goto OnErrorExit;
        }
        cmd->dlen +=
            PCSC_MIFARE_STATUS_LEN;  // reserve 2 byte for Mifare read status
        break;

    case PCSC_ACTION_UUID:
        if (!cmd->dlen)
            cmd->dlen = sizeof(u_int64_t);
        cmd->dlen +=
            PCSC_MIFARE_STATUS_LEN;  // reserve 2 byte for Mifare read status
        break;

    case PCSC_ACTION_WRITE:
        if (!dataJ) {
            EXT_CRITICAL(
                "[pcsc-onecmd-fail] uid=%s action=%s data:mandatory "
                "(pcscParseOneCmd)",
                cmd->uid, cmdAction);
            goto OnErrorExit;
        }
        err = pcscParseOneData(dataJ, &cmd->data, &cmd->dlen);
        if (err)
            goto OnErrorExit;
        break;

    case PCSC_ACTION_TRAILER:
        if (dataJ || cmd->dlen || !trailerJ) {
            EXT_CRITICAL(
                "[pcsc-onecmd-fail] uid=%s action=%s trailer mandary len+data "
                "forbiden (pcscParseOneCmd)",
                cmd->uid, cmdAction);
            goto OnErrorExit;
        }

        err = pcscParseOneTrailer(config, trailerJ, &cmd->trailer);
        if (err)
            goto OnErrorExit;
        break;

    default:
        EXT_CRITICAL(
            "[pcsc-onecmd-fail] uid=%s action=%s unknown (pcscParseOneCmd)",
            cmd->uid, cmdAction);
        goto OnErrorExit;
    }

    // if key is defined search for it
    if (keyUid) {
        cmd->key = pcscKeyByUid(config, keyUid);
        if (!cmd->key) {
            EXT_CRITICAL(
                "[pcsc-onecmd-fail] cmd=%s keys=%s non found within defined "
                "keys] (pcscParseOneCmd)",
                cmd->uid, keyUid);
            goto OnErrorExit;
        }
    }
    // add command to cmd hash table
    HASH_ADD_KEYPTR(hh, config->hTable, cmd->uid, strlen(cmd->uid), cmd);

    return 0;

OnErrorExit:
    return -1;
}

pcscConfigT *pcscParseConfig(json_object *configJ, const int verbosity)
{
    int err;
    pcscConfigT *config = calloc(1, sizeof(pcscConfigT));
    json_object *cmdsJ = NULL, *keysJ = NULL;
    config->verbose = verbosity;
    config->maxdev = PCSC_MAX_DEV;

    err = rp_jsonc_unpack(configJ, "{s?s s?s ss s?i s?i s?i s?o s?o !}", "uid",
                          &config->uid, "info", &config->info, "reader",
                          &config->reader, "maxdev", &config->maxdev, "debug",
                          &config->verbose, "timeout", &config->timeout, "cmds",
                          &cmdsJ, "keys", &keysJ);
    if (err) {
        EXT_CRITICAL(
            "[pcsc-config-fail] config json supported "
            "keys:[into,reader,cmds,keys] (pcscParseConfig)");
        goto OnErrorExit;
    }

    if (!config->uid)
        config->uid = config->reader;

    if (keysJ && !cmdsJ) {
        EXT_CRITICAL(
            "[pcsc-config-fail] key 'cmds' mandatory when 'keys' present "
            "(pcscParseConfig)");
        goto OnErrorExit;
    }
    // parse keys and create a hash table
    switch (json_object_get_type(keysJ)) {
        size_t kcount;

    case json_type_object:
        config->keys = calloc(2, sizeof(pcscKeyT));
        err = pcscParseOneKey(config, keysJ, &config->keys[0]);
        if (err)
            goto OnErrorExit;
        break;

    case json_type_array:
        kcount = json_object_array_length(keysJ);
        config->keys = calloc(kcount + 1, sizeof(pcscKeyT));
        for (int idx = 0; idx < kcount; idx++) {
            json_object *keyJ = json_object_array_get_idx(keysJ, idx);
            err = pcscParseOneKey(config, keyJ, &config->keys[idx]);
            if (err)
                goto OnErrorExit;
        }
        break;

    case json_type_null:
        // use default keys
        break;

    default:
        EXT_CRITICAL("[pcsc-config-fail] keys should be  (pcscParseConfig)");
        goto OnErrorExit;
    }

    // parse commands
    switch (json_object_get_type(cmdsJ)) {
        size_t ccount;

    case json_type_object:
        config->cmds = calloc(2, sizeof(pcscCmdT));
        err = pcscParseOneCmd(config, cmdsJ, &config->cmds[0]);
        if (err)
            goto OnErrorExit;
        break;

    case json_type_array:
        ccount = json_object_array_length(cmdsJ);
        config->cmds = calloc(ccount + 1, sizeof(pcscCmdT));
        for (int idx = 0; idx < ccount; idx++) {
            json_object *cmdJ = json_object_array_get_idx(cmdsJ, idx);
            err = pcscParseOneCmd(config, cmdJ, &config->cmds[idx]);
            if (err)
                goto OnErrorExit;
        }
        break;

    case json_type_null:
        // use default cmds
        break;

    default:
        EXT_CRITICAL(
            "[pcsc-config-fail] cmds should be json object or array of object "
            "(pcscParseConfig)");
        goto OnErrorExit;
    }
    config->magic = PCSC_CONFIG_MAGIC;
    return config;

OnErrorExit:
    return NULL;
}

// get a command from its uid using uthash table
pcscCmdT *pcscCmdByUid(pcscConfigT *config, const char *uid)
{
    assert(config->magic == PCSC_CONFIG_MAGIC);
    pcscCmdT *cmd;

    HASH_FIND_STR(config->hTable, uid, cmd);
    return cmd;
}

int pcscExecOneCmd(pcscHandleT *handle, const pcscCmdT *cmd, u_int8_t *data)
{
    int err;
    ulong dlen = cmd->dlen;

    switch (cmd->action) {
    case PCSC_ACTION_READ:
        err = pcscReadBlock(handle, cmd->uid, cmd->sec, cmd->blk, data, dlen,
                            cmd->key);
        if (err)
            goto OnErrorExit;
        break;

    case PCSC_ACTION_WRITE:
        err = pcsWriteBlock(handle, cmd->uid, cmd->sec, cmd->blk, cmd->data,
                            cmd->dlen, cmd->key);
        if (err)
            goto OnErrorExit;
        break;

    case PCSC_ACTION_TRAILER:
        err = pcsWriteTrailer(handle, cmd->uid, cmd->sec, cmd->blk, cmd->key,
                              cmd->trailer);
        if (err)
            goto OnErrorExit;
        break;

    case PCSC_ACTION_UUID:
        err = pcscReadUuid(handle, cmd->uid, data, &dlen);
        if (err)
            goto OnErrorExit;
        break;

    default:
        goto OnErrorExit;
    }
    return 0;

OnErrorExit:
    return -1;
}
