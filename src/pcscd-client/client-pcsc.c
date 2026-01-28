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
 */

#define _GNU_SOURCE

#include "pcsc-config.h"
#include "pcsc-glue.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <pcsclite.h>

#include <rp-utils/rp-jsonc.h>

static struct option options[] = {
    {"verbose", optional_argument, 0, 'v'},
    {"config", required_argument, 0, 'c'},
    {"group", required_argument, 0, 'g'},
    {"async", optional_argument, 0, 'a'},
    {"force", optional_argument, 0, 'f'},
    {"list", no_argument, 0, 'l'},
    {"help", optional_argument, 0, 'h'},
    {0, 0, 0, 0}  // trailer
};

typedef struct
{
    const char *cnfpath;
    int verbose;
    int index;
    int group;
    int forced;
    int async;
    int list;
    pcscConfigT *config;
} pcscParamsT;

pcscParamsT *parseArgs(int argc, char *argv[])
{
    pcscParamsT *params = calloc(1, sizeof(pcscParamsT));
    int index;

    if (argc < 2)
        goto OnErrorExit;

    for (int done = 0; !done;) {
        int option = getopt_long(argc, argv, "a::c:f::g:lv::", options, &index);
        if (option == -1) {
            params->index = optind;
            break;
        }
        // option return short option even when long option is given
        switch (option) {
        case 'v':
            params->verbose++;
            if (optarg)
                params->verbose = atoi(optarg);
            break;

        case 'c':
            params->cnfpath = optarg;
            break;

        case 'l':
            params->list++;
            break;

        case 'g':
            params->group = atoi(optarg);
            break;

        case 'f':
            params->forced++;
            if (optarg)
                params->forced = atoi(optarg);
            break;

        case 'a':
            params->async++;
            if (optarg)
                params->async = atoi(optarg);
            break;

        case 'h':
        default:
            goto OnErrorExit;
        }
    }

    if (!params->cnfpath && !params->list)
        goto OnErrorExit;

    return params;

OnErrorExit:
    fprintf(stderr,
            "usage: pcsc-client --config=/xxx/my-config.json [--async] "
            "[--group=-+0-9] [--verbose] [--force] [--list]\n");
    return NULL;
}

// execute commands from requested group
static int execGroupCmd(pcscHandleT *handle, pcscParamsT *params)
{
    pcscConfigT *config = params->config;
    int jump = 0;
    int err;

    // loop on defined commands
    for (int idx = 0; config->cmds[idx].uid; idx++) {
        const pcscCmdT *cmd = &config->cmds[idx];
        u_int8_t data[cmd->dlen];

        if (params->group <= cmd->group * -1 || params->group == cmd->group) {
            jump = 1;
            err = pcscExecOneCmd(handle, cmd, data);
            if (err) {
                fprintf(stderr, " -- Fail Executing command uid=%s error=%s\n",
                        cmd->uid, pcscErrorMsg(handle));
                if (!params->forced)
                    goto OnErrorExit;
            }
        }
        else {
            if (params->verbose) {
                if (jump) {
                    fprintf(stderr, "\n");
                    jump = 0;
                }
                fprintf(stderr, " -- Ignoring cmd=%s group=%d\n", cmd->uid,
                        cmd->group);
            }
        }
    }
    fprintf(stderr, "\n ** OK: Cmds/group=%d [done]\n", params->group);
    if (params->async)
        fprintf(stderr, " ?? Insert new scard/token ??\n");
    return 0;

OnErrorExit:
    return -1;
}

// in asynchronous mode CB is call each time reader status change
static int readerMonitorCB(pcscHandleT *handle, ulong state, void *ctx)
{
    pcscParamsT *params = (pcscParamsT *)ctx;
    int err;

    if (state & SCARD_STATE_PRESENT) {
        fprintf(stderr, " -- event: reader=%s card=0x%lx inserted\n",
                pcscReaderName(handle), pcscGetCardUuid(handle));
        err = execGroupCmd(handle, params);
        if (!params->verbose)
            fprintf(stderr,
                    " -- exec : 'group=%d' done (--verbose for detail)\n",
                    params->group);
        if (err)
            goto OnErrorExit;
    }
    else {
        fprintf(stderr, " -- event: reader=%s removed (waiting for new card)\n",
                pcscReaderName(handle));
    }
    return 0;

OnErrorExit:
    fprintf(stderr, "Fatal: closing pcsc monitoring\n");
    return -1;
}

// signal handler
static jmp_buf JumpBuffer;
static void sigHandlerCB(int sig)
{
    switch (sig) {
    case SIGINT:
        fprintf(stderr, "\nCtrl-C received\n");
        break;
    case SIGSEGV:
        fprintf(
            stderr,
            "\n(Hoops!) Sigfault check config.json with jq < my-config.json\n");
        break;
    default:
        return;
    }
    longjmp(JumpBuffer, 1);
}

int main(int argc, char *argv[])
{
    int err;
    json_object *configJ = NULL;
    pcscHandleT *handle;
    pcscParamsT *params = parseArgs(argc, argv);
    if (!params)
        goto OnErrorExit;

    // trap ctrl-C and memory fault
    signal(SIGINT, sigHandlerCB);
    signal(SIGSEGV, sigHandlerCB);
    if (setjmp(JumpBuffer) != 0)
        goto OnSignalExit;

    if (params->cnfpath) {
        // err= json_locator_from_file (&configJ, params->cnfpath);
        configJ = json_object_from_file(params->cnfpath);
        // json_object *configJ= json_tokener_parse(buffer);
        if (!configJ) {
            fprintf(stderr, "Fail to parse params.json (try jq < %s\n",
                    params->cnfpath);
            goto OnErrorExit;
        }
    }
    // list connected readers to pcscd
    if (params->list) {
        ulong readerCount = 16;
        const char *readerList[readerCount];
        fprintf(stderr, "Scanning pscsc reader ...\n");
        handle = pcscList(readerList, &readerCount);
        if (!handle) {
            fprintf(stderr, "-- Fail to connect to pcscd\n");
            goto OnErrorExit;
        }

        for (ulong idx = 0; idx < readerCount; idx++) {
            fprintf(stdout, " -- reader[%ld]=%s\n", idx, readerList[idx]);
        }
    }

    if (configJ) {
        // parse json config and store with params for asynchronous callback
        pcscConfigT *config = pcscParseConfig(configJ, params->verbose);
        if (!config)
            goto OnErrorExit;
        params->config = config;

        // create pcsc handle and set options
        handle = pcscConnect(config->uid, config->reader);
        if (!handle) {
            fprintf(stderr, "Fail to connect to reader=%s\n", config->reader);
            goto OnErrorExit;
        }
        // set options
        pcscSetOpt(handle, PCSC_OPT_VERBOSE, config->verbose);
        pcscSetOpt(handle, PCSC_OPT_TIMEOUT, config->timeout);

        // check async handling
        if (params->async) {
            pthread_t tid;

            // start smartcard reader monitoring pass params as context to
            // handle option in CB
            tid = pcscMonitorReader(handle, readerMonitorCB, (void *)params);
            if (!tid) {
                fprintf(stderr,
                        " -- Fail monitoring reader reader=%s error=%s\n",
                        pcscReaderName(handle), pcscErrorMsg(handle));
                if (!params->forced)
                    goto OnErrorExit;
            }
            fprintf(stderr,
                    " -- Waiting: %ds events for reader=%s (ctrl-C to quit)\n",
                    params->async, pcscReaderName(handle));
            err = pcscMonitorWait(handle, PCSC_MONITOR_WAIT, tid);
            if (err)
                goto OnErrorExit;
        }
        else {
            // get reader status and wait 10 timeout for card
            err = pcscReaderCheck(handle, 10);
            if (err) {
                fprintf(stderr, "Fail to detect scard on reader=%s error=%s\n",
                        pcscReaderName(handle), pcscErrorMsg(handle));
                goto OnErrorExit;
            }
            // try to get card UUID (work with almost any model)
            u_int64_t uuid = pcscGetCardUuid(handle);
            if (!uuid) {
                fprintf(stderr, "Fail reading smart card UUID error=%s\n",
                        pcscErrorMsg(handle));
                goto OnErrorExit;
            }
            fprintf(stderr, " -- Reader=%s smart uuid=%ld\n", config->reader,
                    uuid);
            err = execGroupCmd(handle, params);  // synchronous command exec
            if (err)
                goto OnErrorExit;
        }
    }

    err = pcscDisconnect(handle);
    if (err)
        goto OnErrorExit;

    if (params->verbose)
        fprintf(stderr, "OK: Success Exit\n\n");
    exit(0);

OnErrorExit:
    fprintf(stderr, "FX: Error Exit\n\n");
    exit(1);

OnSignalExit:
    fprintf(stderr, "On Signal Exit\n\n");
    exit(1);
}
