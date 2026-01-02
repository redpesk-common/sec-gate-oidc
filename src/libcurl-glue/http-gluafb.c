/*
 * Copyright (C) 2021-2026 IoT.bzh Company
 * Author: "Fulup Ar Foll" <fulup@iot.bzh>
 * Author: <jose.bollo@iot.bzh>
 * Author: <dev-team@iot.bzh>
 *
 * Use of this efd code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT. $RP_END_LICENSE$
 */

#define _GNU_SOURCE

#include "curl-glue.h"

#include <assert.h>
#include <curl/curl.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include <libafb/core/afb-ev-mgr.h>
#include <libafb/core/afb-sched.h>
#include <libafb/sys/ev-mgr.h>

//  (void *efd, int sock, uint32_t revents, void *ctx)
static void glueOnSocketCB(struct ev_fd *efd,
                           int sock,
                           uint32_t revents,
                           void *ctx)
{
    httpRqtHndlT *httpRqtHndl = (httpRqtHndlT *)ctx;
    int action = 0;

    // translate libafb event into curl event
    if (revents & EV_FD_IN)
        action |= CURL_CSELECT_IN;
    if (revents & EV_FD_OUT)
        action |= CURL_CSELECT_OUT;
    if (revents & EV_FD_ERR)
        action |= CURL_CSELECT_ERR;

    httpOnSocketCB(httpRqtHndl, sock, action);
}

// create libafb efd event and attach http processing callback to sock fd
static int glueSetSocketCB(httpRqtHndlT *httpRqtHndl,
                           int sock,
                           int what,
                           void **psockdata)
{
    struct ev_fd **pefd = (struct ev_fd **)psockdata;
    struct ev_fd *efd = *pefd;  // on 1st call efd is null
    uint32_t events = 0;

    // map CURL events with system events
    switch (what) {
    default:
    case CURL_POLL_REMOVE:
        break;
    case CURL_POLL_IN:
        events = EV_FD_IN;
        break;
    case CURL_POLL_OUT:
        events = EV_FD_OUT;
        break;
    case CURL_POLL_INOUT:
        events = EV_FD_IN | EV_FD_OUT;
        break;
    }

    // end or error
    if (events == 0) {
        if (efd != NULL) {
            ev_fd_unref(efd);
            *pefd = NULL;
        }
        return -(what != CURL_POLL_REMOVE);
    }
    // set the efd or create it
    if (efd != NULL)
        ev_fd_set_events(efd, events);
    else if (afb_ev_mgr_add_fd(pefd, sock, events, glueOnSocketCB, httpRqtHndl,
                               0, 1) < 0)
        return -1;
    return 0;
}

// map libafb ontimer with multi version
static void glueOnTimerCB(struct ev_timer *tim, void *ctx, unsigned decount)
{
    // signal should be null
    if (signal)
        return;

    httpRqtHndlT *httpRqtHndl = (httpRqtHndlT *)ctx;
    httpOnTimerCB(httpRqtHndl);
}

// arm a one shot timer in ms
static int glueSetTimerCB(httpRqtHndlT *httpRqtHndl,
                          long timeout,
                          void **ptimedata)
{
    int err;
    struct ev_timer **ptim = (struct ev_timer **)ptimedata;
    struct ev_timer *tim = *ptim;  // on 1st call efd is null

    if (tim) {
        ev_timer_unref(tim);
        *ptim = NULL;
    }
    if (timeout >= 0) {
        if (afb_ev_mgr_add_timer(ptim, 0, (time_t)timeout / 1000,
                                 (unsigned)timeout % 1000, 1, 0, 0,
                                 glueOnTimerCB, httpRqtHndl, 0) < 0)
            return -1;
    }
    return 0;
}

static const httpCallbacksT libafbCbs = {
    .multiTimer = glueSetTimerCB,
    .multiSocket = glueSetSocketCB,
    .evtMainLoop = NULL,
    .evtRunLoop = NULL,
};

const httpCallbacksT *glueGetCbs()
{
    return &libafbCbs;
}
