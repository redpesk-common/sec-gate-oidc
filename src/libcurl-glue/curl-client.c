/*
 * Copyright (C) 2021-2026 IoT.bzh Company
 * Author: "Fulup Ar Foll" <fulup@iot.bzh>
 * Author: <jose.bollo@iot.bzh>
 * Author: <dev-team@iot.bzh>
 *
 * Use of this source code is governed by an MIT-style
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

#include <rp-utils/rp-base64.h>

// multi-pool handle
typedef struct httpPoolS
{
    int verbose;
    void *evtLoop;
    void *evtTimer;
    const httpCallbacksT *evtCallback;
} httpPoolT;

// http request handle
typedef struct httpRqtHndlS
{
    int verbose;
    httpRqtCbT rqtCallback;
    httpFreeCtxCbT freeCtx;
    struct curl_slist *headers;
    CURL *easy;
    CURLM *multi;
    const httpCallbacksT *evtCallback;
    void *sockdata;
    void *timedata;
    httpPoolT *httpPool;
    httpRqtT httpRqt;
    char error[CURL_ERROR_SIZE];
} httpRqtHndlT;

static uint8_t curl_initialised = 0;
static const char nulchar = 0;

#define INIT                               \
    if (!curl_initialised) {               \
        curl_global_init(CURL_GLOBAL_ALL); \
        curl_initialised = 1;              \
    }

// create systemd source event and attach http processing callback to sock fd
static int multiSetSockCB(CURL *easy,
                          curl_socket_t sock,
                          int what,
                          void *userdata,
                          void *sockp)
{
    httpRqtHndlT *hndl = (httpRqtHndlT *)userdata;

    if (hndl->verbose > 2)
        fprintf(stderr, "[curl-client] multiSockCB sock=%d what=%d\n", sock,
                what);
    int err = hndl->evtCallback->multiSocket(hndl, sock, what, &hndl->sockdata);
    if (err && hndl->verbose)
        fprintf(stderr, "[curl-client] multiSocket failed %d", err);

    return err;
}

static int multiSetTimerCB(CURLM *curl, long timeout, void *ctx)
{
    httpRqtHndlT *hndl = (httpRqtHndlT *)ctx;
    httpPoolT *httpPool = hndl->httpPool;

    if (hndl->verbose > 2)
        fprintf(stderr, "[curl-client] multiSetTimerCB timeout=%ld\n", timeout);

    int err = hndl->evtCallback->multiTimer(hndl, timeout, &hndl->timedata);
    if (err && hndl->verbose)
        fprintf(stderr, "[curl-client] multiTimer failed %d ", err);

    return err;
}

static size_t writeBuffer(void *data,
                          size_t blkSize,
                          size_t blkCount,
                          httpBufferT *buffer)
{
    size_t size = blkSize * blkCount;
    if (size > 0) {
        char *buf = realloc((void*)buffer->buffer, buffer->length + size + 1);
        if (buf == NULL)
            return 0;

        buffer->buffer = buf;
        memcpy(&buf[buffer->length], data, size);
        buffer->length += size;
        buf[buffer->length] = 0;
    }
    return size;
}

// callback might be called as many time as needed to transfert all data
static size_t httpBodyCB(void *data, size_t blkSize, size_t blkCount, void *ctx)
{
    httpRqtHndlT *hndl = (httpRqtHndlT *)ctx;

    if (hndl->verbose > 2)
        fprintf(stderr, "[curl-client] write body %ld\n", blkCount);

    return writeBuffer(data, blkSize, blkCount, &hndl->httpRqt.body);
}

// callback might be called as many time as needed to transfert all data
static size_t httpHeadersCB(void *data,
                            size_t blkSize,
                            size_t blkCount,
                            void *ctx)
{
    httpRqtHndlT *hndl = (httpRqtHndlT *)ctx;

    if (hndl->verbose > 2)
        fprintf(stderr, "[curl-client] write headers %ld\n", blkCount);

    return writeBuffer(data, blkSize, blkCount, &hndl->httpRqt.headers);
}

static void freeHttpRqtHndl(httpRqtHndlT *hndl)
{
    if (hndl->freeCtx && hndl->httpRqt.userData)
        hndl->freeCtx(hndl->httpRqt.userData);
    if (hndl->multi != NULL) {
        curl_multi_remove_handle(hndl->multi, hndl->easy);
        hndl->evtCallback->multiSocket(hndl, -1, CURL_POLL_REMOVE,
                                       &hndl->sockdata);
        hndl->evtCallback->multiTimer(hndl, -1, &hndl->timedata);
        curl_multi_cleanup(hndl->multi);
        hndl->multi = NULL;
    }
    curl_easy_cleanup(hndl->easy);
    curl_slist_free_all(hndl->headers);
    if (hndl->httpRqt.body.buffer != &nulchar)
        free((void*)hndl->httpRqt.body.buffer);
    if (hndl->httpRqt.headers.buffer != &nulchar)
        free((void*)hndl->httpRqt.headers.buffer);
    free(hndl);
}

static void rqtDone(httpRqtHndlT *hndl, CURL *easy, CURLcode status)
{
    // first get end time
    clock_gettime(CLOCK_MONOTONIC, &hndl->httpRqt.stopTime);

    // process end status
    if (status != CURLE_OK) {
        char *url, *message;
        int len;
        curl_easy_getinfo(easy, CURLINFO_EFFECTIVE_URL, &url);

        len = asprintf(&message, "[curl-client] status=%d error='%s' url=[%s]",
                       status, curl_easy_strerror(status), url);
        if (hndl->verbose)
            fprintf(stderr, "%s\n", message);
        hndl->httpRqt.status = -(int)status;
        if (hndl->httpRqt.body.buffer != &nulchar)
            free((void*)hndl->httpRqt.body.buffer);
        hndl->httpRqt.body.buffer = message;
        hndl->httpRqt.body.length = (size_t)len;
    }
    else {
        curl_off_t off;
        long rcode;
        curl_easy_getinfo(easy, CURLINFO_SIZE_DOWNLOAD_T, &off);
        if ((size_t)off != hndl->httpRqt.body.length && hndl->verbose)
            fprintf(stderr,
                    "[curl-client] warning! body length mismatch %lu != %lu.\n",
                    (unsigned long)off,
                    (unsigned long)hndl->httpRqt.body.length);
        curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &rcode);
        hndl->httpRqt.status = (int)rcode;
        if ((long)hndl->httpRqt.status != rcode && hndl->verbose)
            fprintf(stderr,
                    "[curl-client] error! status truncated %ld != %ld.\n",
                    rcode, hndl->httpRqt.status);
        curl_easy_getinfo(easy, CURLINFO_CONTENT_TYPE,
                          &hndl->httpRqt.contentType);
    }

    // ensure no NULL texts
    if (hndl->httpRqt.body.buffer == NULL)
        hndl->httpRqt.body.buffer = &nulchar;
    if (hndl->httpRqt.headers.buffer == NULL)
        hndl->httpRqt.headers.buffer = &nulchar;

    // compute request elapsed time
    hndl->httpRqt.msTime =
        (hndl->httpRqt.stopTime.tv_nsec - hndl->httpRqt.startTime.tv_nsec) /
            1000000 +
        (hndl->httpRqt.stopTime.tv_sec - hndl->httpRqt.startTime.tv_sec) * 1000;

    if (hndl->verbose > 2) {
        fprintf(stderr, "[curl-client] done, header: %.*s\n",
                (int)hndl->httpRqt.headers.length,
                hndl->httpRqt.headers.buffer);
        fprintf(stderr, "[curl-client] done, body: %.*s\n",
                (int)hndl->httpRqt.body.length, hndl->httpRqt.body.buffer);
    }
    // call request callback (note: callback should free hndl)

    httpRqtActionT action = hndl->rqtCallback(&hndl->httpRqt);
    if (action == HTTP_HANDLE_FREE)
        freeHttpRqtHndl(hndl);
}

static int multiAction(httpRqtHndlT *hndl, int sock, int action)
{
    int count, running = 0;
    CURLM *multi = hndl->multi;
    CURLMcode status;

    // send the action
    status = curl_multi_socket_action(multi, sock, action, &running);
    if (status != CURLM_OK && hndl->verbose) {
        fprintf(stderr, "[curl-client]: curl_multi_socket_action fail ");
        return -1;
    }
    // read action resulting messages
    for (;;) {
        CURLMsg *msg = curl_multi_info_read(multi, &count);

        if (msg == NULL)
            return 0;

        if (hndl->verbose > 2)
            fprintf(stderr, "[curl-client] multiAction: status=%d \n",
                    msg->msg);

        if (msg->msg == CURLMSG_DONE) {
            CURL *easy = msg->easy_handle;
            CURLcode status = msg->data.result;

            if (hndl->verbose > 2)
                fprintf(stderr, "[curl-client] multiAction: done\n");

            rqtDone(hndl, easy, status);
        }
    }
}

// call from glue evtLoop. Map event name and pass event to curl action loop
int httpOnSocketCB(httpRqtHndlT *hndl, int sock, int action)
{
    if (hndl->verbose > 2)
        fprintf(stderr, "[curl-client] httpOnSocketCB: sock=%d action=%d\n",
                sock, action);
    return multiAction(hndl, sock, action);
}

// called from glue event loop as Curl needs curl_multi_socket_action to be
// called regularly
int httpOnTimerCB(httpRqtHndlT *hndl)
{
    if (hndl->verbose > 2)
        fprintf(stderr, "[curl-client] httpOnTimerCB\n");
    return multiAction(hndl, CURL_SOCKET_TIMEOUT, 0);
}

static void addHeaders(httpRqtHndlT *hndl, const httpKeyValT *headers)
{
    if (headers != NULL) {
        struct curl_slist *lst;
        char buffer[DFLT_HEADER_MAX_LEN];
        for (; headers->tag != NULL; headers++) {
            snprintf(buffer, sizeof buffer, "%s: %s", headers->tag,
                     headers->value);
            lst = curl_slist_append(hndl->headers, buffer);
            if (lst != NULL)
                hndl->headers = lst;  // TODO error report?
        }
    }
}

static int httpSendQuery(httpPoolT *httpPool,
                         const char *url,
                         const httpOptsT *opts,
                         httpKeyValT *headers,
                         void *datas,
                         long datalen,
                         httpRqtCbT rqtCallback,
                         void *ctx,
                         int post)
{
    httpRqtHndlT *hndl = calloc(1, sizeof(httpRqtHndlT));
    int verbose = httpPool ? httpPool->verbose : 1;
    if (hndl == NULL && verbose) {
        fprintf(stderr, "[curl-client] allocation of hndl failed");
        goto OnErrorExit;
    }

    INIT hndl->verbose = verbose;
    hndl->easy = curl_easy_init();
    if (hndl->easy == NULL && verbose) {
        fprintf(stderr, "[curl-client] allocation of easy CURL failed");
        goto OnErrorExit;
    }

    hndl->rqtCallback = rqtCallback;
    hndl->httpRqt.userData = ctx;

    curl_easy_setopt(hndl->easy, CURLOPT_URL, url);
    curl_easy_setopt(hndl->easy, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(hndl->easy, CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt(hndl->easy, CURLOPT_HEADER, 0L);
    curl_easy_setopt(hndl->easy, CURLOPT_WRITEFUNCTION, httpBodyCB);
    curl_easy_setopt(hndl->easy, CURLOPT_HEADERFUNCTION, httpHeadersCB);
    curl_easy_setopt(hndl->easy, CURLOPT_ERRORBUFFER, hndl->error);
    curl_easy_setopt(hndl->easy, CURLOPT_HEADERDATA, hndl);
    curl_easy_setopt(hndl->easy, CURLOPT_WRITEDATA, hndl);
    curl_easy_setopt(hndl->easy, CURLOPT_PRIVATE, hndl);

    addHeaders(hndl, headers);

    if (opts) {
        addHeaders(hndl, opts->headers);

        if (opts->freeCtx)
            hndl->freeCtx = opts->freeCtx;
        if (opts->follow)
            curl_easy_setopt(hndl->easy, CURLOPT_FOLLOWLOCATION, opts->follow);
        if (opts->verbose)
            curl_easy_setopt(hndl->easy, CURLOPT_VERBOSE, opts->verbose);
        if (opts->agent)
            curl_easy_setopt(hndl->easy, CURLOPT_USERAGENT, opts->agent);
        if (opts->timeout)
            curl_easy_setopt(hndl->easy, CURLOPT_TIMEOUT, opts->timeout);
        if (opts->sslchk) {
            curl_easy_setopt(hndl->easy, CURLOPT_SSL_VERIFYPEER, 1L);
            curl_easy_setopt(hndl->easy, CURLOPT_SSL_VERIFYHOST, 1L);
        }
        if (opts->sslcert)
            curl_easy_setopt(hndl->easy, CURLOPT_SSLCERT, opts->sslcert);
        if (opts->sslkey)
            curl_easy_setopt(hndl->easy, CURLOPT_SSLKEY, opts->sslkey);
        if (opts->maxsz)
            curl_easy_setopt(hndl->easy, CURLOPT_MAXFILESIZE, opts->maxsz);
        if (opts->speedlow)
            curl_easy_setopt(hndl->easy, CURLOPT_LOW_SPEED_TIME,
                             opts->speedlow);
        if (opts->speedlimit)
            curl_easy_setopt(hndl->easy, CURLOPT_LOW_SPEED_LIMIT,
                             opts->speedlimit);
        if (opts->maxredir)
            curl_easy_setopt(hndl->easy, CURLOPT_MAXREDIRS, opts->maxredir);
        if (opts->username)
            curl_easy_setopt(hndl->easy, CURLOPT_USERNAME, opts->username);
        if (opts->password)
            curl_easy_setopt(hndl->easy, CURLOPT_PASSWORD, opts->password);
    }
    // raw post
    if (post) {
        curl_easy_setopt(hndl->easy, CURLOPT_POST, 1L);
        curl_easy_setopt(hndl->easy, CURLOPT_POSTFIELDSIZE, datalen);
        curl_easy_setopt(hndl->easy, CURLOPT_POSTFIELDS, datas);
    }
    // add headers
    if (hndl->headers)
        curl_easy_setopt(hndl->easy, CURLOPT_HTTPHEADER, hndl->headers);

    // init time tracker
    clock_gettime(CLOCK_MONOTONIC, &hndl->httpRqt.startTime);

    if (httpPool != NULL) {
        hndl->httpPool = httpPool;
        hndl->multi = curl_multi_init();
    }
    if (hndl->multi) {
        hndl->evtCallback = httpPool->evtCallback;
        curl_multi_add_handle(hndl->multi, hndl->easy);
        curl_multi_setopt(hndl->multi, CURLMOPT_SOCKETFUNCTION, multiSetSockCB);
        curl_multi_setopt(hndl->multi, CURLMOPT_TIMERFUNCTION, multiSetTimerCB);
        curl_multi_setopt(hndl->multi, CURLMOPT_SOCKETDATA, hndl);
        curl_multi_setopt(hndl->multi, CURLMOPT_TIMERDATA, hndl);
        multiAction(hndl, CURL_SOCKET_TIMEOUT, 0);
    }
    else {
        CURLcode status = curl_easy_perform(hndl->easy);
        rqtDone(hndl, hndl->easy, status);
    }
    return 0;

OnErrorExit:
    freeHttpRqtHndl(hndl);
    return 1;
}

int httpSendPost(httpPoolT *httpPool,
                 const char *url,
                 const httpOptsT *opts,
                 httpKeyValT *headers,
                 void *datas,
                 long len,
                 httpRqtCbT rqtCallback,
                 void *ctx)
{
    return httpSendQuery(httpPool, url, opts, headers, datas, len, rqtCallback,
                         ctx, 1);
}

int httpSendGet(httpPoolT *httpPool,
                const char *url,
                const httpOptsT *opts,
                httpKeyValT *headers,
                httpRqtCbT rqtCallback,
                void *ctx)
{
    return httpSendQuery(httpPool, url, opts, headers, NULL, 0, rqtCallback,
                         ctx, 0);
}

// Create CURL multi httpPool and attach it to systemd evtLoop
httpPoolT *httpCreatePool(void *evtLoop,
                          const httpCallbacksT *mainLoopCbs,
                          int verbose)
{
    httpPoolT *httpPool;

    INIT
        // create the object
        httpPool = calloc(1, sizeof(httpPoolT));
    if (httpPool != NULL) {
        httpPool->verbose = verbose;
        httpPool->evtLoop = evtLoop;
        httpPool->evtCallback = mainLoopCbs;
        if (verbose > 1)
            fprintf(stderr, "[curl-client] pool created\n");
    }
    return httpPool;
}
