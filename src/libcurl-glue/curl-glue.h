/*
 * Copyright (C) 2021-2026 IoT.bzh Company
 * Author: "Fulup Ar Foll" <fulup@iot.bzh>
 * Author: <jose.bollo@iot.bzh>
 * Author: <dev-team@iot.bzh>
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT. $RP_END_LICENSE$
 *
 * Examples:
 *  GET  httpSendGet(oidc->httpPool, "https://example.com", idp->headers,
 * NULL|token, NULL|opts, callback, ctx); POST httpSendPost(oidc->httpPool, url,
 * idp->headers, NULL|token, NULL|opts, (void*)post,datalen, callback, ctx);
 */

#pragma once

#include <curl/curl.h>
#include <stdint.h>
#include <sys/types.h>

#define DFLT_HEADER_MAX_LEN 1024
#define HTTP_DFLT_AGENT     "sec-gate-oidc/1.0"

typedef struct httpPoolS httpPoolT;

typedef enum {
    HTTP_HANDLE_FREE,
    HTTP_HANDLE_KEEP,
} httpRqtActionT;

typedef struct
{
    const char *tag;
    const char *value;
} httpKeyValT;

typedef void (*httpFreeCtxCbT)(void *userData);

// curl options
typedef struct
{
    const char *username;
    const char *password;
    const char *bearer;
    long timeout;
    const long sslchk;
    const long verbose;
    const long maxsz;
    const long speedlimit;
    const long speedlow;
    const long follow;
    const long maxredir;
    const char *proxy;
    const char *cainfo;
    const char *sslcert;
    const char *sslkey;
    const char *tostr;
    const char *agent;
    const httpKeyValT *headers;
    const httpFreeCtxCbT freeCtx;
} httpOptsT;

// buffers
typedef struct httpBufferS
{
    size_t length;
    char *buffer;
} httpBufferT;

// http request handle
typedef struct httpRqtS
{
    int status;
    char *contentType;
    httpBufferT headers;
    httpBufferT body;
    struct timespec startTime;
    struct timespec stopTime;
    uint64_t msTime;
    void *userData;
} httpRqtT;

typedef struct httpRqtHndlS httpRqtHndlT;
typedef httpRqtActionT (*httpRqtCbT)(httpRqtT *httpRqt);

// mainloop glue API interface
typedef void *(*evtMainLoopCbT)();
typedef int (*multiTimerCbT)(httpRqtHndlT *httpRqtHndl,
                             long timeout,
                             void **timedata);
typedef int (*multiSocketCbT)(httpRqtHndlT *httpRqtHndl,
                              int sock,
                              int action,
                              void **sockdata);
typedef int (*evtRunLoopCbT)(httpRqtHndlT *httpRqtHndl, long seconds);

// glue callbacks handle
typedef struct
{
    evtMainLoopCbT evtMainLoop;
    evtRunLoopCbT evtRunLoop;
    multiTimerCbT multiTimer;
    multiSocketCbT multiSocket;
} httpCallbacksT;

// glue proto to get mainloop callbacks
const httpCallbacksT *glueGetCbs(void);

// API to build and lauch request (if httpPoolT==NULL then run synchronously)
int httpSendPost(httpPoolT *pool,
                 const char *url,
                 const httpOptsT *opts,
                 httpKeyValT *tokens,
                 void *databuf,
                 long datalen,
                 httpRqtCbT callback,
                 void *ctx);
int httpSendGet(httpPoolT *pool,
                const char *url,
                const httpOptsT *opts,
                httpKeyValT *tokens,
                httpRqtCbT callback,
                void *ctx);

// init curl multi pool with an abstract mainloop and corresponding callbacks
httpPoolT *httpCreatePool(void *evtLoop,
                          const httpCallbacksT *mainLoopCbs,
                          int verbose);

// curl action callback to be called from glue layer
int httpOnSocketCB(httpRqtHndlT *httpRqtHndl, int sock, int action);
int httpOnTimerCB(httpRqtHndlT *httpRqtHndl);
