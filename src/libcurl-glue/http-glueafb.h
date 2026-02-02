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

#include "curl-glue.h"

// glue proto to get mainloop callbacks
const httpCallbacksT* httpGlueAfbGetCbs(void);

