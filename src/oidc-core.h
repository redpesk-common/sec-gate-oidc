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

#pragma once

#include "oidc-common.h"

typedef struct oidcAliasesS oidcAliasT;
typedef struct oidcApisS oidcApisT;
typedef struct oidcIdpS oidcIdpT;
typedef struct httpPoolS httpPoolT;
typedef struct idpPluginS idpPluginT;

#define MAGIC_OIDC_MAIN         321987
#define MAGIC_OIDC_SESSION(VAR) void *VAR = &VAR

#define URL_OIDC_USR_ERROR    "/sgate/common/error.html"
#define URL_OIDC_USR_LOGIN    "/sgate/common/login.html"
#define URL_OIDC_USR_REGISTER "/sgate/common/register.html"
#define URL_OIDC_USR_FEDLINK  "/sgate/common/fedlink.html"
#define URL_OIDC_USR_HOME     "/"
#define URL_OIDC_AUTH_CACHE   5000  // 5sec alias authen cache
#define MAX_OIDC_IDPS         16    // max number of IDPS in config

#define STATUS_OIDC_AUTH_DENY 403
#define STATUS_OIDC_LOA_RESET 423

typedef struct
{
    const char *loginUrl;
    const char *errorUrl;
    const char *registerUrl;
    const char *fedlinkUrl;
    const char *homeUrl;
    unsigned long tCache;
    unsigned long sTimeout;
    int debug;
} oidGlobalsT;

// this structure is returned by plugin registration callback
typedef struct
{
    long magic;
    const char *uid;
    const char *info;
    const char *api;
    int verbose;
    oidcAliasT *aliases;
    oidcApisT *apis;
    oidcIdpT *idps;
    httpPoolT *httpPool;
    const char *fedapi;
    oidcApisT *apisHash;
    afb_api_v4 *apiv4;
    oidGlobalsT *globals;
} oidcCoreHdlT;
