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

#include <json-c/json.h>

typedef struct oidcAliasesS oidcAliasT;
typedef struct oidcApisS oidcApisT;
typedef struct oidcIdpS oidcIdpT;
typedef struct httpPoolS httpPoolT;
typedef struct idpPluginS idpPluginT;

typedef struct oidGlobalsS oidGlobalsT;
typedef struct oidcCoreHdlS oidcCoreHdlT;

struct oidGlobalsS
{
    const char *loginUrl;
    const char *errorUrl;
    const char *registerUrl;
    const char *fedlinkUrl;
    const char *homeUrl;
    unsigned long tCache;
    unsigned long sTimeout;
    int debug;
};

const char *oidcCoreUID(const oidcCoreHdlT *oidc);
const oidGlobalsT *oidcCoreGlobals(const oidcCoreHdlT *oidc);
afb_api_v4 *oidcCoreAfbApi(const oidcCoreHdlT *oidc);
httpPoolT *oidcCoreHTTPPool(const oidcCoreHdlT *oidc);

int oidcCoreParseConfig(oidcCoreHdlT **poidc, struct json_object *oidcJ, char const *uid);
int oidcCoreDeclareApis(oidcCoreHdlT *oidc, struct afb_apiset *declare_set, struct afb_apiset *call_set);
int oidcCoreDeclareHTTP(oidcCoreHdlT *oidc, afb_hsrv *hsrv);

json_object *oidcCoreGetProfilsForLOA(const oidcCoreHdlT *oidc,
                              int loa,
                              const char **idps,
                              int noslave);

int oidcCoreGetFilteredIdpList(const oidcCoreHdlT *oidc,
                               const char **dest,
                               int nrDest,
                               const char *excludedUID);

int oidcCoreRedirectLogin(const oidcCoreHdlT *oidc,
                          afb_hreq *hreq);
