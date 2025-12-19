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

#include "oidc-core.h"

#include <stdio.h>
#include <stdlib.h>

#include <json-c/json.h>
#include <rp-utils/rp-jsonc.h>

#include <libafb/afb-extension.h>
#include <libafb/afb-v4.h>
#include <libafb/apis/afb-api-ws.h>

#include "curl-glue.h"
#include "oidc-alias.h"
#include "oidc-apis.h"
#include "oidc-builtin-idps.h"
#include "oidc-defaults.h"
#include "oidc-idp.h"
#include "oidc-idsvc.h"

AFB_EXTENSION("sec-gate-oidc")

// Parse and load config.json info oidc global context
int AfbExtensionConfigV1(void **ctx,
                         struct json_object *config,
                         char const *uid)
{
    int rc;
    oidcCoreHdlT *oidc = NULL;

    EXT_INFO("Extension %s got to config", AfbExtensionManifest.name);

    rc = registerBuiltinIdps();
    if (rc >= 0)
        rc = oidcCoreParseConfig(&oidc, config, AfbExtensionManifest.name);
    *ctx = oidc;
    return rc;
}

// Declares the apis
int AfbExtensionDeclareV1(void *ctx,
                          struct afb_apiset *declare_set,
                          struct afb_apiset *call_set)
{
    oidcCoreHdlT *oidc = (oidcCoreHdlT *)ctx;
    const char *apiName, *fedidUri;
    afb_api_v4 *apiv4;
    int rc = 0;

    EXT_INFO("Extension %s got to declare", AfbExtensionManifest.name);

    // TODO: asking oidcCore for inputs is not verry good,
    // TODO: also, internals of oidcCore are depending on fedid stuff
    // TODO: so situation should be made cleaner.
    // TODO: A way is:
    // TODO:  1. split config read into main and oidc core
    // TODO:  2. add an extension object
    // TODO:  3. setup fedid in main extension
    // TODO:  4. deliver fedid to oidcCore
    // TODO: But federation is a specific topic that should I think
    // TODO: be separated from oidcCore that should focus on authorization

    // import/connect to fedid API
    fedidUri = oidcCoreFedIdURI(oidc);
    if (fedidUri != NULL)
        rc = afb_api_ws_add_client(fedidUri, declare_set, call_set, 1);
    // declare internal identity service api
    if (rc >= 0) {
        apiName = oidcCoreAfbApiName(oidc);
        rc = idsvcDeclareApi(&apiv4, apiName, oidc, declare_set, call_set);
        if (rc >= 0)
            oidcCoreSetAfbApi(oidc, apiv4);
    }
    // declare other services
    if (rc >= 0)
        rc = oidcCoreDeclareApis(oidc, declare_set, call_set);

    return rc;
}

// Declare HTTP hooks
int AfbExtensionHTTPV1(void *ctx, afb_hsrv *hsrv)
{
    oidcCoreHdlT *oidc = (oidcCoreHdlT *)ctx;

    EXT_NOTICE("Extension %s got to http", AfbExtensionManifest.name);

    return oidcCoreDeclareHTTP(oidc, hsrv);
}
