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
    EXT_INFO("Extension %s got to config", AfbExtensionManifest.name);

    return oidcCoreParseConfig((oidcCoreHdlT **)ctx, config,
                               AfbExtensionManifest.name);
}

// Declares the apis
int AfbExtensionDeclareV1(void *ctx,
                          struct afb_apiset *declare_set,
                          struct afb_apiset *call_set)
{
    oidcCoreHdlT *oidc = (oidcCoreHdlT *)ctx;

    EXT_INFO("Extension %s got to declare", AfbExtensionManifest.name);

    return oidcCoreDeclareApis(oidc, declare_set, call_set);
}

// Declare HTTP hooks
int AfbExtensionHTTPV1(void *ctx, afb_hsrv *hsrv)
{
    oidcCoreHdlT *oidc = (oidcCoreHdlT *)ctx;

    EXT_NOTICE("Extension %s got to http", AfbExtensionManifest.name);

    return oidcCoreDeclareHTTP(oidc, hsrv);
}
