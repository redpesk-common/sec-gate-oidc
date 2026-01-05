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
 */

#pragma once

#include "oidc-idp.h"

struct idpPluginS {
    const char* uid;
    const char* info;
    int (*registerConfig)(oidcIdpT* idp, json_object* idpJ);
    int (*registerVerbs)(const oidcIdpT* idp, struct afb_api_v4* sgApi);
    int (*registerApis)(const oidcIdpT* idp,
                        struct afb_apiset* declare_set,
                        struct afb_apiset* call_set);
    int (*registerAlias)(const oidcIdpT* idp, struct afb_hsrv* hsrv);
    void (*resetSession)(const oidcProfileT* idpProfile, void* ctx);
    void* ctx;
};

// idp callback definition
typedef int (*oidcPluginInitCbT)(const oidcCoreHdlT* oidc);

const idpPluginT* idpPluginFind(const char* type);
int idpPluginRegister(const idpPluginT* plugin);
int idpPluginParseOne(const oidcCoreHdlT* oidc, json_object* pluginJ);
int idpPluginsParseConfig(const oidcCoreHdlT* oidc, json_object* pluginsJ);
