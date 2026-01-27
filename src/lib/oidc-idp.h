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

#include <fedid-types.h>
#include <json-c/json.h>
#include <libafb/afb-v4.h>

#include "curl-glue.h"
#include "oidc-core.h"
#include "oidc-defaults.h"

typedef struct oidcIdpS oidcIdpT;
typedef struct idpPluginS idpPluginT;

typedef enum {
    IDP_CLIENT_SECRET_UNKNOWN = 0,
    IDP_CLIENT_SECRET_POST,
    IDP_CLIENT_SECRET_BASIC,
    IDP_CLIENT_SECRET_JWT,
    IDP_PRIVATE_KEY_JWT
} oidcAuthMethodT;

typedef enum {
    IDP_RESPOND_TYPE_UNKNOWN = 0,
    IDP_RESPOND_TYPE_CODE,
    IDP_RESPOND_TYPE_ID_TOKEN,
    IDP_RESPOND_TYPE_ID_TOKEN_TOKEN,
} oidcRespondTypeT;

typedef struct oidcWellknownS {
    const char* discovery;
    const char* tokenid;
    const char* authorize;
    const char* userinfo;
    const char* jwks;
    oidcAuthMethodT authMethod;
    oidcRespondTypeT respondType;
    const char* respondLabel;
    const char* authLabel;
    const char* errorLabel;
    int lazy;
} oidcWellknownT;

typedef struct oidcCredentialsS {
    int timeout;  // connection timeout to authority in seconds
    const char* clientId;
    const char* secret;
} oidcCredentialsT;

typedef struct oidcProfileS {
    const char* uid;
    const char* info;
    const char* scope;
    const char* attrs;
    int loa;
    int group;
    int slave;
    unsigned long tCache;
    unsigned long sTimeout;
    oidcIdpT* idp;
} oidcProfileT;

typedef struct oidcStaticsS {
    int loa;
    ulong sTimeout;
    const char* aliasLogo;
    const char* aliasLogin;
    const char* aliasLogout;
} oidcStaticsT;

struct oidcIdpS {
    int magic;
    const char* uid;
    const char* info;
    const char* type;
    const oidcCredentialsT* credentials;
    const oidcWellknownT* wellknown;
    const httpKeyValT* headers;
    const oidcProfileT* scopes;
    const oidcStaticsT* statics;
    const oidcProfileT* profiles;
    void* ctx;
    const idpPluginT* plugin;
    const oidcCoreHdlT* oidc;
    void* userData;
};

typedef struct oidcDefaultsS {
    const oidcCredentialsT* credentials;
    const oidcStaticsT* statics;
    const oidcWellknownT* wellknown;
    const oidcProfileT* profiles;
    const httpKeyValT* headers;
} oidcDefaultsT;

// idp exported functions
const oidcProfileT* idpGetFirstProfile(const oidcIdpT* idp,
                                       int targetLOA,
                                       const char* scope);

int idpPluginsParseConfig(const oidcCoreHdlT* oidc, json_object* pluginsJ);
oidcIdpT* idpParseConfig(const oidcCoreHdlT* oidc, json_object* idpsJ);
int idpParseOidcConfig(oidcIdpT* idp,
                       json_object* configJ,
                       oidcDefaultsT* defaults,
                       void* ctx);
int idpRegisterVerbs(const oidcCoreHdlT* oidc,
                     const oidcIdpT* idp,
                     struct afb_api_v4* sgApi);
int idpRegisterApis(const oidcCoreHdlT* oidc,
                    const oidcIdpT* idp,
                    struct afb_apiset* declare_set,
                    struct afb_apiset* call_set);
int idpRegisterAlias(const oidcCoreHdlT* oidc,
                     const oidcIdpT* idp,
                     struct afb_hsrv* hsrv);

int idpPluginRegister(const idpPluginT* pluginCbs);

/** make an oidcState for the given idp, target LOA and scope
 *
 * @param idp       the IDP
 * @param targetLOA the targeted LOA
 * @param scope     a required scope (can be NULL)
 * @param session   the session to be bound
 * @param state     pointer for storing created state
 *
 * @return 1 if ok, 0 if no profile foun, -1 when out of memory
 */
int idpMakeState(const oidcIdpT *idp,
                        int targetLOA,
                        const char *scope,
                        oidcSessionT *session,
                        oidcStateT **state);

int idpStdRedirectLogin(const oidcIdpT* idp, struct afb_hreq* hreq);

int idpRedirectLogin(const oidcIdpT* idp,
                     struct afb_hreq* hreq,
                     oidcSessionT* session,
                     const char* destPath,
                     const char* redirPath,
                     const char* clientId,
                     const char* responseType,
                     const char* nonce);

typedef int (*idpOnLoginRedirCB)(struct afb_hreq* hreq,
                                 const oidcIdpT* idp,
                                 oidcSessionT* session,
                                 oidcStateT* state);

int idpOnLoginPage(struct afb_hreq* hreq,
                   const oidcIdpT* idp,
                   idpOnLoginRedirCB onRedirCB,
                   const char* destPath,
                   const char* redirPath,
                   const char* clientId,
                   const char* responseType,
                   const char* nonce);

int idpOnLoginRequest(const oidcIdpT* idp,
                      struct afb_req_v4* wreq,
                      int targetLOA,
                      const char* scope,
                      oidcSessionT** session,
                      oidcStateT** state);
