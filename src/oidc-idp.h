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

#include <fedid-types.h>
#include <json-c/json.h>
#include <libafb/afb-v4.h>

#include "curl-glue.h"
#include "oidc-core.h"
#include "oidc-defaults.h"

typedef struct oidcIdpS oidcIdpT;

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

typedef struct
{
    const char *discovery;
    const char *tokenid;
    const char *authorize;
    const char *userinfo;
    const char *jwks;
    oidcAuthMethodT authMethod;
    oidcRespondTypeT respondType;
    const char *respondLabel;
    const char *authLabel;
    const char *errorLabel;
    int lazy;
} oidcWellknownT;

typedef struct
{
    int timeout;  // connection timeout to authority in seconds
    const char *clientId;
    const char *secret;
} oidcCredentialsT;

typedef struct oidcProfileS
{
    const char *uid;
    const char *info;
    const char *scope;
    const char *attrs;
    int loa;
    int group;
    int slave;
    unsigned long tCache;
    unsigned long sTimeout;
    oidcIdpT *idp;
} oidcProfileT;

typedef struct oidcStaticsS
{
    int loa;
    ulong sTimeout;
    const char *aliasLogo;
    const char *aliasLogin;
    const char *aliasLogout;
} oidcStaticsT;

typedef struct oidcIdpS
{
    int magic;
    const char *uid;
    const char *info;
    const char *type;
    const oidcCredentialsT *credentials;
    const oidcWellknownT *wellknown;
    const httpKeyValT *headers;
    const oidcProfileT *scopes;
    const oidcStaticsT *statics;
    const oidcProfileT *profiles;
    void *ctx;
    const idpPluginT *plugin;
    oidcCoreHdlT *oidc;
    void *userData;
} oidcIdpT;

typedef struct
{
    const oidcCredentialsT *credentials;
    const oidcStaticsT *statics;
    const oidcWellknownT *wellknown;
    const oidcProfileT *profiles;
    const httpKeyValT *headers;
} oidcDefaultsT;

// request handle store federation attribute during multiple IDP async calls
typedef struct
{
    int ucount;
    const char *uuid;
    oidcIdpT *idp;
    afb_hreq *hreq;
    struct afb_req_v4 *wreq;
    fedSocialRawT *fedSocial;
    fedUserRawT *fedUser;
    const oidcProfileT *profile;
    char *token;
    void *userData;
} idpRqtCtxT;

// generic IDP utility callback
typedef struct idpGenericCbS
{
    const oidcMagicT magic;
    const oidcCredentialsT *(*parseCredentials)(
        oidcIdpT *idp,
        json_object *credentialJ,
        const oidcCredentialsT *defaults);
    const oidcStaticsT *(*parsestatic)(oidcIdpT *idp,
                                       json_object *staticJ,
                                       const oidcStaticsT *defaults);
    const oidcWellknownT *(*parseWellknown)(oidcIdpT *idp,
                                            json_object *wellknownJ,
                                            const oidcWellknownT *defaults);
    const httpKeyValT *(*parseHeaders)(oidcIdpT *idp,
                                       json_object *headersJ,
                                       const httpKeyValT *defaults);
    int (*parseConfig)(oidcIdpT *idp,
                       json_object *configJ,
                       oidcDefaultsT *defaults,
                       void *ctx);
    int (*fedidCheck)(idpRqtCtxT *idpRqtCtx);
    int (*pluginRegister)(const char *pluginUid, idpPluginT *pluginCbs);
} idpGenericCbT;

typedef struct idpPluginS
{
    const char *uid;
    const char *info;
    int (*registerConfig)(oidcIdpT *idp, json_object *idpJ);
    int (*registerApis)(oidcIdpT *idp,
                        struct afb_apiset *declare_set,
                        struct afb_apiset *call_set);
    int (*registerAlias)(oidcIdpT *idp, afb_hsrv *hsrv);
    void (*resetSession)(const oidcProfileT *idpProfile, void *ctx);
    void *ctx;
} idpPluginT;

// idp callback definition
typedef int (*oidcPluginInitCbT)(oidcCoreHdlT *oidc,
                                 idpGenericCbT *idpGenericCb);

// idp exported functions
const oidcIdpT *idpParseConfig(oidcCoreHdlT *oidc, json_object *idpsJ);
int idpParseOidcConfig(oidcIdpT *idp,
                       json_object *configJ,
                       oidcDefaultsT *defaults,
                       void *ctx);
int idpRegisterApis(oidcCoreHdlT *oidc,
                    oidcIdpT *idp,
                    struct afb_apiset *declare_set,
                    struct afb_apiset *call_set);
int idpRegisterAlias(oidcCoreHdlT *oidc, oidcIdpT *idp, afb_hsrv *hsrv);
json_object *idpLoaProfilsGet(oidcCoreHdlT *oidc,
                              int loa,
                              const char **idps,
                              int noslave);
int idpRegisterPlugin(const char *pluginUid, idpPluginT *pluginCbs);
int idpPLuginRegistryInit(void);
void idpRqtCtxFree(idpRqtCtxT *rqtCtx);
