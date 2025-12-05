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

#include <assert.h>
#include <dlfcn.h>
#include <string.h>

#include <rp-utils/rp-jsonc.h>

#include <libafb/afb-core.h>
#include <libafb/afb-http.h>
#include <libafb/afb-v4.h>

#include "oidc-core.h"
#include "oidc-fedid.h"
#include "oidc-idp.h"
#include "oidc-utils.h"

typedef struct idpRegistryS
{
    struct idpRegistryS *next;
    const char *uid;
    idpPluginT *plugin;
} idpRegistryT;

// registry holds a linked list of core+pugins idps
static idpRegistryT *registryHead = NULL;

const nsKeyEnumT idpAuthMethods[] = {
    {"secret-unknown", IDP_CLIENT_SECRET_UNKNOWN},
    {"client_secret_post", IDP_CLIENT_SECRET_POST},
    {"client_secret_basic", IDP_CLIENT_SECRET_BASIC},
    // {"client_secret_jwt", IDP_CLIENT_SECRET_JWT}, not implemented
    // {"private_key_jwt", IDP_PRIVATE_KEY_JWT}, not implemented
    {NULL}  // terminator
};

const nsKeyEnumT idpRespondTypes[] = {
    {"respond-type-unknown", IDP_RESPOND_TYPE_UNKNOWN},
    {"code", IDP_RESPOND_TYPE_CODE},
    // {"id_token", IDP_RESPOND_TYPE_ID_TOKEN}, // hybrid mode
    // {"id_token token"  , IDP_RESPOND_TYPE_ID_TOKEN_TOKEN}, // hybrid mode
    {NULL}  // terminator
};

void idpRqtCtxFree(idpRqtCtxT *rqtCtx)
{
    assert(rqtCtx->ucount >= 0);
    rqtCtx->ucount--;

    if (rqtCtx->ucount < 0) {
        if (rqtCtx->token)
            free(rqtCtx->token);
        free(rqtCtx);
    }
}

// return the idp list to display corresponding login page.
json_object *idpLoaProfilsGet(oidcCoreHdlT *oidc,
                              int loa,
                              const char **idps,
                              int noslave)
{
    json_object *idpsJ = json_object_new_array();
    const oidcIdpT *idp = oidc->idps;
    for (; idp->uid; idp++) {
        json_object *profilesJ = NULL;
        const oidcProfileT *prof = idp->profiles;
        // search for requested LOA within idp existing profile
        for (; prof->uid; prof++) {
            // if loa does not fit ignore IDP
            if (prof->loa < loa && prof->loa != abs(loa))
                continue;
            if (noslave && prof->slave)
                continue;

            // idp is not within idps list excluse it from list
            if (idps) {
                const char **iter = idps;
                for (; *iter; iter++) {
                    if (!strcasecmp(*iter, idp->uid))
                        break;
                }
                if (!*iter)
                    continue;
            }

            json_object *profileJ;
            if (!profilesJ)
                profilesJ = json_object_new_array();
            rp_jsonc_pack(&profileJ, "{ss ss* ss si}", "uid", prof->uid, "info",
                          prof->info, "scope", prof->scope, "loa", prof->loa);
            json_object_array_add(profilesJ, profileJ);
        }

        // only return IDP with a corresponding loa/scope
        if (profilesJ) {
            json_object *idpJ;
            rp_jsonc_pack(&idpJ, "{ss ss* ss* ss* ss* so}", "uid", idp->uid,
                          "info", idp->info, "logo", idp->statics->aliasLogo,
                          "client-id", idp->credentials->clientId, "login-url",
                          idp->statics->aliasLogin, "profiles", profilesJ);

            json_object_array_add(idpsJ, idpJ);
        }
    }
    return idpsJ;
}

// add a new plugin idp to the registry
int idpRegisterPlugin(const char *pluginUid, idpPluginT *pluginCbs)
{
    idpRegistryT *registryIdx, *registryEntry;

    // create holding hat for idp/decoder CB
    registryEntry = (idpRegistryT *)calloc(1, sizeof(idpRegistryT));
    registryEntry->uid = pluginUid;
    registryEntry->plugin = pluginCbs;

    // if not 1st idp insert at the end of the chain
    if (!registryHead) {
        registryHead = registryEntry;
    }
    else {
        for (registryIdx = registryHead; registryIdx->next;
             registryIdx = registryIdx->next)
            ;
        registryIdx->next = registryEntry;
    }

    return 0;
}

static const oidcCredentialsT *idpParseCredentials(
    oidcIdpT *idp,
    json_object *credentialsJ,
    const oidcCredentialsT *defaults)
{
    oidcCredentialsT *credentials = calloc(1, sizeof(oidcCredentialsT));
    if (defaults)
        memcpy(credentials, defaults, sizeof(oidcCredentialsT));

    if (credentialsJ) {
        int err = rp_jsonc_unpack(credentialsJ, "{ss,ss}", "clientid",
                                  &credentials->clientId, "secret",
                                  &credentials->secret);
        if (err) {
            EXT_CRITICAL(
                "idp=%s parsing fail 'credentials' should define "
                "'clientid','secret' (idpParseCredentials)",
                idp->uid);
            goto OnErrorExit;
        }
    }
    return credentials;

OnErrorExit:
    free(credentials);
    return NULL;
}

static int idpParseOneHeader(oidcIdpT *idp,
                             json_object *headerJ,
                             httpKeyValT *header)
{
    int err = rp_jsonc_unpack(headerJ, "{ss,ss}", "tag", &header->tag, "value",
                              &header->value);
    if (err) {
        EXT_CRITICAL(
            "[idp-header-error] idp=%s parsing fail profile expect: tag,value "
            "(idpParseOneHeader)",
            idp->uid);
        goto OnErrorExit;
    }
    return 0;

OnErrorExit:
    return 1;
}

static const httpKeyValT *idpParseHeaders(oidcIdpT *idp,
                                          json_object *headersJ,
                                          const httpKeyValT *defaults)
{
    if (!headersJ)
        return defaults;

    httpKeyValT *headers;
    int err;

    switch (json_object_get_type(headersJ)) {
        int count;

    case json_type_array:
        count = (int)json_object_array_length(headersJ);
        headers = calloc(count + 1, sizeof(httpKeyValT));

        for (int idx = 0; idx < count; idx++) {
            json_object *headerJ = json_object_array_get_idx(headersJ, idx);
            err = idpParseOneHeader(idp, headerJ, &headers[idx]);
            if (err)
                goto OnErrorExit;
        }
        break;

    case json_type_object:
        headers = calloc(2, sizeof(httpKeyValT));
        err = idpParseOneHeader(idp, headersJ, &headers[0]);
        if (err)
            goto OnErrorExit;
        break;

    default:
        EXT_CRITICAL(
            "[idp-headers-error] idp=%s should be json_array|json_object "
            "(idpParseHeaders)",
            idp->uid);
        goto OnErrorExit;
    }
    return headers;

OnErrorExit:
    return NULL;
}

static int idpParseOneProfil(oidcIdpT *idp,
                             json_object *profileJ,
                             oidcProfileT *profile)
{
    profile->sTimeout = idp->statics->sTimeout;
    profile->idp = idp;
    int err = rp_jsonc_unpack(
        profileJ, "{ss,s?s,si,ss,s?s,s?i,s?b,s?i !}", "uid", &profile->uid,
        "info", &profile->info, "loa", &profile->loa, "scope", &profile->scope,
        "attrs", &profile->attrs, "group", &profile->group, "slave",
        &profile->slave, "timeout", &profile->sTimeout);
    if (err) {
        EXT_CRITICAL(
            "[idp-profile-error] idp=%s parsing fail expect: "
            "uid,loa,scope,label[s],timeout (idpParseOneProfil)",
            idp->uid);
        goto OnErrorExit;
    }
    return 0;

OnErrorExit:
    return 1;
}

static const oidcProfileT *idpParseProfils(oidcIdpT *idp,
                                           json_object *profilesJ,
                                           const oidcProfileT *defaults)
{
    oidcProfileT *profile = NULL;
    int err;

    // no config use defaults
    if (!profilesJ)
        return defaults;

    switch (json_object_get_type(profilesJ)) {
        int count;

    case json_type_array:
        count = (int)json_object_array_length(profilesJ);
        profile = calloc(count + 1, sizeof(oidcProfileT));

        for (int idx = 0; idx < count; idx++) {
            json_object *profileJ = json_object_array_get_idx(profilesJ, idx);
            err = idpParseOneProfil(idp, profileJ, &profile[idx]);
            if (err)
                goto OnErrorExit;
        }
        break;

    case json_type_object:
        profile = calloc(2, sizeof(oidcProfileT));
        err = idpParseOneProfil(idp, profilesJ, &profile[0]);
        if (err)
            goto OnErrorExit;
        break;

    default:
        EXT_CRITICAL(
            "[idp-profile-error] idp=%s should be json_array|json_object",
            idp->uid);
        goto OnErrorExit;
    }
    return (profile);

OnErrorExit:
    free(profile);
    return NULL;
}

static const oidcStaticsT *idpParsestatic(oidcIdpT *idp,
                                          json_object *staticJ,
                                          const oidcStaticsT *defaults)
{
    // no config use defaults
    if (!staticJ)
        return defaults;

    oidcStaticsT *statics = calloc(1, sizeof(oidcStaticsT));
    if (defaults)
        memcpy(statics, defaults, sizeof(oidcStaticsT));
    if (!statics->sTimeout)
        statics->sTimeout = idp->oidc->globals.sTimeout;

    int err = rp_jsonc_unpack(
        staticJ, "{s?s,s?s,s?s,s?i}", "login", &statics->aliasLogin, "logout",
        &statics->aliasLogout, "logo", &statics->aliasLogo, "timeout",
        &statics->sTimeout);
    if (err) {
        EXT_CRITICAL(
            "[idp-static-error] idp=%s parsing fail statics expect: "
            "login,logo,plugin,timeout (idpParsestatic)",
            idp->uid);
        goto OnErrorExit;
    }

    return (statics);

OnErrorExit:
    free(statics);
    return NULL;
}

static const oidcWellknownT *idpParseWellknown(oidcIdpT *idp,
                                               json_object *wellknownJ,
                                               const oidcWellknownT *defaults)
{
    // no config use default;
    if (!wellknownJ)
        return defaults;

    const char *authMethod = NULL;

    oidcWellknownT *wellknown = calloc(1, sizeof(oidcWellknownT));
    if (defaults)
        memcpy(wellknown, defaults, sizeof(oidcWellknownT));

    int err = rp_jsonc_unpack(
        wellknownJ, "{s?b,s?s,s?s,s?s,s?s,s?s,s?s,s?s !}", "lazy",
        &wellknown->lazy, "discovery", &wellknown->discovery, "tokenid",
        &wellknown->tokenid, "authorize", &wellknown->authorize, "userinfo",
        &wellknown->userinfo, "jwks", &wellknown->jwks, "authent",
        &wellknown->authLabel, "respond", &wellknown->respondLabel);
    if (err) {
        EXT_CRITICAL(
            "github parsing fail wellknown expect: "
            "laszy,discovery,tokenid,authorize,userinfo,authent,respond "
            "(idpParseWellknown)");
        goto OnErrorExit;
    }

    return (wellknown);

OnErrorExit:
    free(wellknown);
    return NULL;
}

int idpParseOidcConfig(oidcIdpT *idp,
                       json_object *configJ,
                       oidcDefaultsT *defaults,
                       void *ctx)
{
    json_object *schemaJ;
    if (!configJ) {
        EXT_CRITICAL(
            "ext=%s github config must define client->id & client->secret "
            "(githubRegisterConfig)",
            idp->uid);
        goto OnErrorExit;
    }
    // unpack main IDP config
    json_object *credentialsJ = NULL, *staticJ = NULL, *wellknownJ = NULL,
                *headersJ = NULL, *profilesJ, *pluginJ = NULL;
    int err = rp_jsonc_unpack(
        configJ, "{ss s?s s?s s?o s?o s?o s?o s?o s?o s?o !}", "uid", &idp->uid,
        "info", &idp->info, "type", &idp->type, "plugin", &pluginJ,
        "credentials", &credentialsJ, "statics", &staticJ, "profiles",
        &profilesJ, "wellknown", &wellknownJ, "headers", &headersJ, "schema",
        &schemaJ);
    if (err) {
        EXT_CRITICAL(
            "idp=%s parsing fail should define 'credentials','static','alias' "
            "(idpParseOidcConfig)",
            idp->uid);
        goto OnErrorExit;
    }
    // type is only use for generic IDP (ldap & oidc)
    if (!idp->info)
        idp->info = idp->uid;

    // parse config sections
    idp->magic = MAGIC_OIDC_IDP;
    idp->ctx = ctx;
    idp->credentials =
        idpParseCredentials(idp, credentialsJ, defaults->credentials);
    idp->statics = idpParsestatic(idp, staticJ, defaults->statics);
    idp->profiles = idpParseProfils(idp, profilesJ, defaults->profiles);
    idp->wellknown = idpParseWellknown(idp, wellknownJ, defaults->wellknown);
    idp->headers = idpParseHeaders(idp, headersJ, defaults->headers);

    // any error is fatal, even if section check continue after 1st error
    if (!idp->wellknown || !idp->statics || !idp->credentials ||
        !idp->headers || !idp->profiles)
        goto OnErrorExit;

    idp->ctx = ctx;  // optional idp context specific handle
    return 0;

OnErrorExit:
    return 1;
}

// search for a plugin idps/decoders CB list
static const idpPluginT *idpFindPlugin(const char *type)
{
    idpPluginT *idp = NULL;
    int index;

    // search within plugin list
    for (idpRegistryT *registryIdx = registryHead; registryIdx;
         registryIdx = registryIdx->next) {
        idpPluginT *idps = registryIdx->plugin;
        for (index = 0; idps[index].uid; index++) {
            if (!strcasecmp(idps[index].uid, type)) {
                idp = &idps[index];
                break;
            }
        }
    }
    if (!idp)
        goto OnErrorExit;

    return idp;

OnErrorExit:
    return NULL;
}

// build IDP generic callback handle
static idpGenericCbT idpGenericCB = {
    .magic = MAGIC_OIDC_CBS,
    .parseCredentials = idpParseCredentials,
    .parsestatic = idpParsestatic,
    .parseWellknown = idpParseWellknown,
    .parseHeaders = idpParseHeaders,
    .parseConfig = idpParseOidcConfig,
    .fedidCheck = fedidCheck,
    .pluginRegister = idpRegisterPlugin,
};

static int idpParseOne(oidcCoreHdlT *oidc, json_object *idpJ, oidcIdpT *idp)
{
    int err;

    // search idp with registry
    const char *uid =
        json_object_get_string(json_object_object_get(idpJ, "uid"));
    if (!uid) {
        EXT_ERROR("[idp-parsing-error] invalid json requires: uid");
        goto OnErrorExit;
    }
    const char *type =
        json_object_get_string(json_object_object_get(idpJ, "type"));
    if (!type)
        type = uid;

    // if not builtin load plugin before processing any further the config
    json_object *pluginJ = json_object_object_get(idpJ, "plugin");
    if (pluginJ) {
        const char *ldpath =
            json_object_get_string(json_object_object_get(pluginJ, "ldpath"));
        if (!ldpath) {
            EXT_CRITICAL(
                "[idp-parsing-ldpath] idp=%s invalid json 'ldpath' missing",
                uid);
            goto OnErrorExit;
        }
        else {
            void *handle = NULL;
            char *filepath;
            // split string into multiple configpath
            str2TokenT tknHandle;
            for (filepath = utilStr2Token(&tknHandle, ':', ldpath); filepath;
                 filepath = utilStr2Token(&tknHandle, 0, 0)) {
                handle = dlopen(filepath, RTLD_NOW | RTLD_LOCAL);
                if (handle)
                    break;
            }
            if (!handle) {
                EXT_ERROR("[idp-plugin-load] idp=%s plugin=%s error=%s", uid,
                          ldpath, dlerror());
                goto OnErrorExit;
            }

            oidcPluginInitCbT registerPluginCB =
                (oidcPluginInitCbT)dlsym(handle, "oidcPluginInit");
            if (!registerPluginCB) {
                EXT_ERROR(
                    "[idp-plugin-symb] idp=%s plugin=%s "
                    "initcb='oidcPluginInit' (symbol not found)",
                    uid, filepath);
                goto OnErrorExit;
            }

            err = registerPluginCB(oidc, &idpGenericCB);
            if (err) {
                EXT_ERROR(
                    "[idp-plugin-init] idp=%s plugin=%s "
                    "initcb='oidcPluginInit' (call fail)",
                    uid, filepath);
                goto OnErrorExit;
            }
        }
    }

    idp->magic = MAGIC_OIDC_IDP;
    idp->oidc = oidc;
    idp->plugin = idpFindPlugin(type);
    if (!idp->plugin) {
        EXT_ERROR("[idp-plugin-missing] fail to find type=%s [idp=%s]", type,
                  uid);
        goto OnErrorExit;
    }
    // when call idp custom config callback
    if (idp->plugin->registerConfig)
        err = idp->plugin->registerConfig(idp, idpJ);
    else
        err = idpParseOidcConfig(idp, idpJ, NULL, NULL);
    if (err)
        goto OnErrorExit;

    return 0;

OnErrorExit:
    return 1;
}

oidcIdpT const *idpParseConfig(oidcCoreHdlT *oidc, json_object *idpsJ)
{
    oidcIdpT *idps;
    int err, count;

    switch (json_object_get_type(idpsJ)) {
    case json_type_array:
        count = (int)json_object_array_length(idpsJ);
        idps = calloc(count + 1, sizeof(oidcIdpT));

        for (int idx = 0; idx < count; idx++) {
            json_object *idpJ = json_object_array_get_idx(idpsJ, idx);
            err = idpParseOne(oidc, idpJ, &idps[idx]);
            if (err) {
                EXT_ERROR("[idp-parsing-error] ext=%s", oidc->uid);
                goto OnErrorExit;
            }
        }
        break;

    case json_type_object:
        idps = calloc(2, sizeof(oidcIdpT));
        err = idpParseOne(oidc, idpsJ, &idps[0]);
        if (err) {
            EXT_ERROR("[idp-parsing-error] ext=%s check config", oidc->uid);
            goto OnErrorExit;
        }
        break;

    default:
        EXT_ERROR(
            "[idp-parsing-error] ext=%s idp config should be json/array|object",
            oidc->uid);
        goto OnErrorExit;
    }
    return idps;

OnErrorExit:
    return NULL;
}

int idpRegisterAlias(oidcCoreHdlT *oidc, oidcIdpT *idp, afb_hsrv *hsrv)
{
    int err;

    if (idp->plugin->registerAlias) {
        EXT_DEBUG("[idp-register-alias] uid=%s login='%s'", idp->uid,
                  idp->plugin->uid);
        err = idp->plugin->registerAlias(idp, hsrv);
        if (err)
            goto OnErrorExit;
    }
    return 0;

OnErrorExit:
    EXT_ERROR(
        "[idp-register-alias] ext=%s idp=%s config should be json/array|object",
        oidc->uid, idp->uid);
    return 1;
}

// register IDP login and authentication callback endpoint
int idpRegisterApis(oidcCoreHdlT *oidc,
                    oidcIdpT *idp,
                    struct afb_apiset *declare_set,
                    struct afb_apiset *call_set)
{
    int err;

    // call idp init callback
    if (idp->plugin->registerApis) {
        EXT_DEBUG("[idp-register-apis] uid=%s login='%s'", idp->uid,
                  idp->plugin->uid);
        err = idp->plugin->registerApis(idp, declare_set, call_set);
        if (err)
            goto OnErrorExit;
    }
    return 0;

OnErrorExit:
    EXT_ERROR(
        "[idp-register-apis] ext=%s idp=%s config should be json/array|object",
        oidc->uid, idp->uid);
    return 1;
}

int idpPLuginRegistryInit(void)
{
    return 0;
}
