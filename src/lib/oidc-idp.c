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

#include <rp-utils/rp-enum-map.h>
#include <rp-utils/rp-jsonc.h>

#include <libafb/afb-core.h>
#include <libafb/afb-http.h>
#include <libafb/afb-v4.h>

#include "oidc-core.h"
#include "oidc-fedid.h"
#include "oidc-idp-plugin.h"
#include "oidc-idp.h"

const rp_enum_map_t idpAuthMethods[] = {
    {"secret-unknown", IDP_CLIENT_SECRET_UNKNOWN},
    {"client_secret_post", IDP_CLIENT_SECRET_POST},
    {"client_secret_basic", IDP_CLIENT_SECRET_BASIC},
    // {"client_secret_jwt", IDP_CLIENT_SECRET_JWT}, not implemented
    // {"private_key_jwt", IDP_PRIVATE_KEY_JWT}, not implemented
    {NULL}  // terminator
};

const rp_enum_map_t idpRespondTypes[] = {
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

// get the first profile of idp enough for the targeted LOA
// and the given scope (that might be NULL)
// Return NULL if no profile matches the LOA
const oidcProfileT *idpGetFirstProfile(const oidcIdpT *idp,
                                       int targetLOA,
                                       const char *scope)
{
    const oidcProfileT *iter = idp->profiles;
    const oidcProfileT *result = NULL;
    while (iter->uid != NULL) {
        if (iter->loa >= targetLOA &&
            (scope == NULL ||
             (iter->scope != NULL && strcmp(scope, iter->scope) == 0)) &&
            (result == NULL || iter->loa < result->loa))
            result = iter;
        iter++;
    }
    return result;
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
        statics->sTimeout = oidcCoreGlobals(idp->oidc)->sTimeout;

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

// parse one idp configuration
static int idpParseOne(const oidcCoreHdlT *oidc, json_object *idpJ, oidcIdpT *idp)
{
    int err;
    const char *uid, *type;
    json_object *pluginJ, *obj;

    // get IDP uid
    if (!json_object_object_get_ex(idpJ, "uid", &obj) ||
        !json_object_is_type(obj, json_type_string)) {
        EXT_ERROR("[oidc-idp] idp config requires a string 'uid'");
        goto OnErrorExit;
    }
    uid = json_object_get_string(obj);

    // compute IDP type
    if (!json_object_object_get_ex(idpJ, "type", &obj))
        type = uid;
    else {
        if (!json_object_is_type(obj, json_type_string)) {
            EXT_ERROR("[oidc-idp] idp config 'type' must be a string");
            goto OnErrorExit;
        }
        type = json_object_get_string(obj);
    }

    // if not builtin load plugin before processing any further the config
    pluginJ = json_object_object_get(idpJ, "plugin");
    if (pluginJ != NULL) {
        err = idpPluginParseOne(oidc, pluginJ);
        if (err < 0)
            goto OnErrorExit;
    }

    idp->oidc = oidc;
    idp->plugin = idpPluginFind(type);
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

// Parse the configuration object idpJ for idps list
oidcIdpT *idpParseConfig(const oidcCoreHdlT *oidc, json_object *idpsJ)
{
    oidcIdpT *idps = NULL;
    int err, count, idx;

    switch (json_object_get_type(idpsJ)) {
    case json_type_array:
        count = (int)json_object_array_length(idpsJ);
        idps = calloc(count + 1, sizeof(oidcIdpT));
        if (idps == NULL)
            goto oom;

        for (idx = 0; idx < count; idx++) {
            json_object *idpJ = json_object_array_get_idx(idpsJ, idx);
            err = idpParseOne(oidc, idpJ, &idps[idx]);
            if (err)
                goto OnErrorExit;
        }
        break;

    case json_type_object:
        idps = calloc(2, sizeof(oidcIdpT));
        if (idps == NULL)
            goto oom;

        err = idpParseOne(oidc, idpsJ, &idps[0]);
        if (err)
            goto OnErrorExit;
        break;

    default:
        EXT_ERROR("[oidc-idp] Bad idps config object");
        goto OnErrorExit;
    }
    return idps;

oom:
    EXT_ERROR("[oidc-idp] out of memory");
OnErrorExit:
    free(idps);
    return NULL;
}

// register aliases of IDPs
int idpRegisterAlias(const oidcCoreHdlT *oidc, const oidcIdpT *idp, afb_hsrv *hsrv)
{
    int err;

    // declares an alias?
    if (idp->plugin->registerAlias == NULL)
        return 0;

    // call idp's alias register callback
    EXT_DEBUG("[idp-register-alias] idp/plugin uids: %s/%s", idp->uid,
              idp->plugin->uid);
    err = idp->plugin->registerAlias(idp, hsrv);
    if (err)
        EXT_ERROR(
            "[idp-register-alias] failed to register idp alias, idp/plugin "
            "uids: %s/%s",
            idp->uid, idp->plugin->uid);
    return err;
}

// register IDP login and authentication callback endpoint
int idpRegisterApis(const oidcCoreHdlT *oidc,
                    const oidcIdpT *idp,
                    struct afb_apiset *declare_set,
                    struct afb_apiset *call_set)
{
    int err;

    // declares an API?
    if (idp->plugin->registerApis == NULL)
        return 0;

    // call idp's api register callback
    EXT_DEBUG("[idp-register-apis] idp/plugin uids: %s/%s", idp->uid,
              idp->plugin->uid);
    err = idp->plugin->registerApis(idp, declare_set, call_set);
    if (err)
        EXT_ERROR(
            "[idp-register-apis] failed to register idp api, idp/plugin uids: "
            "%s/%s",
            idp->uid, idp->plugin->uid);
    return err;
}
