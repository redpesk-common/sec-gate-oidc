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
#include <rp-utils/rp-escape.h>

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


const char *oidcCoreUID(const oidcCoreHdlT *oidc)
{
    return oidc->uid;
}

const oidGlobalsT *oidcCoreGlobals(const oidcCoreHdlT *oidc)
{
    return &oidc->globals;
}

afb_api_v4 *oidcCoreAfbApi(const oidcCoreHdlT *oidc)
{
    return oidc->apiv4;
}

httpPoolT *oidcCoreHTTPPool(const oidcCoreHdlT *oidc)
{
    return oidc->httpPool;
}

/* read and setup the global configuration object */
static int globalConfig(oidGlobalsT *globals, json_object *globalsJ)
{
    int err;
    json_object *infoJ;

    if (globalsJ) {
        // clang-format off
        err = rp_jsonc_unpack (globalsJ,
                               "{s?o s?s s?s s?s s?s s?s s?i s?i s?b !}",
                               "info", &infoJ,
                               "login", &globals->loginUrl,
                               "error", &globals->errorUrl,
                               "register", &globals->registerUrl,
                               "fedlink", &globals->fedlinkUrl,
                               "home", &globals->homeUrl, "cache", &globals->tCache, "timeout", &globals->sTimeout, "debug", &globals->debug);
        // clang-format on
        if (err < 0) {
            EXT_ERROR("[oidc-core] misconfig of globals %s (pos %d)",
                      rp_jsonc_get_error_string(err),
                      rp_jsonc_get_error_position(err));
            return err;
        }
    }
    // setup default values
    if (!globals->registerUrl)
        globals->registerUrl = URL_OIDC_USR_REGISTER;
    if (!globals->fedlinkUrl)
        globals->fedlinkUrl = URL_OIDC_USR_FEDLINK;
    if (!globals->homeUrl)
        globals->homeUrl = URL_OIDC_USR_HOME;
    if (!globals->errorUrl)
        globals->errorUrl = URL_OIDC_USR_ERROR;
    if (!globals->tCache)
        globals->tCache = URL_OIDC_AUTH_CACHE;
    if (!globals->sTimeout)
        globals->sTimeout = EXT_SESSION_TIMEOUT;

    return 0;
}

// Pase and load config.json info oidc global context
int oidcCoreParseConfig(oidcCoreHdlT **poidc, struct json_object *oidcJ, char const *uid)
{
    int err;
    json_object *idpsJ = NULL, *aliasJ = NULL, *apisJ = NULL, *globalsJ = NULL,
                *pluginsJ = NULL;
    oidcCoreHdlT *oidc;

    oidc = calloc(1, sizeof(oidcCoreHdlT));
    if (oidc == NULL)
        goto OnErrorExit;

    oidc->magic = MAGIC_OIDC_MAIN;
    oidc->uid = uid;
    json_object_get(oidcJ);

    // register builtin IDPs
    err = registerBuiltinIdps();
    if (err)
        goto OnErrorExit;

    // clang-format off
    err = rp_jsonc_unpack (oidcJ,
                           "{s?s,s?s,s?o,s?o,s?o,s?o,s?o,s?o,s?i}",
                           "api", &oidc->api,
                           "info", &oidc->info,
                           "globals", &globalsJ,
                           "plugins", &pluginsJ, "idp", &idpsJ, "idps", &idpsJ, "alias", &aliasJ, "apis", &apisJ, "verbose", &oidc->verbose);
    // clang-format on
    if (err) {
        EXT_ERROR("[oidc-core] misconfig %s (pos %d)",
                  rp_jsonc_get_error_string(err),
                  rp_jsonc_get_error_position(err));
        goto OnErrorExit;
    }
    // set the api
    if (!oidc->api)
        oidc->api = oidc->uid;

    // set the global config
    err = globalConfig(&oidc->globals, globalsJ);
    if (err)
        goto OnErrorExit;

    // load the plugins if exist
    if (pluginsJ != NULL) {
        err = idpPluginsParseConfig(oidc, pluginsJ);
        if (err)
            goto OnErrorExit;
    }
    // set idps
    oidc->idps = idpParseConfig(oidc, idpsJ);

    // set aliases
    oidc->aliases = aliasParseConfig(oidc, aliasJ);

    // set apis
    oidc->apis = apisParseConfig(oidc, apisJ);

    // stop when error in previous setting
    if (!oidc->idps || !oidc->aliases || !oidc->apis)
        goto OnErrorExit;

    // There is at least one IDP and one profile per IDP
    // So test if there is only one profile of only one idp
    // or not when global loginUrl is NULL
    // see oidcCoreRedirectLogin
    if (!oidc->globals.loginUrl &&
        (oidc->idps[1].uid || oidc->idps[0].profiles[1].uid))
        oidc->globals.loginUrl = URL_OIDC_USR_LOGIN;

    *poidc = oidc;
    return 0;

OnErrorExit:
    free(oidc);  // TODO also free sub components
    *poidc = NULL;
    EXT_CRITICAL("[oidc-core] Failed to initialize at configuration");
    return -1;
}

// Declares the apis
int oidcCoreDeclareApis(oidcCoreHdlT *oidc,
                        struct afb_apiset *declare_set,
                        struct afb_apiset *call_set)
{
    int err, idx;

    // import/connect to fedid API
    if (oidc->fedapi) {
        err = afb_api_ws_add_client(oidc->fedapi, declare_set, call_set, 1);
        if (err) {
            EXT_ERROR(
                "[oidc-fedapi-not-found] ext=%s fail to connect to fedidp=%s  "
                "(AfbExtensionDeclareV1)",
                oidc->uid, oidc->fedapi);
            goto OnErrorExit;
        }
    }
    // declare internal identity service api
    err = idsvcDeclareApi(&oidc->apiv4, oidc->api, oidc, declare_set, call_set);
    if (err)
        goto OnErrorExit;

    // register apis of idps
    for (idx = 0; oidc->idps[idx].uid; idx++) {
        err = idpRegisterApis(oidc, &oidc->idps[idx], declare_set, call_set);
        if (err)
            goto OnErrorExit;
    }

    // register protected apis
    for (idx = 0; oidc->apis[idx].uid; idx++) {
        err = apisRegisterOne(oidc, &oidc->apis[idx], declare_set, call_set);
        if (err)
            goto OnErrorExit;
    }

    return 0;

OnErrorExit:
    EXT_CRITICAL(
        "[oidc-declare-ext-fail] ext=%s fail to declare oidc API "
        "(AfbExtensionDeclareV1)",
        oidc->uid);
    return -1;
}

// Declare HTTP hooks
int oidcCoreDeclareHTTP(oidcCoreHdlT *oidc, afb_hsrv *hsrv)
{
    const oidcIdpT *idpiter;
    const oidcAliasT *aliasiter;

    // create libcurl http multi pool
    // oidc->httpPool= httpCreatePool(hsrv->efd, glueGetCbs(), oidc->verbose);
    oidc->httpPool = httpCreatePool(NULL, glueGetCbs(), oidc->verbose);
    if (!oidc->httpPool)
        goto OnErrorExit;

    // register IDP aliases
    for (idpiter = oidc->idps ; idpiter->uid != NULL ; idpiter++) {
        int err = idpRegisterAlias(oidc, idpiter, hsrv);
        if (err)
            goto OnErrorExit;
    }

    // register other aliases
    for (aliasiter = oidc->aliases ; aliasiter->uid != NULL ; aliasiter++) {
        int err = aliasRegisterOne(aliasiter, hsrv);
        if (err)
            goto OnErrorExit;
    }

    return 0;

OnErrorExit:
    return -1;
}

// return the idp list to display corresponding login page.
json_object *oidcCoreGetProfilsForLOA(const oidcCoreHdlT *oidc,
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

int oidcCoreGetFilteredIdpList(const oidcCoreHdlT *oidc,
                               const char **dest,
                               int nrDest,
                               const char *excludedUID)
{
    int index = 0;
    const oidcIdpT *idp = oidc->idps;
    for (; idp->uid != NULL && index < nrDest ; idp++) {
        if (excludedUID != NULL || strcasecmp(idp->uid, excludedUID)) {
            dest[index++] = idp->uid;
        }
    }
    return index;
}

int oidcCoreRedirectLogin(const oidcCoreHdlT *oidc,
                          afb_hreq *hreq)
{
    int rc;
    char url[EXT_URL_MAX_LEN];
    char redirectUrl[EXT_HEADER_MAX_LEN];
    const char *redirurl;
    const oidcIdpT *idp;
    const oidcProfileT *profile;
    oidcSessionT *session;

    if (oidc->globals.loginUrl) {
        const char *params[] = {
#if FORCELANG
            "language", setlocale(LC_CTYPE, ""),
#endif
            NULL};
        size_t sz = rp_escape_url_to(NULL, oidc->globals.loginUrl,
                                     params, url, sizeof url);
        if (sz < sizeof url)
            redirurl = url;
        else {
            EXT_ERROR("[oidc-core] redirect too long");
            redirurl = oidc->globals.loginUrl;
        }
    }
    else {
        // when no global login page defined use idp[0]+profile[0] with openid
        // url form
        idp = oidc->idps;
        profile = idp->profiles;
        session = oidcSessionOfHttpReq(hreq);

        rc = afb_hreq_make_here_url(hreq, idp->statics->aliasLogin, redirectUrl,
                                    sizeof(redirectUrl));
        if (rc < 0) {
            EXT_ERROR("[oidc-core] failed to make here url");
            redirurl = URL_OIDC_USR_LOGIN;
        }
        else {
            const char *params[] = {"client_id",
                                    idp->credentials->clientId,
                                    "response_type",
                                    idp->wellknown->respondLabel,
                                    "state",
                                    oidcSessionUUID(session),
                                    "nonce",
                                    oidcSessionUUID(session),
                                    "scope",
                                    profile->scope,
                                    "redirect_uri",
                                    redirectUrl,
#if FORCELANG
                                    "language",
                                    setlocale(LC_CTYPE, ""),
#endif
                                    NULL};

            // build wreq and send it
            size_t sz = rp_escape_url_to(NULL, idp->wellknown->authorize,
                                         params, url, sizeof url);
            if (sz >= sizeof url) {
                EXT_ERROR("[oidc-core] redirect too long");
                redirurl = URL_OIDC_USR_LOGIN;
            }
            else {
                // keep track of selected idp profile
                oidcSessionSetIdpProfile(session, profile);
                redirurl = url;
            }
        }
    }

    EXT_DEBUG("[oidc-core] redirect login %s", redirurl);
    afb_hreq_redirect_to(hreq, redirurl, HREQ_QUERY_EXCL, HREQ_REDIR_TMPY);
    return 1;
}

