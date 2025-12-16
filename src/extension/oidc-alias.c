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

#include <locale.h>
#include <microhttpd.h>
#include <string.h>
#include <time.h>

#include <rp-utils/rp-escape.h>
#include <rp-utils/rp-jsonc.h>

#include <libafb/afb-core.h>
#include <libafb/afb-http.h>
#include <libafb/afb-v4.h>

#include "oidc-alias.h"
#include "oidc-core.h"
#include "oidc-fedid.h"
#include "oidc-idsvc.h"
#include "oidc-session.h"

// dummy unique value for session key

// check if one of requested role exist within social cookie
// return 0 if that is the case
// return 1 if none matches
static int aliasCheckAttrs(oidcSessionT *session, oidcAliasT *alias)
{
    const char **roles = alias->roles;
    while (*roles) {
        if (fedidsessionHasAttribute(session, *roles))
            return 1;
        roles++;
    }
    return 0;
};

// create aliasFrom cookie and redirect to common login page
static int aliasRedirectLogin(afb_hreq *hreq, oidcAliasT *alias, oidcSessionT *session)
{
    int rc;
    char url[EXT_URL_MAX_LEN];
    char redirectUrl[EXT_HEADER_MAX_LEN];
    const char *redirurl;
    const oidcIdpT *idp;
    const oidcProfileT *profile;

    oidcSessionSetAlias(session, alias);

    if (alias->oidc->globals.loginUrl) {
        const char *params[] = {
#if FORCELANG
            "language", setlocale(LC_CTYPE, ""),
#endif
            NULL};
        size_t sz = rp_escape_url_to(NULL, alias->oidc->globals.loginUrl,
                                     params, url, sizeof url);
        if (sz < sizeof url)
            redirurl = url;
        else {
            EXT_ERROR("[oidc-alias] redirect too long");
            redirurl = alias->oidc->globals.loginUrl;
        }
    }
    else {
        // when no global login page defined use idp[0]+profile[0] with openid
        // url form
        idp = &alias->oidc->idps[0];
        profile = &idp->profiles[0];

        rc = afb_hreq_make_here_url(hreq, idp->statics->aliasLogin,
                                        redirectUrl, sizeof(redirectUrl));
        if (rc < 0) {
            EXT_ERROR("[oidc-alias] failed to make here url");
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
            size_t sz = rp_escape_url_to(NULL, idp->wellknown->authorize, params,
                                         url, sizeof url);
            if (sz >= sizeof url) {
                EXT_ERROR("[oidc-alias] redirect too long");
                redirurl = URL_OIDC_USR_LOGIN;
            }
            else {
                // keep track of selected idp profile
                oidcSessionSetIdpProfile(session, profile);
                redirurl = url;
            }
        }
    }

    EXT_DEBUG("[oidc-alias] redirect login %s", redirurl);
    afb_hreq_redirect_to(hreq, redirurl, HREQ_QUERY_EXCL, HREQ_REDIR_TMPY);
    return 1;
}

// create aliasFrom cookie and redirect to idp profile page
static int aliasRedirectTimeout(afb_hreq *hreq, oidcAliasT *alias, oidcSessionT *session)
{
    char url[EXT_URL_MAX_LEN];
    char redirectUrl[EXT_HEADER_MAX_LEN];
    const oidcProfileT *profile;
    const oidcIdpT *idp;
    int rc;

    oidcSessionSetAlias(session, alias);
    profile = oidcSessionGetIdpProfile(session);
    idp = profile->idp;

    // add afb-binder endpoint to login redirect alias
    rc = afb_hreq_make_here_url(hreq, idp->statics->aliasLogin,
                                 redirectUrl, sizeof(redirectUrl));
    if (rc < 0)
        EXT_ERROR("[oidc-alias] failed to make here url");
    else {
        const char *params[] = {"client_id",
                                idp->credentials->clientId,
                                "response_type",
                                idp->wellknown->respondLabel,
                                "state",
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

        size_t sz = rp_escape_url_to(NULL, idp->statics->aliasLogin,
                                     params, url, sizeof url);
        if (sz < sizeof url) {
            EXT_DEBUG("[oidc-alias] redirect timeout %s", url);
            afb_hreq_redirect_to(hreq, url, HREQ_QUERY_EXCL, HREQ_REDIR_TMPY);
            return 1;
        }

        EXT_ERROR("[oidc-alias] redirect too long");
    }
    // error: redirect to global login
    return aliasRedirectLogin(hreq, alias, session);
}

/**
 * check that the client has the required LOA
 */
static int aliasCheckReq(afb_hreq *hreq, void *ctx)
{
    oidcAliasT *alias = (oidcAliasT *)ctx;
    const oidcProfileT *idpProfile;
    oidcSessionT *session;
    json_object *eventJ;

    // get session of the request
    session = oidcSessionOfHttpReq(hreq);
    if (session == NULL) {
        EXT_NOTICE("[oidc-alias] can't bind to session");
        afb_hreq_reply_error(hreq, EXT_HTTP_CONFLICT);
        return 1;
    }

    // Check required LOA
    if (!oidcSessionIsValid(session) || oidcSessionGetLOA(session) < alias->loa) {

        // push event to notify the access denied
        oidcSessionEventPush(session, "{ss ss ss si si}", "status",
                      "loa-mismatch", "uid", alias->uid, "url",
                      alias->url, "loa-target", alias->loa,
                      "loa-session", oidcSessionGetLOA(session));

        // if current profile LOA is enough then fire same idp/profile
        // authen
        idpProfile = oidcSessionGetIdpProfile(session);
        if (idpProfile != NULL && idpProfile->loa >= alias->loa)
            return aliasRedirectTimeout(hreq, alias, session);
        return aliasRedirectLogin(hreq, alias, session);
    }

    // if tCache not expired use jump authent check
    if (oidcSessionShouldCheck(session)) {

        // check roles
        if (alias->roles) {
            if (!aliasCheckAttrs(session, alias))
                return aliasRedirectLogin(hreq, alias, session);
        }
        // store a timestamp to cache authentication validation
        oidcSessionSetNextCheck(session, alias->tCache);
    }

    // change hreq bearer (TODO why?)
    afb_req_common_set_token(&hreq->comreq, NULL);
    oidcSessionValidate(session, alias->oidc->globals.sTimeout);
    return 0;  // move forward and continue parsing lower priority aliases
}

/**
 * Register one alias, described by 'alias', to the HTTP server 'hsrv'
 */
int aliasRegisterOne(oidcAliasT *alias, afb_hsrv *hsrv)
{
    const char *rootdir;
    int rc;

    // if alias full path does not start with '/' then prefix it with
    // http_root_dir
    if (alias->path[0] == '/')
        rootdir = "";
    else
        rootdir = afb_common_rootdir_get_path();

    // insert LOA checking if required
    if (alias->loa > 0) {
        rc = afb_hsrv_add_handler(hsrv, alias->url, aliasCheckReq, alias,
                                      alias->priority);
        if (rc == 0) {
            EXT_ERROR("[oidc-alias] failed to add alias %s handler %s",
                        alias->uid, alias->url);
            return -1;
        }
    }

    // add with lower priority the redirection
    rc = afb_hsrv_add_alias_path(hsrv, alias->url, rootdir, alias->path,
                                     alias->priority - 1, 0 /*not relax */);
    if (rc == 0) {
        EXT_ERROR("[oidc-alias] failed to add alias %s from %s to %s/%s",
                        alias->uid, alias->url, rootdir, alias->path);
        return -1;
    }

    EXT_DEBUG("[oidc-alias] register uid=%s loa=%d url='%s' fullpath='%s/%s'",
              alias->uid, alias->loa, alias->url, rootdir, alias->path);
    return 0;
}

/**
 * extract from aliasJ the struct oidcAliasT
 * alias recording the alias
 *
 * @param oidc the main structure
 * @param aliasJ the json object configuration
 * @param alias the struct to fill
 *
 * @return 0 on success or else not zero for error
 */
static int parseOneAlias(oidcCoreHdlT *oidc,
                            json_object *aliasJ,
                            oidcAliasT *alias)
{
    const char **roles;
    int rc, count, idx;
    json_object *requireJ = NULL;

    // set tCache default
    alias->tCache = oidc->globals.tCache;
    alias->oidc = oidc;

    rc = rp_jsonc_unpack(aliasJ, "{ss,s?s,s?s,s?s,s?i,s?i,s?o}", "uid",
                              &alias->uid, "info", &alias->info, "url",
                              &alias->url, "path", &alias->path, "prio",
                              &alias->priority, "loa", &alias->loa,
                              "require", &requireJ);
    if (rc) {
        EXT_CRITICAL( "[oidc-alias] bad alias conf: %s", json_object_to_json_string(aliasJ));
        return -1;
    }

    // provide some defaults value based on uid
    if (!alias->url)
        asprintf((char **)&alias->url, "/%s", alias->uid);
    if (!alias->path)
        asprintf((char **)&alias->path, "$ROOTDIR/%s", alias->uid);

    // handle required roles
    if (requireJ) {
        switch (json_object_get_type(requireJ)) {
        case json_type_array:
            count = (int)json_object_array_length(requireJ);
            roles = calloc(count + 1, sizeof(char *));
            if (roles == NULL) {
oom:                
                EXT_CRITICAL("[oidc-alias] out of memory");
                return -1;
            }

            for (int idx = 0; idx < count; idx++) {
                json_object *roleJ = json_object_array_get_idx(requireJ, idx);
                roles[idx] = json_object_get_string(roleJ);
            }
            break;

        case json_type_object:
            roles = calloc(2, sizeof(char *));
            if (roles == NULL)
                goto oom;

            roles[0] = json_object_get_string(requireJ);
            break;

        default:
            EXT_CRITICAL( "[oidc-alias] bad require conf: %s", json_object_to_json_string(requireJ));
            return -1;
        }
        alias->roles = roles;
    }
    return 0;
}

/**
 * extract from aliasesJ the array of structs oidcAliasT
 * recording aliases
 *
 * @param oidc the main structure
 * @param aliasesJ the json object configuration
 *
 * @return NULL on error or the array of aliases
 */
oidcAliasT *aliasParseConfig(oidcCoreHdlT *oidc, json_object *aliasesJ)
{
    oidcAliasT *aliases = NULL;
    int rc = 0, count, idx;

    switch (json_object_get_type(aliasesJ)) {
    case json_type_array:
        /* extract array of aliases */
        count = (int)json_object_array_length(aliasesJ);
        aliases = calloc(count + 1, sizeof(oidcAliasT));
        if (aliases != NULL) {
            for (idx = 0; rc >= 0 && idx < count; idx++) {
                json_object *aliasJ = json_object_array_get_idx(aliasesJ, idx);
                rc = parseOneAlias(oidc, aliasJ, &aliases[idx]);
            }
        }
        break;

    case json_type_object:
        /* extract single alias */
        aliases = calloc(2, sizeof(oidcAliasT));
        if (aliases != NULL)
            rc = parseOneAlias(oidc, aliasesJ, &aliases[0]);
        break;

    default:
        rc = -1;
        break;
    }
    if (aliases == NULL) {
        if (rc == 0)
            EXT_CRITICAL("[oidc-alias] out of memory");
        else
            EXT_CRITICAL("[oidc-alias] bad aliases conf: %s", json_object_to_json_string(aliasesJ));
    }
    else if (rc < 0) {
        free(aliases);
        aliases = NULL;
    }
    return aliases;
}
