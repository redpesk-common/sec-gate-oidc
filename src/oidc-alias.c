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

#include <rp-utils/rp-jsonc.h>
#include <rp-utils/rp-escape.h>

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
int aliasCheckAttrs(oidcSession *session, oidcAliasT *alias)
{
    const char **roles = alias->roles;
    while(*roles) {
        if (fedidsessionHasAttribute(session, *roles))
            return 0;
        roles++;
    }
    return 1;
};

// create aliasFrom cookie and redirect to idp profile page
static void aliasRedirectTimeout(afb_hreq *hreq, oidcAliasT *alias)
{
    char url[EXT_URL_MAX_LEN];
    char redirectUrl[EXT_HEADER_MAX_LEN];
    const oidcProfileT *profile;
    int err;
    oidcSession *session = oidcSessionOfHttpReq(hreq);

    oidcSessionSetAlias(session, alias);
    profile = oidcSessionGetIdpProfile(session);

    // add afb-binder endpoint to login redirect alias
    err = afb_hreq_make_here_url(hreq, profile->idp->statics->aliasLogin,
                                 redirectUrl, sizeof(redirectUrl));
    if (err < 0)
        goto OnErrorExit;

    const char *params[] = {
        "client_id", profile->idp->credentials->clientId,
        "response_type", profile->idp->wellknown->respondLabel,
        "state", oidcSessionUUID(session),
        "scope", profile->scope,
        "redirect_uri", redirectUrl,
        "language", setlocale(LC_CTYPE, ""),
        NULL };

    size_t sz = rp_escape_url_to(NULL, profile->idp->statics->aliasLogin, params, url, sizeof url);
    if (sz >= sizeof url) {
        EXT_ERROR(
            "[fail-login-redirect] fail to build redirect url "
            "(aliasRedirectLogin)");
        goto OnErrorExit;
    }

    EXT_DEBUG("[alias-redirect-login] %s (aliasRedirectLogin)", url);
    afb_hreq_redirect_to(hreq, url, HREQ_QUERY_EXCL, HREQ_REDIR_TMPY);
    return;

OnErrorExit:
    afb_hreq_redirect_to(hreq, alias->oidc->globals->loginUrl, HREQ_QUERY_EXCL,
                         HREQ_REDIR_TMPY);
}

// create aliasFrom cookie and redirect to common login page
static void aliasRedirectLogin(afb_hreq *hreq, oidcAliasT *alias)
{
    int err;
    char url[EXT_URL_MAX_LEN];

    oidcSessionSetAlias(oidcSessionOfHttpReq(hreq), alias);

    if (alias->oidc->globals->loginUrl) {
        const char *params[] = {
            "language", setlocale(LC_CTYPE, ""),
            NULL };
        size_t sz = rp_escape_url_to(NULL, alias->oidc->globals->loginUrl, params, url, sizeof url);
        if (sz >= sizeof url) {
            EXT_ERROR(
                "[fail-login-redirect] fail to build redirect url "
                "(aliasRedirectLogin)");
            goto OnErrorExit;
        }
    }
    else {
        // when no global login page defined use idp[0]+profile[0] with openid
        // url form
        int status;
        oidcIdpT *idp = &alias->oidc->idps[0];
        const oidcProfileT *profile = &idp->profiles[0];
        const char *uuid = oidcSessionUUID(oidcSessionOfHttpReq(hreq));
        char redirectUrl[EXT_HEADER_MAX_LEN];

        status = afb_hreq_make_here_url(hreq, idp->statics->aliasLogin,
                                        redirectUrl, sizeof(redirectUrl));
        if (status < 0)
            goto OnErrorExit;

        const char *params[] = {
            "client_id", idp->credentials->clientId,
            "response_type", idp->wellknown->respondLabel,
            "state", uuid,
            "nonce", uuid,
            "scope", profile->scope,
            "redirect_uri", redirectUrl,
            "language", setlocale(LC_CTYPE, ""),
            NULL };

        // build wreq and send it
        size_t sz = rp_escape_url_to(NULL, idp->wellknown->authorize, params, url, sizeof url);
        if (sz >= sizeof url) {
            EXT_ERROR(
                "[fail-login-redirect] fail to build redirect url "
                "(aliasRedirectLogin)");
            goto OnErrorExit;
        }

        // keep track of selected idp profile
        oidcSessionSetIdpProfile(oidcSessionOfHttpReq(hreq), profile);
    }
    EXT_DEBUG("[alias-redirect-login] %s (aliasRedirectLogin)", url);
    afb_hreq_redirect_to(hreq, url, HREQ_QUERY_EXCL, HREQ_REDIR_TMPY);
    return;

OnErrorExit:
    afb_hreq_redirect_to(hreq, alias->oidc->globals->loginUrl, HREQ_QUERY_EXCL,
                         HREQ_REDIR_TMPY);
}

/**
 * check that the client has the required LOA
 */
static int aliasCheckLoaCB(afb_hreq *hreq, void *ctx)
{
    oidcAliasT *alias = (oidcAliasT *)ctx;
    struct timespec tCurrent;
    const oidcProfileT *idpProfile;
    int sessionLoa, tStamp, tNow, err;
    oidcSession *session;

    if (alias->loa) {
        // get session of the request
        session = oidcSessionOfHttpReq(hreq);

        // in case session create failed
        if (session == NULL) {
            EXT_ERROR(
                "[fail-hreq-session] fail to initialise hreq session "
                "(aliasCheckLoaCB)");
            afb_hreq_reply_error(hreq, EXT_HTTP_CONFLICT);
            goto OnRedirectExit;
        }

        // if tCache not expired use jump authent check
        clock_gettime(CLOCK_MONOTONIC, &tCurrent);
        tNow = (int)((tCurrent.tv_nsec / 1000000 + tCurrent.tv_sec * 1000) / 100);
        tStamp = oidcSessionGetExpiration(session);
        if (tNow > tStamp) {
            EXT_NOTICE("session uuid=%s (aliasCheckLoaCB)",
                       oidcSessionUUID(session));

            // if LOA too weak redirect to authentication
            sessionLoa = oidcSessionGetLOA(session);
            if (alias->loa > sessionLoa) {
                json_object *eventJ;

                rp_jsonc_pack(&eventJ, "{ss ss ss si si}", "status",
                              "loa-mismatch", "uid", alias->uid, "url",
                              alias->url, "loa-target", alias->loa,
                              "loa-session", sessionLoa);

                // try to push event to notify the access deny and replay with
                // redirect to login
                idscvPushEvent(session, eventJ);

                // if current profile LOA is enough then fire same idp/profile
                // authen
                idpProfile = oidcSessionGetIdpProfile(session);
                if (idpProfile != NULL && (idpProfile->loa >= alias->loa ||
                             idpProfile->loa == abs(alias->loa))) {
                    aliasRedirectTimeout(hreq, alias);
                }
                else {
                    aliasRedirectLogin(hreq, alias);
                }
                goto OnRedirectExit;
            }

            if (alias->roles) {
                err = aliasCheckAttrs(session, alias);
                if (err) {
                    aliasRedirectLogin(hreq, alias);
                    goto OnRedirectExit;
                }
            }
            // store a timestamp to cache authentication validation
            tStamp = (int)(tNow + alias->tCache / 100);
            oidcSessionSetExpiration(session, tStamp);
        }
    }
    // change hreq bearer
    afb_req_common_set_token(&hreq->comreq, NULL);
    return 0;  // move forward and continue parsing lower priority alias

OnRedirectExit:
    return 1;  // we're done stop scanning alias callback
}

/**
 * Register one alias, described by 'alias', to the HTTP server 'hsrv'
 */
int aliasRegisterOne(oidcAliasT *alias, afb_hsrv *hsrv)
{
    const char *rootdir;
    int status;

    // if alias full path does not start with '/' then prefix it with
    // http_root_dir
    if (alias->path[0] == '/')
        rootdir = "";
    else
        rootdir = afb_common_rootdir_get_path();

    // insert LOA checking if required
    if (alias->loa) {
        status = afb_hsrv_add_handler(hsrv, alias->url, aliasCheckLoaCB, alias,
                                      alias->priority);
        if (status != AFB_HSRV_OK)
            goto OnErrorExit;
    }

    // add with lower priority the redirection
    status = afb_hsrv_add_alias_path(hsrv, alias->url, rootdir, alias->path,
                                     alias->priority - 1, 0 /*not relax */);
    if (status != AFB_HSRV_OK)
        goto OnErrorExit;

    EXT_DEBUG("[alias-register] uid=%s loa=%d url='%s' fullpath='%s/%s'",
              alias->uid, alias->loa, alias->url, rootdir, alias->path);
    return 0;

OnErrorExit:
    EXT_ERROR(
        "[alias-fail-register] fail to register alias uid=%s url=%s "
        "fullpath=%s/%s",
        alias->uid, alias->url, rootdir, alias->path);
    return 1;
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
static int idpParseOneAlias(oidcCoreHdlT *oidc,
                            json_object *aliasJ,
                            oidcAliasT *alias)
{
    json_object *requirerJ = NULL;

    // set tCache default
    alias->tCache = oidc->globals->tCache;
    alias->oidc = oidc;

    int err = rp_jsonc_unpack(aliasJ, "{ss,s?s,s?s,s?s,s?i,s?i,s?i,s?o}", "uid",
                              &alias->uid, "info", &alias->info, "url",
                              &alias->url, "path", &alias->path, "prio",
                              &alias->priority, "loa", &alias->loa, "cache",
                              &alias->tCache, "require", &requirerJ);
    if (err) {
        EXT_CRITICAL(
            "[idp-alias-error] oidc=%s parsing fail profile expect: "
            "uid,url,fullpath,prio,loa,role (idpParseOneAlias)",
            oidc->uid);
        goto OnErrorExit;
    }

    // provide some defaults value based on uid
    if (!alias->url)
        asprintf((char **)&alias->url, "/%s", alias->uid);
    if (!alias->path)
        asprintf((char **)&alias->path, "$ROOTDIR/%s", alias->uid);

    // handle required roles
    if (requirerJ) {
        const char **roles;
        int count;
        switch (json_object_get_type(requirerJ)) {
        case json_type_array:
            count = (int)json_object_array_length(requirerJ);
            roles = calloc(count + 1, sizeof(char *));
            if (roles == NULL)
                goto OnErrorExit;

            for (int idx = 0; idx < count; idx++) {
                json_object *roleJ = json_object_array_get_idx(requirerJ, idx);
                roles[idx] = json_object_get_string(roleJ);
            }
            break;

        case json_type_object:
            roles = calloc(2, sizeof(char *));
            if (roles == NULL)
                goto OnErrorExit;

            roles[0] = json_object_get_string(requirerJ);
            break;

        default:
            EXT_CRITICAL(
                "[idp-alias-error] oidc=%s role should be "
                "json_array|json_object (idpParseOneAlias)",
                oidc->uid);
            goto OnErrorExit;
        }
        alias->roles = roles;
    }
    return 0;

OnErrorExit:
    return 1;
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
    int err, count, idx;

    switch (json_object_get_type(aliasesJ)) {

    case json_type_array:
        /* extract array of aliases */
        count = (int)json_object_array_length(aliasesJ);
        aliases = calloc(count + 1, sizeof(oidcAliasT));
        if (aliases == NULL)
                goto OnErrorExit;

        for (idx = 0; idx < count; idx++) {
            json_object *aliasJ = json_object_array_get_idx(aliasesJ, idx);
            err = idpParseOneAlias(oidc, aliasJ, &aliases[idx]);
            if (err)
                goto OnErrorExit;
        }
        break;

    case json_type_object:
        /* extract single alias */
        aliases = calloc(2, sizeof(oidcAliasT));
        if (aliases == NULL)
                goto OnErrorExit;
        err = idpParseOneAlias(oidc, aliasesJ, &aliases[0]);
        if (err)
            goto OnErrorExit;
        break;

    default:
        EXT_CRITICAL(
            "[idp-aliases-error] idp=%s alias should be json_array|json_object "
            "(aliasParseConfig)",
            oidc->uid);
        goto OnErrorExit;
    }
    return aliases;

OnErrorExit:
    return NULL;
}
