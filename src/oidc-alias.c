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

#include <libafb/afb-core.h>
#include <libafb/afb-http.h>
#include <libafb/afb-v4.h>

#include "curl-glue.h"
#include "oidc-alias.h"
#include "oidc-core.h"
#include "oidc-fedid.h"
#include "oidc-idsvc.h"

// dummy unique value for session key
MAGIC_OIDC_SESSION(oidcSessionCookie);
MAGIC_OIDC_SESSION(oidcAliasCookie);

// check if one of requested role exist within social cookie
int aliasCheckAttrs(afb_session *session, oidcAliasT *alias)
{
    fedSocialRawT *fedSocial;
    int err, requestCount = 0, matchCount = 0;

    // search within profile if we have the right role
    err = afb_session_cookie_get(session, oidcFedSocialCookie,
                                 (void **)&fedSocial);
    if (err < 0)
        goto OnErrorExit;

    // this should be replaced by Cynagora request
    for (int idx = 0; alias->roles[idx]; idx++) {
        requestCount++;
        if (fedSocial->attrs)
            for (int jdx = 0; fedSocial->attrs[jdx]; jdx++) {
                if (!strcasecmp(alias->roles[idx], fedSocial->attrs[jdx])) {
                    matchCount++;
                    break;
                }
            }
        if (matchCount)
            break;
    }
    if (!matchCount)
        goto OnErrorExit;
    return 0;

OnErrorExit:
    return 1;
};

// create aliasFrom cookie and redirect to idp profile page
static void aliasRedirectTimeout(afb_hreq *hreq, oidcAliasT *alias)
{
    oidcProfileT *profile;
    int err;

    afb_session_cookie_set(hreq->comreq.session, oidcAliasCookie, alias, NULL,
                           NULL);
    afb_session_cookie_get(hreq->comreq.session, oidcIdpProfilCookie,
                           (void **)&profile);

    // add afb-binder endpoint to login redirect alias
    char redirectUrl[EXT_HEADER_MAX_LEN];
    err = afb_hreq_make_here_url(hreq, profile->idp->statics->aliasLogin,
                                 redirectUrl, sizeof(redirectUrl));
    if (err < 0)
        goto OnErrorExit;

    char url[EXT_URL_MAX_LEN];
    httpKeyValT query[] = {
        {.tag = "client_id", .value = profile->idp->credentials->clientId},
        {.tag = "response_type",
         .value = profile->idp->wellknown->respondLabel},
        {.tag = "state", .value = afb_session_uuid(hreq->comreq.session)},
        {.tag = "scope", .value = profile->scope},
        {.tag = "redirect_uri", .value = redirectUrl},
        {.tag = "language", .value = setlocale(LC_CTYPE, "")},
        {NULL}  // terminator
    };

    err = httpBuildQuery(alias->uid, url, sizeof(url), NULL /* prefix */,
                         profile->idp->statics->aliasLogin, query);
    if (err) {
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

    afb_session_cookie_set(hreq->comreq.session, oidcAliasCookie, alias, NULL,
                           NULL);

    if (alias->oidc->globals->loginUrl) {
        httpKeyValT query[] = {
            {.tag = "language", .value = setlocale(LC_CTYPE, "")},
            {NULL}  // terminator
        };

        err = httpBuildQuery(alias->uid, url, sizeof(url), NULL /* prefix */,
                             alias->oidc->globals->loginUrl, query);
        if (err) {
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
        const char *session = afb_session_uuid(hreq->comreq.session);
        char redirectUrl[EXT_HEADER_MAX_LEN];

        status = afb_hreq_make_here_url(hreq, idp->statics->aliasLogin,
                                        redirectUrl, sizeof(redirectUrl));
        if (status < 0)
            goto OnErrorExit;

        httpKeyValT query[] = {
            {.tag = "client_id", .value = idp->credentials->clientId},
            {.tag = "response_type", .value = idp->wellknown->respondLabel},
            {.tag = "state", .value = session},
            {.tag = "nonce", .value = session},
            {.tag = "scope", .value = profile->scope},
            {.tag = "redirect_uri", .value = redirectUrl},
            {.tag = "language", .value = setlocale(LC_CTYPE, "")},
            {NULL}  // terminator
        };

        // build wreq and send it
        err = httpBuildQuery(idp->uid, url, sizeof(url), NULL /* prefix */,
                             idp->wellknown->authorize, query);
        if (err)
            goto OnErrorExit;

        // keep track of selected idp profile
        afb_session_cookie_set(hreq->comreq.session, oidcIdpProfilCookie,
                               (void *)profile, NULL, NULL);
    }
    EXT_DEBUG("[alias-redirect-login] %s (aliasRedirectLogin)", url);
    afb_hreq_redirect_to(hreq, url, HREQ_QUERY_EXCL, HREQ_REDIR_TMPY);
    return;

OnErrorExit:
    afb_hreq_redirect_to(hreq, alias->oidc->globals->loginUrl, HREQ_QUERY_EXCL,
                         HREQ_REDIR_TMPY);
}

static int aliasCheckLoaCB(afb_hreq *hreq, void *ctx)
{
    oidcAliasT *alias = (oidcAliasT *)ctx;
    struct timespec tCurrent;
    oidcProfileT *idpProfile;
    int sessionLoa, tStamp, tNow, err;

    if (alias->loa) {
        // in case session create failed
        if (!hreq->comreq.session) {
            EXT_ERROR(
                "[fail-hreq-session] fail to initialise hreq session "
                "(aliasCheckLoaCB)");
            afb_hreq_reply_error(hreq, EXT_HTTP_CONFLICT);
            goto OnRedirectExit;
        }
        // if tCache not expired use jump authent check
        clock_gettime(CLOCK_MONOTONIC, &tCurrent);
        tNow = (int)((tCurrent.tv_nsec) / 1000000 + (tCurrent.tv_sec) * 1000) /
               100;
        tStamp = afb_session_get_loa(hreq->comreq.session, oidcAliasCookie);
        if (tNow > tStamp) {
            EXT_NOTICE("session uuid=%s (aliasCheckLoaCB)",
                       afb_session_uuid(hreq->comreq.session));

            // if LOA too weak redirect to authentication  //afb_session_close
            // ()
            sessionLoa =
                afb_session_get_loa(hreq->comreq.session, oidcSessionCookie);
            if (alias->loa > sessionLoa && sessionLoa != abs(alias->loa)) {
                json_object *eventJ;

                rp_jsonc_pack(&eventJ, "{ss ss ss si si}", "status",
                              "loa-mismatch", "uid", alias->uid, "url",
                              alias->url, "loa-target", alias->loa,
                              "loa-session", sessionLoa);

                // try to push event to notify the access deny and replay with
                // redirect to login
                idscvPushEvent(hreq->comreq.session, eventJ);

                // if current profile LOA is enough then fire same idp/profile
                // authen
                err = afb_session_cookie_get(hreq->comreq.session,
                                             oidcIdpProfilCookie,
                                             (void *)&idpProfile);
                if (!err && (idpProfile->loa >= alias->loa ||
                             idpProfile->loa == abs(alias->loa))) {
                    aliasRedirectTimeout(hreq, alias);
                }
                else {
                    aliasRedirectLogin(hreq, alias);
                }
                goto OnRedirectExit;
            }

            if (alias->roles) {
                int err = aliasCheckAttrs(hreq->comreq.session, alias);
                if (err) {
                    aliasRedirectLogin(hreq, alias);
                    goto OnRedirectExit;
                }
            }
            // store a sampstamp to cache authentication validation
            tStamp = (int)(tNow + alias->tCache / 100);
            afb_session_set_loa(hreq->comreq.session, oidcAliasCookie, tStamp);
        }
    }
    // change hreq bearer
    afb_req_common_set_token(&hreq->comreq, NULL);
    return 0;  // move forward and continue parsing lower priority alias

OnRedirectExit:
    return 1;  // we're done stop scanning alias callback
}

int aliasRegisterOne(oidcCoreHdlT *oidc, oidcAliasT *alias, afb_hsrv *hsrv)
{
    const char *rootdir;
    int status;

    if (alias->loa) {
        status = afb_hsrv_add_handler(hsrv, alias->url, aliasCheckLoaCB, alias,
                                      alias->priority);
        if (status != AFB_HSRV_OK)
            goto OnErrorExit;
    }
    // if alias full path does not start with '/' then prefix it with
    // http_root_dir
    if (alias->path[0] == '/')
        rootdir = "";
    else
        rootdir = afb_common_rootdir_get_path();

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

static int idpParseOneAlias(oidcCoreHdlT *oidc,
                            json_object *aliasJ,
                            oidcAliasT *alias)
{
    json_object *requirerJ = NULL;

    // set tCache default
    alias->tCache = oidc->globals->tCache;

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

    if (requirerJ) {
        const char **roles;
        int count;
        switch (json_object_get_type(requirerJ)) {
        case json_type_array:
            count = (int)json_object_array_length(requirerJ);
            roles = calloc(count + 1, sizeof(char *));

            for (int idx = 0; idx < count; idx++) {
                json_object *roleJ = json_object_array_get_idx(requirerJ, idx);
                roles[idx] = json_object_get_string(roleJ);
            }
            break;

        case json_type_object:
            roles = calloc(2, sizeof(char *));
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
    alias->oidc = oidc;
    return 0;

OnErrorExit:
    return 1;
}

oidcAliasT *aliasParseConfig(oidcCoreHdlT *oidc, json_object *aliasesJ)
{
    oidcAliasT *aliases;
    int err;

    switch (json_object_get_type(aliasesJ)) {
        int count;

    case json_type_array:
        count = (int)json_object_array_length(aliasesJ);
        aliases = calloc(count + 1, sizeof(oidcAliasT));

        for (int idx = 0; idx < count; idx++) {
            json_object *aliasJ = json_object_array_get_idx(aliasesJ, idx);
            err = idpParseOneAlias(oidc, aliasJ, &aliases[idx]);
            if (err)
                goto OnErrorExit;
        }
        break;

    case json_type_object:
        aliases = calloc(2, sizeof(oidcAliasT));
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
