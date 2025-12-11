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
 *
 *  References:
 * https://docs.github.com/en/developers/apps/authorizing-oauth-apps#web-application-flow
 */

#define _GNU_SOURCE

#include <rp-utils/rp-escape.h>

#include <libafb/afb-core.h>
#include <libafb/afb-http.h>
#include <libafb/afb-v4.h>

#include "curl-glue.h"
#include "oidc-alias.h"
#include "oidc-core.h"
#include "oidc-fedid.h"
#include "oidc-idp.h"
#include "oidc-session.h"

#include <assert.h>
#include <locale.h>
#include <string.h>

static const httpKeyValT dfltHeaders[] = {
    {.tag = "Content-type", .value = "application/x-www-form-urlencoded"},
    {.tag = "Accept", .value = "application/json"},
    {NULL}  // terminator
};

static const oidcProfileT dfltProfiles[] = {
    {.loa = 1, .scope = "user,email"},
    {NULL}  // terminator
};

static const oidcWellknownT dfltWellknown = {
    .tokenid = "https://github.com/login/oauth/authorize",
    .authorize = "https://github.com/login/oauth/access_token",
    .userinfo = "https://api.github.com/user",
    .respondType = IDP_RESPOND_TYPE_CODE,
    .respondLabel = "code",
};

static const oidcStaticsT dfltstatics = {
    .aliasLogin = "/sgate/github/login",
    .aliasLogo = "/sgate/github/logo-64px.png",
    .sTimeout = 600};

static httpOptsT dfltOpts = {
    .agent = HTTP_DFLT_AGENT,
    .headers = dfltHeaders,
    .follow = 1,
    .timeout = 10,  // default authentication timeout
    // .verbose=1
};

// duplicate key value if not null
static char *json_object_dup_key_value(json_object *objJ, const char *key)
{
    char *value;
    value = (char *)json_object_get_string(json_object_object_get(objJ, key));
    if (value)
        value = strdup(value);
    return value;
}

// call when IDP respond to user profile wreq
// reference:
// https://docs.github.com/en/rest/reference/users#get-the-authenticated-user
static httpRqtActionT githubAttrsGetByTokenCB(httpRqtT *httpRqt)
{
    idpRqtCtxT *rqtCtx = (idpRqtCtxT *)httpRqt->userData;
    int err;

    // something when wrong
    if (httpRqt->status != 200)
        goto OnErrorExit;

    // unwrap user profile
    json_object *orgsJ = json_tokener_parse(httpRqt->body);
    if (!orgsJ || !json_object_is_type(orgsJ, json_type_array))
        goto OnErrorExit;
    size_t count = json_object_array_length(orgsJ);
    rqtCtx->fedSocial->attrs = calloc(count + 1, sizeof(char *));
    for (int idx = 0; idx < count; idx++) {
        json_object *orgJ = json_object_array_get_idx(orgsJ, idx);
        rqtCtx->fedSocial->attrs[idx] =
            json_object_dup_key_value(orgJ, "login");
    }

    // we've got everything check federated user now
    err = fedidCheck(rqtCtx);
    if (err)
        goto OnErrorExit;

    return HTTP_HANDLE_FREE;

OnErrorExit:
    EXT_CRITICAL(
        "[github-fail-orgs] Fail to get user organisation status=%ld body='%s'",
        httpRqt->status, httpRqt->body);
    return HTTP_HANDLE_FREE;
}

// reference
// https://docs.github.com/en/developers/apps/authorizing-oauth-apps#web-application-flow
static void githubGetAttrsByToken(idpRqtCtxT *rqtCtx, const char *orgApiUrl)
{
    char tokenVal[EXT_TOKEN_MAX_LEN];
    oidcIdpT *idp = rqtCtx->idp;
    rqtCtx->ucount++;

    snprintf(tokenVal, sizeof(tokenVal), "token %s", rqtCtx->token);
    httpKeyValT authToken[] = {
        {.tag = "Authorization", .value = tokenVal}, {NULL}  // terminator
    };

    // asynchronous wreq to IDP user profile
    // https://docs.github.com/en/rest/reference/orgs#list-organizations-for-the-authenticated-user
    EXT_DEBUG("[github-attrs-get] curl -H 'Authorization: %s' %s\n", tokenVal,
              orgApiUrl);
    int err = httpSendGet(idp->oidc->httpPool, orgApiUrl, &dfltOpts, authToken,
                          githubAttrsGetByTokenCB, rqtCtx);
    if (err)
        EXT_ERROR("[github-attrs-fail] curl -H 'Authorization: %s' %s\n",
                  tokenVal, orgApiUrl);
    return;
}

// call when IDP respond to user profile wreq
// reference:
// https://docs.github.com/en/rest/reference/users#get-the-authenticated-user
static httpRqtActionT githubUserGetByTokenCB(httpRqtT *httpRqt)
{
    idpRqtCtxT *rqtCtx = (idpRqtCtxT *)httpRqt->userData;
    oidcIdpT *idp = rqtCtx->idp;
    fedSocialRawT *fedSocial = NULL;
    fedUserRawT *fedUser = NULL;
    int err;

    // something when wrong
    if (httpRqt->status != 200)
        goto OnErrorExit;

    // unwrap user profile
    json_object *profileJ = json_tokener_parse(httpRqt->body);
    if (!profileJ)
        goto OnErrorExit;

    // build social fedkey from idp->uid+github->id
    fedSocial = calloc(1, sizeof(fedSocialRawT));
    fedSocial->fedkey = json_object_dup_key_value(profileJ, "id");
    fedSocial->idp = strdup(idp->uid);
    rqtCtx->fedSocial = fedSocial;

    fedUser = calloc(1, sizeof(fedUserRawT));
    fedUser->pseudo = json_object_dup_key_value(profileJ, "login");
    fedUser->avatar = json_object_dup_key_value(profileJ, "avatar_url");
    fedUser->name = json_object_dup_key_value(profileJ, "name");
    fedUser->company = json_object_dup_key_value(profileJ, "company");
    fedUser->email = json_object_dup_key_value(profileJ, "email");
    rqtCtx->fedUser = fedUser;

    // user is ok, let's map user organisation onto security attributes
    if (rqtCtx->profile->attrs) {
        const char *organizationsUrl = json_object_get_string(
            json_object_object_get(profileJ, rqtCtx->profile->attrs));
        if (organizationsUrl) {
            githubGetAttrsByToken(rqtCtx, organizationsUrl);
        }
    }
    else {
        // no organisation attributes we've got everything check federated user
        // now
        err = fedidCheck(rqtCtx);
        if (err)
            goto OnErrorExit;
    }
    return HTTP_HANDLE_FREE;

OnErrorExit:
    EXT_CRITICAL(
        "[github-fail-user-profile] Fail to get user profile from github "
        "status=%ld body='%s'",
        httpRqt->status, httpRqt->body);
    afb_hreq_reply_error(rqtCtx->hreq, EXT_HTTP_UNAUTHORIZED);
    fedSocialUnRef(fedSocial);
    fedUserUnRef(fedUser);
    return HTTP_HANDLE_FREE;
}

// from acces token wreq user profile
// reference
// https://docs.github.com/en/developers/apps/authorizing-oauth-apps#web-application-flow
static void githubUserGetByToken(idpRqtCtxT *rqtCtx)
{
    char tokenVal[EXT_TOKEN_MAX_LEN];
    oidcIdpT *idp = rqtCtx->idp;

    snprintf(tokenVal, sizeof(tokenVal), "token %s", rqtCtx->token);
    httpKeyValT authToken[] = {
        {.tag = "Authorization", .value = tokenVal}, {NULL}  // terminator
    };

    // asynchronous wreq to IDP user profile
    // https://docs.github.com/en/rest/reference/orgs#list-organizations-for-the-authenticated-user
    EXT_DEBUG("[github-profile-get] curl -H 'Authorization: %s' %s\n", tokenVal,
              idp->wellknown->userinfo);
    int err = httpSendGet(idp->oidc->httpPool, idp->wellknown->userinfo,
                          &dfltOpts, authToken, githubUserGetByTokenCB, rqtCtx);
    if (err)
        goto OnErrorExit;
    return;

OnErrorExit:
    afb_hreq_reply_error(rqtCtx->hreq, EXT_HTTP_UNAUTHORIZED);
    afb_hreq_unref(rqtCtx->hreq);
}

// call when github return a valid access_token
static httpRqtActionT githubAccessTokenCB(httpRqtT *httpRqt)
{
    assert(httpRqt->magic == MAGIC_HTTP_RQT);
    idpRqtCtxT *rqtCtx = (idpRqtCtxT *)httpRqt->userData;

    // github returns
    // "access_token=ffefd8e2f7b0fbe2de25b54e6a415c92a15491b8&scope=user%3Aemail&token_type=bearer"
    if (httpRqt->status != 200)
        goto OnErrorExit;

    // we should have a valid token or something when wrong
    json_object *responseJ = json_tokener_parse(httpRqt->body);
    if (!responseJ)
        goto OnErrorExit;

    rqtCtx->token = json_object_dup_key_value(responseJ, "access_token");
    if (!rqtCtx->token)
        goto OnErrorExit;

    // we have our wreq token let's try to get user profile
    githubUserGetByToken(rqtCtx);

    // callback is responsible to free wreq & context
    json_object_put(responseJ);
    return HTTP_HANDLE_FREE;

OnErrorExit:
    EXT_CRITICAL(
        "[fail-access-token] Fail to process response from github status=%ld "
        "body='%s' (githubAccessTokenCB)",
        httpRqt->status, httpRqt->body);
    afb_hreq_reply_error(rqtCtx->hreq, EXT_HTTP_UNAUTHORIZED);
    return HTTP_HANDLE_FREE;
}

static int githubAccessToken(afb_hreq *hreq,
                             oidcIdpT *idp,
                             const char *redirectUrl,
                             const char *code,
                             oidcSessionT *session)
{
    assert(idp->magic == MAGIC_OIDC_IDP);
    char url[EXT_URL_MAX_LEN];
    oidcCoreHdlT *oidc = idp->oidc;
    int err;

    const char *params[] = {
        "client_id",
        idp->credentials->clientId,
        "client_secret",
        idp->credentials->secret,
        "code",
        code,
        "redirect_uri",
        redirectUrl,
        "state",
        oidcSessionUUID(session),
        NULL  // terminator
    };

    idpRqtCtxT *rqtCtx = calloc(1, sizeof(idpRqtCtxT));
    // afb_hreq_addref (hreq); // prevent automatic href liberation
    rqtCtx->hreq = hreq;
    rqtCtx->idp = idp;
    rqtCtx->profile = oidcSessionGetIdpProfile(session);
    if (rqtCtx->profile == NULL)
        goto OnErrorExit;

    // send asynchronous post wreq with params in query //
    // https://gist.github.com/technoweenie/419219

    size_t sz = rp_escape_url_to(NULL, idp->wellknown->tokenid, params, url,
                                 sizeof url);
    if (sz >= sizeof url)
        goto OnErrorExit;

    EXT_DEBUG("[github-access-token] curl -X post %s\n", url);
    err = httpSendPost(oidc->httpPool, url, &dfltOpts, NULL /*token */,
                       (void *)1 /*post */, 0 /*no data */, githubAccessTokenCB,
                       rqtCtx);
    if (err)
        goto OnErrorExit;

    return 0;

OnErrorExit:
    afb_hreq_reply_error(hreq, EXT_HTTP_UNAUTHORIZED);
    return 1;
}

// this check idp code and either wreq profile or redirect to idp login page
static int githubLoginCB(afb_hreq *hreq, void *ctx)
{
    oidcIdpT *idp = (oidcIdpT *)ctx;
    assert(idp->magic == MAGIC_OIDC_IDP);
    char redirectUrl[EXT_HEADER_MAX_LEN];
    const oidcProfileT *profile = NULL;
    const oidcAliasT *alias = NULL;
    int err, status, aliasLoa;

    // check if wreq as a code
    const char *code = afb_hreq_get_argument(hreq, "code");
    oidcSessionT *session = oidcSessionOfHttpReq(hreq);
    const char *uuid = oidcSessionUUID(session);
    alias = oidcSessionGetAlias(session);
    if (alias)
        aliasLoa = alias->loa;
    else
        aliasLoa = 0;

    // add afb-binder endpoint to login redirect alias
    status = afb_hreq_make_here_url(hreq, idp->statics->aliasLogin, redirectUrl,
                                    sizeof(redirectUrl));
    if (status < 0)
        goto OnErrorExit;

    // if no code then set state and redirect to IDP
    if (!code) {
        char url[EXT_URL_MAX_LEN];
        const char *scope = afb_hreq_get_argument(hreq, "scope");

        // search for a scope fiting wreqing loa
        for (int idx = 0; idp->profiles[idx].uid; idx++) {
            if (idp->profiles[idx].loa >= aliasLoa) {
                // if no scope take the 1st profile with valid LOA
                if (scope && (strcmp(scope, idp->profiles[idx].scope)))
                    continue;
                profile = &idp->profiles[idx];
                break;
            }
        }

        // if loa working and no profile fit exit without trying authentication
        if (!profile)
            goto OnErrorExit;

        // store working profile to retreive attached loa and role filter if
        // login succeded
        oidcSessionSetIdpProfile(session, profile);

        const char *params[] = {
            "client_id",
            idp->credentials->clientId,
            "response_type",
            "code",
            "state",
            uuid,
            "scope",
            profile->scope,
            "redirect_uri",
            redirectUrl,
#if FORCELANG
            "language",
            setlocale(LC_CTYPE, ""),
#endif
            NULL  // terminator
        };

        // build wreq and send it
        size_t sz = rp_escape_url_to(NULL, idp->wellknown->authorize, params,
                                     url, sizeof url);
        if (sz >= sizeof url)
            goto OnErrorExit;

        EXT_DEBUG("[github-redirect-url] %s (githubRegisterAlias)", url);
        afb_hreq_redirect_to(hreq, url, HREQ_QUERY_EXCL, HREQ_REDIR_TMPY);
    }
    else {
        // check question/response state match
        const char *oidcState = afb_hreq_get_argument(hreq, "state");
        if (strcmp(oidcState, uuid)) {
            EXT_DEBUG(
                "[github-auth-code] missmatch uuid/state state=%s "
                "uuid=%s (githubRegisterAlias)",
                oidcState, uuid);
            goto OnErrorExit;
        }

        EXT_DEBUG("[github-auth-code] state=%s code=%s (githubRegisterAlias)",
                  oidcState, code);
        // wreq authentication token from tempry code
        err = githubAccessToken(hreq, idp, redirectUrl, code, session);
        if (err)
            goto OnErrorExit;
    }
    return 1;  // we're done (0 would search for an html page)

OnErrorExit:
    afb_hreq_reply_error(hreq, EXT_HTTP_UNAUTHORIZED);
    return 1;
}

static int githubRegisterAlias(oidcIdpT *idp, afb_hsrv *hsrv)
{
    int err;
    EXT_DEBUG("[github-register-alias] uid=%s login='%s'", idp->uid,
              idp->statics->aliasLogin);

    err = afb_hsrv_add_handler(hsrv, idp->statics->aliasLogin, githubLoginCB,
                               idp, EXT_HIGHEST_PRIO);
    if (!err)
        goto OnErrorExit;

    return 0;

OnErrorExit:
    EXT_ERROR(
        "[github-register-alias] idp=%s fail to register alias=%s "
        "(githubRegisterAlias)",
        idp->uid, idp->statics->aliasLogin);
    return 1;
}

// github is openid compliant. Provide default and delegate parsing to default
// ParseOidcConfigCB
static int githubRegisterConfig(oidcIdpT *idp, json_object *configJ)
{
    oidcDefaultsT defaults = {
        .credentials = NULL,
        .statics = &dfltstatics,
        .wellknown = &dfltWellknown,
        .profiles = dfltProfiles,
        .headers = dfltHeaders,
    };
    int err = idpParseOidcConfig(idp, configJ, &defaults, NULL);
    if (err)
        goto OnErrorExit;

    // if timeout defined
    if (idp->credentials->timeout)
        dfltOpts.timeout = idp->credentials->timeout;

    return 0;

OnErrorExit:
    return 1;
}

//----------------------------------------------------------------
// Description
//----------------------------------------------------------------
const idpPluginT githubPluginDesc = {
    .uid = "github",
    .info = "github public oauth2 idp",
    .registerConfig = githubRegisterConfig,
    .registerAlias = githubRegisterAlias
};


