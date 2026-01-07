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
 *
 *  References:
 * https://docs.github.com/en/developers/apps/authorizing-oauth-apps#web-application-flow
 */

#define _GNU_SOURCE

#include "idp-github.h"

#include <assert.h>
#include <locale.h>
#include <string.h>

#include <rp-utils/rp-escape.h>

#include <libafb/afb-core.h>
#include <libafb/afb-http.h>
#include <libafb/afb-v4.h>

#include "curl-glue.h"
#include "oidc-core.h"
#include "oidc-fedid.h"
#include "oidc-idp.h"
#include "oidc-session.h"

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

// string key value if exist
static const char *get_object_string(json_object *objJ, const char *key)
{
    json_object *valJ;
    if (!json_object_object_get_ex(objJ, key, &valJ) || valJ == NULL)
        return NULL;
    return json_object_get_string(valJ);
}

// duplicate key value if not null
static char *json_object_dup_key_value(json_object *objJ, const char *key)
{
    const char *str = get_object_string(objJ, key);
    return str == NULL ? NULL : strdup(str);
}

// call when IDP respond to user profile wreq
// reference:
// https://docs.github.com/en/rest/reference/users#get-the-authenticated-user
static httpRqtActionT githubAttrsGetByTokenCB(const httpRqtT *httpRqt)
{
    idpRqtCtxT *rqtCtx = (idpRqtCtxT *)httpRqt->userData;
    int err;

    // something when wrong
    if (httpRqt->status != 200)
        goto OnErrorExit;

    // unwrap user profile
    json_object *orgsJ = json_tokener_parse(httpRqt->body.buffer);
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
        "[idp-github] Fail to get user organisation status=%d body='%s'",
        httpRqt->status, httpRqt->body.buffer);
    return HTTP_HANDLE_FREE;
}

// reference
// https://docs.github.com/en/developers/apps/authorizing-oauth-apps#web-application-flow
static void githubGetAttrsByToken(idpRqtCtxT *rqtCtx, const char *orgApiUrl)
{
    char tokenVal[EXT_TOKEN_MAX_LEN];
    const oidcIdpT *idp = rqtCtx->idp;
    rqtCtx->ucount++;

    snprintf(tokenVal, sizeof(tokenVal), "Bearer %s", rqtCtx->token);
    httpKeyValT authToken[] = {
        {.tag = "Authorization", .value = tokenVal}, {NULL}  // terminator
    };

    // asynchronous wreq to IDP user profile
    // https://docs.github.com/en/rest/reference/orgs#list-organizations-for-the-authenticated-user
    EXT_DEBUG("[idp-github] curl -H 'Authorization: %s' %s\n", tokenVal,
              orgApiUrl);
    int err = httpSendGet(oidcCoreHTTPPool(idp->oidc), orgApiUrl, &dfltOpts,
                          authToken, githubAttrsGetByTokenCB, rqtCtx);
    if (err)
        EXT_ERROR("[idp-github] curl -H 'Authorization: %s' %s\n", tokenVal,
                  orgApiUrl);
    return;
}

// call when IDP respond to user profile wreq
// reference:
// https://docs.github.com/en/rest/reference/users#get-the-authenticated-user
static httpRqtActionT githubUserGetByTokenCB(const httpRqtT *httpRqt)
{
    idpRqtCtxT *rqtCtx = (idpRqtCtxT *)httpRqt->userData;
    const oidcIdpT *idp = rqtCtx->idp;
    fedSocialRawT *fedSocial = NULL;
    fedUserRawT *fedUser = NULL;
    int err;

    // something when wrong
    if (httpRqt->status != 200)
        goto OnErrorExit;

    // unwrap user profile
    json_object *profileJ = json_tokener_parse(httpRqt->body.buffer);
    if (!profileJ)
        goto OnErrorExit;

    // build social fedkey from idp->uid+github->id
    fedSocial = fedSocialCreate(idp->uid, get_object_string(profileJ, "id"), 0);
    fedUser = fedUserCreate(get_object_string(profileJ, "login"),
                            get_object_string(profileJ, "email"),
                            get_object_string(profileJ, "name"),
                            get_object_string(profileJ, "avatar_url"),
                            get_object_string(profileJ, "company"),
                            0);

    rqtCtx->fedSocial = fedSocial;
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
        "[idp-github] Fail to get user profile from github "
        "status=%d body='%s'",
        httpRqt->status, httpRqt->body.buffer);
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
    const oidcIdpT *idp = rqtCtx->idp;

    snprintf(tokenVal, sizeof(tokenVal), "Bearer %s", rqtCtx->token);
    httpKeyValT authToken[] = {
        {.tag = "Authorization", .value = tokenVal}, {NULL}  // terminator
    };

    // asynchronous wreq to IDP user profile
    // https://docs.github.com/en/rest/reference/orgs#list-organizations-for-the-authenticated-user
    EXT_DEBUG("[idp-github] curl -H 'Authorization: %s' %s\n", tokenVal,
              idp->wellknown->userinfo);
    int err = httpSendGet(oidcCoreHTTPPool(idp->oidc), idp->wellknown->userinfo,
                          &dfltOpts, authToken, githubUserGetByTokenCB, rqtCtx);
    if (err)
        goto OnErrorExit;
    return;

OnErrorExit:
    afb_hreq_reply_error(rqtCtx->hreq, EXT_HTTP_UNAUTHORIZED);
    afb_hreq_unref(rqtCtx->hreq);
}

// call when github return a valid access_token
static httpRqtActionT githubAccessTokenCB(const httpRqtT *httpRqt)
{
    idpRqtCtxT *rqtCtx = (idpRqtCtxT *)httpRqt->userData;

    // github returns
    // "access_token=ffefd8e2f7b0fbe2de25b54e6a415c92a15491b8&scope=user%3Aemail&token_type=bearer"
    if (httpRqt->status != 200)
        goto OnErrorExit;

    // we should have a valid token or something when wrong
    json_object *responseJ = json_tokener_parse(httpRqt->body.buffer);
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
        "[idp-github] Fail to process response from github status=%d "
        "body='%s' (githubAccessTokenCB)",
        httpRqt->status, httpRqt->body.buffer);
    afb_hreq_reply_error(rqtCtx->hreq, EXT_HTTP_UNAUTHORIZED);
    return HTTP_HANDLE_FREE;
}

static int githubAccessToken(struct afb_hreq *hreq,
                             const oidcIdpT *idp,
                             const char *redirectUrl,
                             const char *code,
                             oidcSessionT *session)
{
    char url[EXT_URL_MAX_LEN];
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
    rqtCtx->profile = oidcSessionGetTargetProfile(session);
    if (rqtCtx->profile == NULL)
        goto OnErrorExit;

    // send asynchronous post wreq with params in query //
    // https://gist.github.com/technoweenie/419219

    size_t sz = rp_escape_url_to(NULL, idp->wellknown->tokenid, params, url,
                                 sizeof url);
    if (sz >= sizeof url)
        goto OnErrorExit;

    EXT_DEBUG("[idp-github] curl -X post %s\n", url);
    err = httpSendPost(oidcCoreHTTPPool(idp->oidc), url, &dfltOpts,
                       NULL /*headers */, NULL /*data */, 0 /*length */,
                       githubAccessTokenCB, rqtCtx);
    if (err)
        goto OnErrorExit;

    return 0;

OnErrorExit:
    afb_hreq_reply_error(hreq, EXT_HTTP_SERVER_ERROR);
    return 1;
}

// this check idp code and either wreq profile or redirect to idp login page
static int githubLoginCB(struct afb_hreq *hreq, void *ctx)
{
    const oidcIdpT *idp = (const oidcIdpT *)ctx;
    char redirectUrl[EXT_HEADER_MAX_LEN];
    int err, status;

    // check if wreq as a code
    const char *code = afb_hreq_get_argument(hreq, "code");
    oidcSessionT *session = oidcSessionOfHttpReq(hreq);

    // if no code then set state and redirect to IDP
    if (code == NULL) {
        return idpRedirectLogin(idp, hreq, session, idp->wellknown->authorize,
                                idp->statics->aliasLogin,
                                idp->credentials->clientId, "code", NULL);
    }

    // check question/response state match
    const char *uuid = oidcSessionUUID(session);
    const char *oidcState = afb_hreq_get_argument(hreq, "state");
    if (strcmp(oidcState, uuid)) {
        EXT_WARNING("[idp-github] state mismatch recv=%s expect=%s", oidcState,
                    uuid);
        goto OnErrorExit;
    }

    // add afb-binder endpoint to login redirect alias
    status = afb_hreq_make_here_url(hreq, idp->statics->aliasLogin, redirectUrl,
                                    sizeof(redirectUrl));
    if (status < 0)
        goto OnErrorExit;

    // wreq authentication token from tempory code
    EXT_DEBUG("[idp-github] authorized state=%s code=%s", oidcState, code);
    githubAccessToken(hreq, idp, redirectUrl, code, session);
    return 1;

OnErrorExit:
    afb_hreq_reply_error(hreq, EXT_HTTP_SERVER_ERROR);
    return 1;
}

static int githubRegisterAlias(const oidcIdpT *idp, struct afb_hsrv *hsrv)
{
    int rc;

    EXT_DEBUG("[idp-github] uid=%s login='%s'", idp->uid,
              idp->statics->aliasLogin);

    rc = afb_hsrv_add_handler(hsrv, idp->statics->aliasLogin, githubLoginCB,
                              (void *)idp, EXT_HIGHEST_PRIO);
    if (rc)
        return 0;

    EXT_ERROR("[idp-github] fail to register alias=%s",
              idp->statics->aliasLogin);
    return -1;
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
        return -1;

    // if timeout defined
    if (idp->credentials->timeout)
        dfltOpts.timeout = idp->credentials->timeout;

    return 0;
}

//----------------------------------------------------------------
// Description
//----------------------------------------------------------------
const idpPluginT githubPluginDesc = {.uid = "github",
                                     .info = "github public oauth2 idp",
                                     .registerConfig = githubRegisterConfig,
                                     .registerAlias = githubRegisterAlias};
