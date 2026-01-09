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
    oidcStateT *state = (oidcStateT *)httpRqt->userData;
    int err;

    // something when wrong
    if (httpRqt->status != 200)
        goto OnErrorExit;

    // unwrap user profile
    json_object *orgsJ = json_tokener_parse(httpRqt->body.buffer);
    if (!orgsJ || !json_object_is_type(orgsJ, json_type_array))
        goto OnErrorExit;
    size_t count = json_object_array_length(orgsJ);
    const char **attrs = calloc(count + 1, sizeof(char *));
    for (int idx = 0; idx < count; idx++) {
        json_object *orgJ = json_object_array_get_idx(orgsJ, idx);
        attrs[idx] = json_object_dup_key_value(orgJ, "login");
    }
    state->fedSocial->attrs = attrs;

    // we've got everything check federated user now
    err = fedidCheck(state);
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
static void githubGetAttrsByToken(oidcStateT *state, const char *orgApiUrl)
{
    const oidcIdpT *idp = oidcStateGetIdp(state);

    httpKeyValT authToken[] = {
        {.tag = "Authorization", .value = oidcStateGetBearer(state)},
        {NULL}  // terminator
    };

    // asynchronous wreq to IDP user profile
    // https://docs.github.com/en/rest/reference/orgs#list-organizations-for-the-authenticated-user
    EXT_DEBUG("[idp-github] curl -H 'Authorization: %s' %s\n",
              oidcStateGetToken(state), orgApiUrl);
    int err = httpSendGet(oidcCoreHTTPPool(idp->oidc), orgApiUrl, &dfltOpts,
                          authToken, githubAttrsGetByTokenCB, state);
    if (err)
        EXT_ERROR("[idp-github] curl -H 'Authorization: %s' %s\n",
                  oidcStateGetToken(state), orgApiUrl);
    return;
}

// call when IDP respond to user profile wreq
// reference:
// https://docs.github.com/en/rest/reference/users#get-the-authenticated-user
static httpRqtActionT githubUserGetByTokenCB(const httpRqtT *httpRqt)
{
    oidcStateT *state = (oidcStateT *)httpRqt->userData;
    const oidcProfileT *profile = oidcStateGetProfile(state);
    const oidcIdpT *idp = oidcStateGetIdp(state);
    fedSocialRawT *fedSocial = NULL;
    fedUserRawT *fedUser = NULL;

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
                            get_object_string(profileJ, "company"), 0);

    state->fedSocial = fedSocial;
    state->fedUser = fedUser;

    // user is ok, let's map user organisation onto security attributes
    if (profile->attrs) {
        const char *organizationsUrl = json_object_get_string(
            json_object_object_get(profileJ, profile->attrs));
        if (organizationsUrl) {
            githubGetAttrsByToken(state, organizationsUrl);
        }
    }
    else {
        // no organisation attributes we've got everything check federated user
        // now
        int err = fedidCheck(state);
        if (err)
            goto OnErrorExit;
    }
    return HTTP_HANDLE_FREE;

OnErrorExit:
    EXT_CRITICAL(
        "[idp-github] Fail to get user profile from github "
        "status=%d body='%s'",
        httpRqt->status, httpRqt->body.buffer);
    afb_hreq_reply_error(oidcStateGetHttpReq(state), EXT_HTTP_UNAUTHORIZED);
    fedSocialUnRef(fedSocial);
    fedUserUnRef(fedUser);
    return HTTP_HANDLE_FREE;
}

// from acces token wreq user profile
// reference
// https://docs.github.com/en/developers/apps/authorizing-oauth-apps#web-application-flow
static void githubUserGetByToken(oidcStateT *state)
{
    const oidcIdpT *idp = oidcStateGetIdp(state);

    httpKeyValT authToken[] = {
        {.tag = "Authorization", .value = oidcStateGetBearer(state)},
        {NULL}  // terminator
    };

    // asynchronous wreq to IDP user profile
    // https://docs.github.com/en/rest/reference/orgs#list-organizations-for-the-authenticated-user
    EXT_DEBUG("[idp-github] curl -H 'Authorization: %s' %s\n",
              oidcStateGetToken(state), idp->wellknown->userinfo);
    int err = httpSendGet(oidcCoreHTTPPool(idp->oidc), idp->wellknown->userinfo,
                          &dfltOpts, authToken, githubUserGetByTokenCB, state);
    if (err)
        goto OnErrorExit;
    return;

OnErrorExit:
    afb_hreq_reply_error(oidcStateGetHttpReq(state), EXT_HTTP_UNAUTHORIZED);
}

// call when github return a valid access_token
static httpRqtActionT githubAccessTokenCB(const httpRqtT *httpRqt)
{
    oidcStateT *state = (oidcStateT *)httpRqt->userData;
    oidcSessionT *session = oidcStateGetSession(state);
    const char *accessTok;

    // github returns
    // "access_token=ffefd8e2f7b0fbe2de25b54e6a415c92a15491b8&scope=user%3Aemail&token_type=bearer"
    if (httpRqt->status != 200) {
        EXT_ERROR("[idp-github] Getting token returned error %d",
                  httpRqt->status);
        goto OnErrorExit;
    }

    // we should have a valid token or something when wrong
    json_object *responseJ = json_tokener_parse(httpRqt->body.buffer);
    if (!responseJ) {
        EXT_ERROR("[idp-github] Can't parse response");
        EXT_INFO("[idp-github] response is: %s", httpRqt->body.buffer);
        goto OnErrorExit;
    }
    accessTok = get_object_string(responseJ, "access_token");
    json_object_put(responseJ);
    if (accessTok == NULL) {
        EXT_ERROR("[idp-github] No access token in response");
        goto OnErrorExit;
    }

    // save the access token
    if (oidcStatePutToken(state, accessTok) < 0) {
        EXT_ERROR("[idp-github] Allocation failed");
        goto OnErrorExit;
    }

    // we have our wreq token let's try to get user profile
    githubUserGetByToken(state);
    return HTTP_HANDLE_FREE;

OnErrorExit:
    afb_hreq_reply_error(oidcStateGetHttpReq(state), EXT_HTTP_UNAUTHORIZED);
    return HTTP_HANDLE_FREE;
}

static int githubOnCodeCB(struct afb_hreq *hreq,
                          const oidcIdpT *idp,
                          oidcSessionT *session,
                          oidcStateT *state)
{
    int err, status;
    char url[EXT_URL_MAX_LEN];
    char redirectUrl[EXT_HEADER_MAX_LEN];

    // check if wreq as a code
    const char *code = afb_hreq_get_argument(hreq, "code");
    if (code == NULL) {
        EXT_WARNING("[idp-github] code is missing");
        goto OnErrorExit;
    }

    // add afb-binder endpoint to login redirect alias
    status = afb_hreq_make_here_url(hreq, idp->statics->aliasLogin, redirectUrl,
                                    sizeof(redirectUrl));
    if (status < 0) {
        EXT_WARNING("[idp-github] can't compute redirect url");
        goto OnErrorExit;
    }

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

    // send asynchronous post wreq with params in query //
    // https://gist.github.com/technoweenie/419219
    size_t sz = rp_escape_url_to(NULL, idp->wellknown->tokenid, params, url,
                                 sizeof url);
    if (sz >= sizeof url)
        goto OnErrorExit;

    EXT_DEBUG("[idp-github] curl -X post %s\n", url);
    err = httpSendPost(oidcCoreHTTPPool(idp->oidc), url, &dfltOpts,
                       NULL /*headers */, NULL /*data */, 0 /*length */,
                       githubAccessTokenCB, state);
    if (err) {
    OnErrorExit:
        afb_hreq_reply_error(hreq, EXT_HTTP_SERVER_ERROR);
    }

    return 1;
}

// this check idp code and either wreq profile or redirect to idp login page
static int githubLoginCB(struct afb_hreq *hreq, void *ctx)
{
    const oidcIdpT *idp = (const oidcIdpT *)ctx;
    return idpOnLoginPage(hreq, idp, githubOnCodeCB, idp->wellknown->authorize,
                          idp->statics->aliasLogin, idp->credentials->clientId,
                          "code", NULL);
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
