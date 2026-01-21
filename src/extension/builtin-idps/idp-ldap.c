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
 */

#define _GNU_SOURCE

#include <assert.h>
#include <locale.h>
#include <string.h>

#include <rp-utils/rp-escape.h>
#include <rp-utils/rp-jsonc.h>

#include <libafb/afb-core.h>
#include <libafb/afb-http.h>
#include <libafb/afb-v4.h>

#include "curl-glue.h"
#include "oidc-core.h"
#include "oidc-fedid.h"
#include "oidc-idp-plugin.h"
#include "oidc-idp.h"
#include "oidc-session.h"
#include "oidc-utils.h"

typedef struct
{
    int gidsMax;
    int timeout;
    const char *avatarAlias;
    const char *login;
    const char *uri;
    char *people;
    char *groups;
} ldapOptsT;

// ldap context request handle for callbacks
typedef struct
{
    char *login;
    char *passwd;
    char *userdn;
    httpPoolT *httpPool;
    json_object *loginJ;
    oidcStateT *state;
    const ldapOptsT *ldapOpts;
} ldapRqtCtxT;

// provide dummy default values to oidc callbacks
static const oidcCredentialsT noCredentials = {};
static const httpKeyValT noHeaders = {};

// dflt_xxxx config.json default options
static ldapOptsT dfltLdap = {
    .gidsMax = 32,
    .timeout = 5,  // 5s default timeout
    .avatarAlias = "/sgate/ldap/avatar-dflt.png",
    .groups = NULL,
    .login = NULL,
};

static const oidcProfileT dfltProfiles[] = {
    {.loa = 1, .scope = "login"},
    {NULL}  // terminator
};

static const oidcStaticsT dfltstatics = {
    .aliasLogin = "/sgate/ldap/login",
    .aliasLogo = "/sgate/ldap/logo-64px.png",
    .sTimeout = 600};

static const oidcWellknownT dfltWellknown = {
    .tokenid = "/sgate/ldap/login.html",
    .userinfo = NULL,
    .authorize = NULL,
};

static void ldapRqtCtxFree(ldapRqtCtxT *ldapRqtCtx)
{
    free(ldapRqtCtx->login);
    free(ldapRqtCtx->passwd);
    free(ldapRqtCtx->userdn);
    json_object_put(ldapRqtCtx->loginJ);
    oidcStateUnRef(ldapRqtCtx->state);
    free(ldapRqtCtx);
}

static httpRqtActionT ldapAccessAttrsCB(const httpRqtT *httpRqt)
{
    ldapRqtCtxT *ldapRqtCtx = (ldapRqtCtxT *)httpRqt->userData;
    idpRqtCtxT *idpRqtCtx = ldapRqtCtx->state;
    const ldapOptsT *ldapOpts = ldapRqtCtx->ldapOpts;
    int err;

    // something when wrong
    if (httpRqt->status < 0)
        goto OnErrorExit;

    // unwrap user groups from LDIF buffer
    // DN: cn=fulup,ou=Groups,dc=vannes,dc=iot
    // DN: cn=admin,ou=Groups,dc=vannes,dc=iot
    // DN: cn=skipail,ou=Groups,dc=vannes,dc=iot
    // DN: cn=matomo,ou=Groups,dc=vannes,dc=iot

    // token not json
    static char DNString[] = "DN: ";
    static int DNLen = sizeof(DNString) - 1;
    static char cnString[] = "cn=";
    static int cnLen = sizeof(cnString) - 1;

    int idx = 0;
    const char *iter = strcasestr(httpRqt->body.buffer, DNString);
    idpRqtCtx->fedSocial->attrs = calloc(ldapOpts->gidsMax + 1, sizeof(char *));
    while (iter) {
        const char *line = iter + DNLen;
        const char *niter = strcasestr(line, DNString);
        const char *entry = strcasestr(line, cnString);
        if (niter == NULL || entry < niter) {
            const char *start = entry + cnLen;
            const char *end = start;
            while (*end != 0 && *end != ',' && *end != '\n')
                end++;
            if (idx == ldapOpts->gidsMax) {
                EXT_INFO("[idp-ldap] maxgids=%d too small, ignoring group %.*s",
                         ldapOpts->gidsMax, (int)(end - start), start);
            }
            else {
                unsigned len = (unsigned)(end - start);
                idpRqtCtx->fedSocial->attrs[idx++] = strndup(start, len);
            }
        }
        iter = niter;
    }

    // reduse groups attrs size to what ever is needed
    idpRqtCtx->fedSocial->attrs =
        realloc(idpRqtCtx->fedSocial->attrs, sizeof(char *) * (idx + 1));

    // query federation ldap groups are handle asynchronously
    err = fedidCheck(idpRqtCtx);
    if (err)
        goto OnErrorExit;

    // we done idpRqtCtx is cleared by fedidCheck
    ldapRqtCtxFree(ldapRqtCtx);

    return HTTP_HANDLE_FREE;

OnErrorExit:
    EXT_CRITICAL(
        "[ldap-fail-groups] Fail to get user groups status=%d body='%s'",
        httpRqt->status, httpRqt->body.buffer);
    return HTTP_HANDLE_FREE;
}

// reference
// https://docs.ldap.com/en/developers/apps/authorizing-oauth-apps#web-application-flow
static void ldapAccessAttrs(ldapRqtCtxT *ldapRqtCtx)
{
    const ldapOptsT *ldapOpts = ldapRqtCtx->ldapOpts;

    const char *curlQuery =
        utilsExpandJson(ldapOpts->groups, ldapRqtCtx->loginJ);
    if (!curlQuery) {
        EXT_CRITICAL(
            "[curl-query-fail] fail to build curl ldap groups query=%s missing "
            "'%%login%%'",
            ldapOpts->login);
        goto OnErrorExit;
    }
    // build curl ldap options structure
    httpOptsT curlOpts = {
        .username = ldapRqtCtx->userdn,
        .password = ldapRqtCtx->passwd,
    };

    // asynchronous wreq to LDAP to check passwd and retrieve user groups
    EXT_DEBUG("[curl-ldap-attrs] curl -u '%s:my_secret_passwd' '%s'",
              ldapRqtCtx->userdn, curlQuery);
    int err = httpSendGet(ldapRqtCtx->httpPool, curlQuery, &curlOpts, NULL,
                          ldapAccessAttrsCB, ldapRqtCtx);
    if (err)
        goto OnErrorExit;

    return;

OnErrorExit:
    EXT_ERROR("[curl-ldap-error] curl -u '%s:my_secret_passwd' '%s'",
              ldapRqtCtx->userdn, curlQuery);
    return;
}

// call after user authenticate
static httpRqtActionT ldapAccessProfileCB(const httpRqtT *httpRqt)
{
    static char errorMsg[] =
        "[ldap-fail-user-profile] Fail to get user profile from ldap "
        "(login/passwd ?)";
    ldapRqtCtxT *ldapRqtCtx = (ldapRqtCtxT *)httpRqt->userData;
    idpRqtCtxT *idpRqtCtx = ldapRqtCtx->state;
    const ldapOptsT *ldapOpts = ldapRqtCtx->ldapOpts;

    int err, start;
    char *value;
    afb_data_t reply;

    // reserve federation and social user structure
    idpRqtCtx->fedSocial = fedSocialCreate(idpRqtCtx->idp->uid, NULL, 0);
    idpRqtCtx->fedUser = calloc(1, sizeof(fedUserRawT));
    idpRqtCtx->fedUser->refcount = 1;

    // something when wrong
    if (httpRqt->status < 0)
        goto OnErrorExit;

    // nothing were replied
    if (httpRqt->body.length == 0 || httpRqt->body.buffer == NULL)
        goto OnErrorExit;

    // search for "DN:"
    static char dnString[] = "DN:";
    start = sizeof(dnString);
    value = strcasestr(httpRqt->body.buffer, dnString);
    if (!value)
        goto OnErrorExit;
    for (int idx = 0; value[idx]; idx++) {
        if (value[idx] == '\n') {
            value[idx] = '\0';
            idpRqtCtx->fedSocial->fedkey = strdup(&httpRqt->body.buffer[start]);
            start = idx + 1;
            break;
        }
    }

    // search for "pseudo:"
    static char uidString[] = "uid:";
    value = strcasestr(&httpRqt->body.buffer[start], uidString);
    if (value) {
        for (int idx = sizeof(uidString); value[idx]; idx++) {
            if (value[idx] == '\n') {
                idpRqtCtx->fedUser->pseudo =
                    strndup(&value[sizeof(uidString)], idx - sizeof(uidString));
                break;
            }
        }
    }
    // search for "fullname:"
    static char gecosString[] = "gecos:";
    value = strcasestr(&httpRqt->body.buffer[start], gecosString);
    if (value) {
        for (int idx = sizeof(gecosString); value[idx]; idx++) {
            if (value[idx] == '\n') {
                idpRqtCtx->fedUser->name = strndup(&value[sizeof(gecosString)],
                                                   idx - sizeof(gecosString));
                break;
            }
        }
    }
    // search for "email:"
    static char mailString[] = "mail:";
    value = strcasestr(&httpRqt->body.buffer[start], mailString);
    if (value) {
        for (int idx = +sizeof(mailString); value[idx]; idx++) {
            if (value[idx] == '\n') {
                idpRqtCtx->fedUser->email = strndup(&value[sizeof(mailString)],
                                                    idx - sizeof(mailString));
                break;
            }
        }
    }
    // user is ok, let's map user organisation onto security attributes
    if (ldapOpts->groups)
        ldapAccessAttrs(ldapRqtCtx);
    else {
        // query federation ldap groups are handle asynchronously
        err = fedidCheck(idpRqtCtx);
        if (err)
            goto OnErrorExit;

        // we done idpRqtCtx is cleared by fedidCheck
        ldapRqtCtxFree(ldapRqtCtx);
    }

    return HTTP_HANDLE_FREE;

OnErrorExit:
    EXT_CRITICAL("%s", errorMsg);

    if (idpRqtCtx->hreq) {
        afb_hreq_reply_error(idpRqtCtx->hreq, EXT_HTTP_UNAUTHORIZED);
    }
    else {
        afb_create_data_raw(&reply, AFB_PREDEFINED_TYPE_STRINGZ, errorMsg,
                            sizeof(errorMsg), NULL, NULL);
        afb_req_v4_reply_hookable(idpRqtCtx->wreq, -1, 1, &reply);
    }

    fedSocialUnRef(idpRqtCtx->fedSocial);
    fedUserUnRef(idpRqtCtx->fedUser);
    ldapRqtCtxFree(ldapRqtCtx);
    return HTTP_HANDLE_FREE;
}

// check ldap login/passwd scope is unused
static int ldapAccessProfile(oidcStateT *state,
                             const oidcIdpT *idp,
                             const char *login,
                             const char *passwd)
{
    int err;
    ldapOptsT *ldapOpts = (ldapOptsT *)idp->userData;

    // prepare context for curl callbacks
    ldapRqtCtxT *ldapRqtCtx = calloc(1, sizeof(ldapRqtCtxT));
    ldapRqtCtx->login = strdup(login);
    ldapRqtCtx->passwd = strdup(passwd);
    ldapRqtCtx->state = state;
    ldapRqtCtx->ldapOpts = ldapOpts;

    // place %%login%% with wreq.
    err = rp_jsonc_pack(&ldapRqtCtx->loginJ, "{ss}", "login", login);
    if (err)
        goto OnErrorExit;

    // complete userdn login for authentication
    ldapRqtCtx->userdn = utilsExpandJson(ldapOpts->login, ldapRqtCtx->loginJ);
    if (!ldapRqtCtx->userdn) {
        EXT_CRITICAL(
            "[curl-query-fail] fail to build curl ldap login=%s missing "
            "'%%login%%'",
            ldapOpts->login);
        goto OnErrorExit;
    }

    char *curlQuery = utilsExpandJson(ldapOpts->people, ldapRqtCtx->loginJ);
    if (!curlQuery) {
        EXT_CRITICAL(
            "[curl-query-fail] fail to build curl ldap query=%s missing "
            "'%%login%%'",
            ldapOpts->login);
        goto OnErrorExit;
    }
    // build curl ldap options structure
    httpOptsT curlOpts = {
        .username = ldapRqtCtx->userdn,
        .password = passwd,
        .timeout = (long)ldapOpts->timeout,
    };

    // asynchronous wreq to LDAP to check passwd and retrieve user groups
    EXT_DEBUG("[curl-ldap-profile] curl -u '%s:my_secret_passwd' '%s'\n",
              ldapRqtCtx->userdn, curlQuery);
    err = httpSendGet(ldapRqtCtx->httpPool, curlQuery, &curlOpts, NULL,
                      ldapAccessProfileCB, ldapRqtCtx);
    if (err)
        goto OnErrorExit;

    return 0;

OnErrorExit:
    ldapRqtCtxFree(ldapRqtCtx);
    return 1;
}

// check user email/pseudo attribute
static void checkLoginVerb(struct afb_req_v4 *wreq,
                           unsigned nparams,
                           struct afb_data *const params[])
{
    const char *errmsg = "[ldap-login] invalid credentials";
    const oidcIdpT *idp = (const oidcIdpT *)afb_req_v4_vcbdata(wreq);
    struct afb_data *args[nparams];
    const char *login, *stateid, *passwd = NULL, *scope = NULL;
    const oidcProfileT *profile = NULL;
    afb_data_t reply;
    int targetLOA;
    int err;

    err = afb_data_convert(params[0], &afb_type_predefined_json_c, &args[0]);
    json_object *queryJ = afb_data_ro_pointer(args[0]);
    err = rp_jsonc_unpack(queryJ, "{ss ss s?s s?s s?s}", "login", &login,
                          "state", &stateid, "passwd", &passwd, "password",
                          &passwd, "scope", &scope);
    if (err)
        goto OnErrorExit;

    // search for a scope fiting matching loa
    oidcSessionT *session = oidcSessionOfReq(wreq);
    if (!stateid || strcmp(stateid, oidcSessionUUID(session)))
        goto OnErrorExit;

    targetLOA = oidcSessionGetTargetLOA(session);

    // search for a matching profile if scope is selected then scope&loa should
    // match
    profile = idpGetFirstProfile(idp, targetLOA, scope);
    if (!profile) {
        EXT_NOTICE("[ldap-check-scope] scope=%s does not match working loa=%d",
                   scope, targetLOA);
        goto OnErrorExit;
    }
    // check login password
    oidcStateT *state = oidcStateCreate(idp, session, profile);
    state->wreq = afb_req_addref(wreq);
    err = ldapAccessProfile(state, idp, login, passwd);
    if (err)
        goto OnErrorExit;

    return;  // curl ldap callback will respond to application

OnErrorExit:

    afb_create_data_raw(&reply, AFB_PREDEFINED_TYPE_STRINGZ, errmsg,
                        strlen(errmsg) + 1, NULL, NULL);
    afb_req_v4_reply_hookable(wreq, -1, 1, &reply);
}

// Called when login page got a valid state
static int ldapOnCredsCB(struct afb_hreq *hreq,
                         const oidcIdpT *idp,
                         oidcSessionT *session,
                         oidcStateT *state)
{
    // check if wreq as a code
    const char *login = afb_hreq_get_argument(hreq, "login");
    const char *passwd = afb_hreq_get_argument(hreq, "passwd");

    // if no code then set state and redirect to IDP
    if (login != NULL && passwd != NULL) {
        int err = ldapAccessProfile(state, idp, login, passwd);
        if (err == 0)
            return 1;  // we're done
    }

    afb_hreq_redirect_to(hreq, idp->wellknown->tokenid, HREQ_QUERY_INCL,
                         HREQ_REDIR_TMPY);
    return 1;
}

// Called when on login page
static int ldapLoginCB(struct afb_hreq *hreq, void *ctx)
{
    const oidcIdpT *idp = (const oidcIdpT *)ctx;
    return idpOnLoginPage(hreq, idp, ldapOnCredsCB, idp->wellknown->tokenid,
                          idp->statics->aliasLogin, NULL, NULL, NULL);
}

static int ldapRegisterVerbs(const oidcIdpT *idp, struct afb_api_v4 *sgApi)
{
    int err;

    // add a dedicate verb to check login/passwd from websocket
    err = afb_api_add_verb(sgApi, idp->uid, idp->info, checkLoginVerb,
                           (void *)idp, NULL, 0, 0);
    if (err)
        goto OnErrorExit;

    return 0;

OnErrorExit:
    return 1;
}

static int ldapRegisterAlias(const oidcIdpT *idp, struct afb_hsrv *hsrv)
{
    int err;
    EXT_DEBUG("[ldap-register-alias] uid=%s login='%s'", idp->uid,
              idp->statics->aliasLogin);

    err = afb_hsrv_add_handler(hsrv, idp->statics->aliasLogin, ldapLoginCB,
                               (void *)idp, EXT_HIGHEST_PRIO);
    if (!err)
        goto OnErrorExit;

    return 0;

OnErrorExit:
    EXT_ERROR(
        "[ldap-register-alias] idp=%s fail to register alias=%s "
        "(ldapRegisterAlias)",
        idp->uid, idp->statics->aliasLogin);
    return 1;
}

// ldap is a fake openid authority as it get everyting locally
static int ldapRegsterConfig(oidcIdpT *idp, json_object *idpJ)
{
    int err;
    const char *people, *groups;
    // only default profile is usefull
    oidcDefaultsT defaults = {
        .profiles = dfltProfiles,
        .statics = &dfltstatics,
        .credentials = &noCredentials,
        .wellknown = &dfltWellknown,
        .headers = &noHeaders,
    };

    // copy default ldap options as idp private user data
    ldapOptsT *ldapOpts = malloc(sizeof(ldapOptsT));
    memcpy(ldapOpts, &dfltLdap, sizeof(ldapOptsT));
    idp->userData = (void *)ldapOpts;

    // check is we have custom options
    json_object *ldapJ = json_object_object_get(idpJ, "schema");
    if (ldapJ) {
        const char *info;
        err = rp_jsonc_unpack(
            ldapJ, "{s?s ss ss ss ss s?s s?i s?i !}", "info", &info, "uri",
            &ldapOpts->uri, "login", &ldapOpts->login, "groups", &groups,
            "people", &people, "avatar", &ldapOpts->avatarAlias, "gids",
            &ldapOpts->gidsMax, "timeout", &ldapOpts->timeout);
        if (err) {
            EXT_ERROR(
                "[ldap-config-opts] json parse fail 'schema' require json "
                "keys: uri,login,groups,people");
            goto OnErrorExit;
        }
        // prebuild request adding ldap uri
        asprintf(&ldapOpts->groups, "%s/%s", ldapOpts->uri, groups);
        asprintf(&ldapOpts->people, "%s/%s", ldapOpts->uri, people);
    }
    // delegate config parsing to common idp utility callbacks
    err = idpParseOidcConfig(idp, idpJ, &defaults, NULL);
    if (err)
        goto OnErrorExit;

    return 0;

OnErrorExit:
    return 1;
}

//----------------------------------------------------------------
// Description
//----------------------------------------------------------------
const idpPluginT ldapPluginDesc = {.uid = "ldap",
                                   .info = "ldap internal users",
                                   .registerConfig = ldapRegsterConfig,
                                   .registerAlias = ldapRegisterAlias,
                                   .registerVerbs = ldapRegisterVerbs};
