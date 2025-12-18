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

// ldap context request handle for callbacks
typedef struct
{
    char *login;
    char *passwd;
    char *userdn;
    httpPoolT *httpPool;
    json_object *loginJ;
} ldapRqtCtxT;

// provide dummy default values to oidc callbacks
static const oidcCredentialsT noCredentials = {};
static const httpKeyValT noHeaders = {};

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
    if (ldapRqtCtx->login)
        free(ldapRqtCtx->login);
    if (ldapRqtCtx->passwd)
        free(ldapRqtCtx->passwd);
    if (ldapRqtCtx->userdn)
        free(ldapRqtCtx->userdn);
    if (ldapRqtCtx->loginJ)
        json_object_put(ldapRqtCtx->loginJ);
}

static httpRqtActionT ldapAccessAttrsCB(httpRqtT *httpRqt)
{
    idpRqtCtxT *idpRqtCtx = (idpRqtCtxT *)httpRqt->userData;
    ldapRqtCtxT *ldapRqtCtx = (ldapRqtCtxT *)idpRqtCtx->userData;
    ldapOptsT *ldapOpts = (ldapOptsT *)idpRqtCtx->idp->userData;
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
    static const char token[] = "DN: ";
    idpRqtCtx->fedSocial->attrs = calloc(ldapOpts->gidsMax + 1, sizeof(char *));
    char *savptr, *ptr = strtok_r(httpRqt->body.buffer, token, &savptr);
    int idx;
    for (idx = 0; ptr != NULL; idx++) {
        static char cnString[] = "cn=";
        static int cnLen = sizeof(cnString) - 1;
        char *value = strcasestr(ptr, cnString);
        if (value) {
            // groups over gidsMax are ignored
            if (idx == ldapOpts->gidsMax) {
                EXT_ERROR(
                    "[ldap-fail-groups] ldap->maxgids=%d too small (remaining "
                    "groups ignored)",
                    ldapOpts->gidsMax);
                idpRqtCtx->fedSocial->attrs[idx] = NULL;
                break;
            }
            // extract groupname from LDIF cn=fulup,ou=Groups,dc=vannes,dc=iot\n
            for (int jdx = cnLen; value[jdx]; jdx++) {
                if (value[jdx] == ',' || value[jdx] == '\n') {
                    idpRqtCtx->fedSocial->attrs[idx] =
                        strndup(&value[cnLen], jdx - cnLen);
                    break;
                }
            }
        }
        // move to next cn= (next group)
        ptr = strtok_r(NULL, token, &savptr);
    }

    // reduse groups attrs size to what ever is needed
    idpRqtCtx->fedSocial->attrs[idx + 1] = NULL;
    idpRqtCtx->fedSocial->attrs =
        realloc(idpRqtCtx->fedSocial->attrs, sizeof(char *) * (idx + 2));

    // query federation ldap groups are handle asynchronously
    err = fedidCheck(idpRqtCtx);
    if (err)
        goto OnErrorExit;

    // we done idpRqtCtx is cleared by fedidCheck
    ldapRqtCtxFree(ldapRqtCtx);

    return HTTP_HANDLE_FREE;

OnErrorExit:
    EXT_CRITICAL(
        "[ldap-fail-groups] Fail to get user groups status=%ld body='%s'",
        httpRqt->status, httpRqt->body);
    return HTTP_HANDLE_FREE;
}

// reference
// https://docs.ldap.com/en/developers/apps/authorizing-oauth-apps#web-application-flow
static void ldapAccessAttrs(idpRqtCtxT *idpRqtCtx)
{
    ldapRqtCtxT *ldapRqtCtx = (ldapRqtCtxT *)idpRqtCtx->userData;
    ldapOptsT *ldapOpts = (ldapOptsT *)idpRqtCtx->idp->userData;

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

    // asynchronous wreq to LDAP to check passwd and retreive user groups
    EXT_DEBUG("[curl-ldap-attrs] curl -u '%s:my_secret_passwd' '%s'",
              ldapRqtCtx->userdn, curlQuery);
    int err = httpSendGet(ldapRqtCtx->httpPool, curlQuery, &curlOpts, NULL,
                          ldapAccessAttrsCB, idpRqtCtx);
    if (err)
        goto OnErrorExit;

    return;

OnErrorExit:
    EXT_ERROR("[curl-ldap-error] curl -u '%s:my_secret_passwd' '%s'",
              ldapRqtCtx->userdn, curlQuery);
    return;
}

// call after user authenticate
static httpRqtActionT ldapAccessProfileCB(httpRqtT *httpRqt)
{
    static char errorMsg[] =
        "[ldap-fail-user-profile] Fail to get user profile from ldap "
        "(login/passwd ?)";
    idpRqtCtxT *idpRqtCtx = (idpRqtCtxT *)httpRqt->userData;
    ldapRqtCtxT *ldapRqtCtx = (ldapRqtCtxT *)idpRqtCtx->userData;
    ldapOptsT *ldapOpts = (ldapOptsT *)idpRqtCtx->idp->userData;

    int err, start;
    char *value;
    afb_data_t reply;

    // reserve federation and social user structure
    idpRqtCtx->fedSocial = calloc(1, sizeof(fedSocialRawT));
    idpRqtCtx->fedUser = calloc(1, sizeof(fedUserRawT));
    idpRqtCtx->fedSocial->idp = strdup(idpRqtCtx->idp->uid);

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
        ldapAccessAttrs(idpRqtCtx);
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
static int ldapAccessProfile(oidcIdpT *idp,
                             const char *login,
                             const char *passwd,
                             afb_hreq *hreq,
                             struct afb_req_v4 *wreq)
{
    int err;
    ldapOptsT *ldapOpts = (ldapOptsT *)idp->userData;

    // prepare context for curl callbacks
    ldapRqtCtxT *ldapRqtCtx = calloc(1, sizeof(ldapRqtCtxT));
    ldapRqtCtx->login = strdup(login);
    ldapRqtCtx->passwd = strdup(passwd);

    idpRqtCtxT *idpRqtCtx = calloc(1, sizeof(idpRqtCtxT));
    idpRqtCtx->hreq = hreq;
    idpRqtCtx->wreq = wreq;
    idpRqtCtx->idp = idp;
    idpRqtCtx->userData = (void *)ldapRqtCtx;

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

    // asynchronous wreq to LDAP to check passwd and retreive user groups
    EXT_DEBUG("[curl-ldap-profile] curl -u '%s:my_secret_passwd' '%s'\n",
              ldapRqtCtx->userdn, curlQuery);
    err = httpSendGet(ldapRqtCtx->httpPool, curlQuery, &curlOpts, NULL,
                      ldapAccessProfileCB, idpRqtCtx);
    if (err)
        goto OnErrorExit;

    return 0;

OnErrorExit:
    ldapRqtCtxFree(ldapRqtCtx);
    idpRqtCtxFree(idpRqtCtx);
    return 1;
}

// check user email/pseudo attribute
static void checkLoginVerb(struct afb_req_v4 *wreq,
                           unsigned nparams,
                           struct afb_data *const params[])
{
    const char *errmsg = "[ldap-login] invalid credentials";
    oidcIdpT *idp = (oidcIdpT *)afb_req_v4_vcbdata(wreq);
    struct afb_data *args[nparams];
    const char *login, *passwd = NULL, *scope = NULL;
    const oidcProfileT *profile = NULL;
    afb_data_t reply;
    const char *state;
    int targetLOA;
    int err;

    err = afb_data_convert(params[0], &afb_type_predefined_json_c, &args[0]);
    json_object *queryJ = afb_data_ro_pointer(args[0]);
    err = rp_jsonc_unpack(queryJ, "{ss ss s?s s?s s?s}", "login", &login,
                          "state", &state, "passwd", &passwd, "password",
                          &passwd, "scope", &scope);
    if (err)
        goto OnErrorExit;

    // search for a scope fiting matching loa
    oidcSessionT *session = oidcSessionOfReq(wreq);
    if (!state || strcmp(state, oidcSessionUUID(session)))
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
    err = ldapAccessProfile(idp, login, passwd, NULL /*hreq */, wreq);
    afb_req_addref(wreq);
    if (err)
        goto OnErrorExit;

    return;  // curl ldap callback will respond to application

OnErrorExit:

    afb_create_data_raw(&reply, AFB_PREDEFINED_TYPE_STRINGZ, errmsg,
                        strlen(errmsg) + 1, NULL, NULL);
    afb_req_v4_reply_hookable(wreq, -1, 1, &reply);
}

// when call with no login/passwd display form otherwise try to log user
static int ldapLoginCB(afb_hreq *hreq, void *ctx)
{
    oidcIdpT *idp = (oidcIdpT *)ctx;
    assert(idp->magic == MAGIC_OIDC_IDP);
    char redirectUrl[EXT_HEADER_MAX_LEN];
    const oidcProfileT *profile = NULL;
    int err, status, targetLOA;

    // check if wreq as a code
    const char *login = afb_hreq_get_argument(hreq, "login");
    const char *passwd = afb_hreq_get_argument(hreq, "passwd");
    const char *scope = afb_hreq_get_argument(hreq, "scope");
    oidcSessionT *session = oidcSessionOfHttpReq(hreq);

    targetLOA = oidcSessionGetTargetLOA(session);

    // add afb-binder endpoint to login redirect alias
    status = afb_hreq_make_here_url(hreq, idp->statics->aliasLogin, redirectUrl,
                                    sizeof(redirectUrl));
    if (status < 0)
        goto OnErrorExit;

    // if no code then set state and redirect to IDP
    if (!login || !passwd) {
        char url[EXT_URL_MAX_LEN];

        // search for a scope fiting wreqing loa
        profile = idpGetFirstProfile(idp, targetLOA, scope);

        // if loa working and no profile fit exit without trying authentication
        if (!profile)
            goto OnErrorExit;

        // store working profile to retreive attached loa and role filter if
        // login succeded
        oidcSessionSetIdpProfile(session, profile);

        const char *params[] = {
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
            NULL  // terminator
        };

        // build wreq and send it
        size_t sz = rp_escape_url_to(NULL, idp->wellknown->tokenid, params, url,
                                     sizeof url);
        if (sz >= sizeof url)
            goto OnErrorExit;

        EXT_DEBUG("[ldap-redirect-url] %s (ldapLoginCB)", url);
        afb_hreq_redirect_to(hreq, url, HREQ_QUERY_EXCL, HREQ_REDIR_TMPY);
    }
    else {
        // we have a code check state to assert that the response was generated
        // by us then wreq authentication token
        const char *state = afb_hreq_get_argument(hreq, "state");
        if (!state || strcmp(state, oidcSessionUUID(session)))
            goto OnErrorExit;

        EXT_DEBUG("[ldap-auth-code] login=%s (ldapLoginCB)", login);
        profile = oidcSessionGetIdpProfile(session);
        if (!profile)
            goto OnErrorExit;

        // Check received login/passwd
        err = ldapAccessProfile(idp, login, passwd, hreq, NULL /*wreq */);
        if (err)
            goto OnErrorExit;
    }

    return 1;  // we're done

OnErrorExit:
    afb_hreq_redirect_to(hreq, idp->wellknown->tokenid, HREQ_QUERY_INCL,
                         HREQ_REDIR_TMPY);
    return 1;
}

static int ldapRegisterApis(oidcIdpT *idp,
                            struct afb_apiset *declare_set,
                            struct afb_apiset *call_set)
{
    int err;

    // add a dedicate verb to check login/passwd from websocket
    err = afb_api_add_verb(oidcCoreAfbApi(idp->oidc), idp->uid, idp->info,
                           checkLoginVerb, idp, NULL, 0, 0);
    if (err)
        goto OnErrorExit;

    return 0;

OnErrorExit:
    return 1;
}

static int ldapRegisterAlias(const oidcIdpT *idp, afb_hsrv *hsrv)
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
                                   .registerApis = ldapRegisterApis};
