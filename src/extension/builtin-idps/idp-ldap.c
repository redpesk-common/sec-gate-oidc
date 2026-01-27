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
#include "oidc-login.h"
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

static int extract(const httpRqtT *httpRqt, const char **dest, const char *key)
{
    size_t sz;
    const char *value;

    /* search the key */
    value = strcasestr(httpRqt->body.buffer, key);
    if (value == NULL)
        return 0;

    /* compute the value */
    value += strlen(key);
    while (*value == ' ')
        value++;
    sz = strcspn(value, "\n");

    /* extract a copy of the value */
    *dest = strndup(value, sz);
    return *dest == NULL ? -1 : 1;
}

static void ldapRqtCtxFree(ldapRqtCtxT *ldapRqtCtx)
{
    if (ldapRqtCtx != NULL) {
        free(ldapRqtCtx->login);
        free(ldapRqtCtx->passwd);
        free(ldapRqtCtx->userdn);
        json_object_put(ldapRqtCtx->loginJ);
        oidcStateUnRef(ldapRqtCtx->state);
        free(ldapRqtCtx);
    }
}

static httpRqtActionT ldapAccessAttrsCB(const httpRqtT *httpRqt)
{
    ldapRqtCtxT *ldapRqtCtx = (ldapRqtCtxT *)httpRqt->userData;
    oidcStateT *state = ldapRqtCtx->state;
    char **attrs = NULL;

    // something when wrong
    if (httpRqt->status < 0) {
        EXT_ERROR("[idp-ldap] Getting attributes failed: %d, %s",
                  httpRqt->status, httpRqt->body.buffer);
        goto done;
    }

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

    for (;;) {
        int idx = 0;
        const char *iter = strcasestr(httpRqt->body.buffer, DNString);
        while (iter) {
            const char *line = iter + DNLen;
            const char *niter = strcasestr(line, DNString);
            const char *entry = strcasestr(line, cnString);
            if (niter == NULL || entry < niter) {
                const char *start = entry + cnLen;
                size_t len = strcspn(start, ",\n");
                if (len > 0) {
                    if (attrs != NULL)
                        attrs[idx] = strndup(start, len);
                    idx++;
                }
            }
            iter = niter;
        }
        if (attrs != NULL)
            break;
        attrs = calloc(idx + 1, sizeof(char *));
        if (attrs == NULL) {
            EXT_ERROR("[idp-ldap] out of memory");
            goto done;
        }
    }
    oidcStateGetSocial(state)->attrs = (const char **)attrs;

    // query federation ldap groups are handle asynchronously
    oidcLogin(state);

done:
    ldapRqtCtxFree(ldapRqtCtx);
    return HTTP_HANDLE_FREE;
}

// reference
// https://docs.ldap.com/en/developers/apps/authorizing-oauth-apps#web-application-flow
static void ldapAccessAttrs(ldapRqtCtxT *ldapRqtCtx)
{
    const ldapOptsT *ldapOpts = ldapRqtCtx->ldapOpts;

    char *curlQuery = utilsExpandJson(ldapOpts->groups, ldapRqtCtx->loginJ);
    if (curlQuery == NULL) {
        EXT_CRITICAL(
            "[idp-ldap] fail to build curl ldap groups query=%s missing "
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
    EXT_DEBUG("[idp-ldap] curl -u '%s:my_secret_passwd' '%s'",
              ldapRqtCtx->userdn, curlQuery);
    int err = httpSendGet(ldapRqtCtx->httpPool, curlQuery, &curlOpts, NULL,
                          ldapAccessAttrsCB, ldapRqtCtx);
    free(curlQuery);
    if (err)
        goto OnErrorExit;

    return;

OnErrorExit:
    EXT_ERROR("[idp-ldap] curl -u '%s:my_secret_passwd' '%s'",
              ldapRqtCtx->userdn, curlQuery);
    return;
}

// call after user authenticate
static httpRqtActionT ldapAccessProfileCB(const httpRqtT *httpRqt)
{
    ldapRqtCtxT *ldapRqtCtx = (ldapRqtCtxT *)httpRqt->userData;
    oidcStateT *state = ldapRqtCtx->state;
    const ldapOptsT *ldapOpts = ldapRqtCtx->ldapOpts;

    int rc;
    fedUserRawT *fedUser = oidcStateGetUser(state);
    fedSocialRawT *fedSocial = oidcStateGetSocial(state);

    // something when wrong
    if (httpRqt->status < 0) {
        EXT_ERROR("[idp-ldap] http returned %d, %.*s", httpRqt->status,
                  (int)httpRqt->body.length, httpRqt->body.buffer);
        goto OnErrorExit;
    }

    // nothing were replied
    if (httpRqt->body.length == 0 || httpRqt->body.buffer == NULL) {
        EXT_ERROR("[idp-ldap] http returned nothing");
        goto OnErrorExit;
    }

    // search for "DN:"
    static char dnString[] = "DN:";
    rc = extract(httpRqt, &fedSocial->fedkey, dnString);
    if (rc <= 0) {
        EXT_ERROR("[idp-ldap] can't get id");
        goto OnErrorExit;
    }

    // search for "pseudo:"
    static char uidString[] = "uid:";
    extract(httpRqt, &fedUser->pseudo, uidString);

    // search for "fullname:"
    static char gecosString[] = "gecos:";
    extract(httpRqt, &fedUser->name, gecosString);

    // search for "email:"
    static char mailString[] = "mail:";
    extract(httpRqt, &fedUser->email, mailString);

    // user is ok, let's map user organisation onto security attributes
    if (ldapOpts->groups)
        ldapAccessAttrs(ldapRqtCtx);
    else {
        // query federation ldap groups are handle asynchronously
        oidcLogin(state);

        ldapRqtCtxFree(ldapRqtCtx);
    }

    return HTTP_HANDLE_FREE;

OnErrorExit:
    oidcStateReplyUnauthorized(state);
    ldapRqtCtxFree(ldapRqtCtx);
    return HTTP_HANDLE_FREE;
}

// check ldap login/passwd scope is unused
static int ldapAccessProfile(oidcStateT *state,
                             const oidcIdpT *idp,
                             const char *login,
                             const char *passwd)
{
    int rc;
    char *curlQuery = NULL;
    ldapRqtCtxT *ldapRqtCtx;

    ldapOptsT *ldapOpts = (ldapOptsT *)idp->userData;

    // prepare context for curl callbacks
    ldapRqtCtx = calloc(1, sizeof(ldapRqtCtxT));
    if (ldapRqtCtx == NULL)
        goto oom;

    ldapRqtCtx->login = strdup(login);
    ldapRqtCtx->passwd = strdup(passwd);
    ldapRqtCtx->state = state;
    ldapRqtCtx->ldapOpts = ldapOpts;

    // place %%login%% with wreq.
    rc = rp_jsonc_pack(&ldapRqtCtx->loginJ, "{ss}", "login", login);
    if (rc < 0)
        goto oom;

    // complete userdn login for authentication
    ldapRqtCtx->userdn = utilsExpandJson(ldapOpts->login, ldapRqtCtx->loginJ);
    if (ldapRqtCtx->userdn == NULL)
        goto oom;

    curlQuery = utilsExpandJson(ldapOpts->people, ldapRqtCtx->loginJ);
    if (curlQuery == NULL)
        goto oom;

    // build curl ldap options structure
    httpOptsT curlOpts = {
        .username = ldapRqtCtx->userdn,
        .password = ldapRqtCtx->passwd,
        .timeout = (long)ldapOpts->timeout,
    };

    // asynchronous wreq to LDAP to check passwd and retrieve user groups
    EXT_DEBUG("[idp-ldap] curl -u '%s:my_secret_passwd' '%s'",
              ldapRqtCtx->userdn, curlQuery);
    rc = httpSendGet(ldapRqtCtx->httpPool, curlQuery, &curlOpts, NULL,
                     ldapAccessProfileCB, ldapRqtCtx);
    if (rc < 0)
        goto error;

    return 0;

oom:
    EXT_ERROR("[idp-ldap] out of memory");
error:
    free(curlQuery);
    ldapRqtCtxFree(ldapRqtCtx);
    return -1;
}

// check user email/pseudo attribute
static void checkLoginVerb(struct afb_req_v4 *wreq,
                           unsigned nparams,
                           struct afb_data *const params[])
{
    const oidcIdpT *idp = (const oidcIdpT *)afb_req_v4_vcbdata(wreq);
    struct afb_data *data;
    const char *login, *stateid, *passwd = NULL, *scope = NULL;
    const oidcProfileT *profile;
    int rc, targetLOA;

    /* get parameters */
    rc = afb_data_convert(params[0], &afb_type_predefined_json_c, &data);
    if (rc >= 0) {
        json_object *queryJ = afb_data_ro_pointer(data);
        rc = rp_jsonc_unpack(queryJ, "{ss ss s?s s?s s?s}", "login", &login,
                             "state", &stateid, "passwd", &passwd, "password",
                             &passwd, "scope", &scope);
    }
    if (rc < 0)
        return afb_req_v4_reply_hookable(wreq, AFB_ERRNO_INVALID_REQUEST, 0,
                                         NULL);

    // search for a scope fiting matching loa
    oidcSessionT *session = oidcSessionOfReq(wreq);
    if (!stateid || strcmp(stateid, oidcSessionUUID(session)))
        return afb_req_v4_reply_hookable(wreq, AFB_ERRNO_BAD_API_STATE, 0,
                                         NULL);

    // search for a matching profile if scope is selected then scope&loa should
    // match
    targetLOA = oidcSessionGetTargetLOA(session);
    profile = idpGetFirstProfile(idp, targetLOA, scope);
    if (!profile) {
        EXT_NOTICE("[idp-ldap] scope=%s does not match working loa=%d", scope,
                   targetLOA);
        return afb_req_v4_reply_hookable(wreq, AFB_ERRNO_UNAUTHORIZED, 0, NULL);
    }

    // check login password
    oidcStateT *state = oidcStateCreate(idp, session, profile);
    oidcStateSetAfbReq(state, wreq);
    rc = ldapAccessProfile(state, idp, login, passwd);
    if (rc < 0)
        afb_req_v4_reply_hookable(wreq, AFB_ERRNO_OUT_OF_MEMORY, 0, NULL);
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
        int rc = ldapAccessProfile(state, idp, login, passwd);
        if (rc >= 0)
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
    EXT_DEBUG("[idp-ldap] uid=%s login='%s'", idp->uid,
              idp->statics->aliasLogin);

    err = afb_hsrv_add_handler(hsrv, idp->statics->aliasLogin, ldapLoginCB,
                               (void *)idp, EXT_HIGHEST_PRIO);
    if (!err)
        goto OnErrorExit;

    return 0;

OnErrorExit:
    EXT_ERROR("[idp-ldap] idp=%s fail to register alias=%s", idp->uid,
              idp->statics->aliasLogin);
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
                "[idp-ldap] json parse fail 'schema' require json "
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
