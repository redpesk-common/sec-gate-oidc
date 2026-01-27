/*
 * Copyright (C) 2021-2026 IoT.bzh Company
 * Author: "Fulup Ar Foll" <fulup@iot.bzh>
 * Author: <jose.bollo@iot.bzh>
 * Author: <dev-team@iot.bzh>
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 *
 * WARNING: pam plugin requires read access to /etc/shadow
 */

#define _GNU_SOURCE

#include <assert.h>
#include <locale.h>
#include <string.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <grp.h>
#include <pwd.h>
#include <security/pam_appl.h>

#include <rp-utils/rp-escape.h>
#include <rp-utils/rp-jsonc.h>

#include <libafb/afb-core.h>
#include <libafb/afb-http.h>
#include <libafb/afb-v4.h>

#include "oidc-core.h"
#include "oidc-fedid.h"
#include "oidc-idp-plugin.h"
#include "oidc-idp.h"
#include "oidc-session.h"

// provide dummy default values to oidc callbacks
static const oidcCredentialsT noCredentials = {};
static const httpKeyValT noHeaders = {};

typedef struct
{
    int gidsMax;
    const char *avatarAlias;
    int uidMin;
} pamOptsT;

// dflt_xxxx config.json default options
static pamOptsT dfltOpts = {
    .gidsMax = 32,
    .avatarAlias = "/sgate/pam/avatar-dflt.png",
    .uidMin = 1000,
};

static const oidcProfileT dfltProfiles[] = {
    {.loa = 1, .scope = "login"},
    {NULL}  // terminator
};

static const oidcStaticsT dfltstatics = {
    .aliasLogin = "/sgate/pam/login",
    .aliasLogo = "/sgate/pam/logo-64px.png",
    .sTimeout = 600};

static const oidcWellknownT dfltWellknown = {
    .tokenid = "/sgate/pam/login.html",
    .userinfo = NULL,
    .authorize = NULL,
};

// simulate a user UI for passwd input
static int pamChalengeCB(int num_msg,
                         const struct pam_message **msg,
                         struct pam_response **resp,
                         void *passwd)
{
    struct pam_response *reply = malloc(sizeof(struct pam_response));
    reply->resp = strdup(passwd);
    reply->resp_retcode = 0;

    *resp = reply;
    return PAM_SUCCESS;
}

// check pam login/passwd using scope as pam application
static int pamAccessToken(const oidcIdpT *idp,
                          const oidcProfileT *profile,
                          const char *login,
                          const char *passwd,
                          fedSocialRawT *fedSocial,
                          fedUserRawT *fedUser)
{
    int status = 0, err;
    pam_handle_t *pamh = NULL;
    gid_t groups[dfltOpts.gidsMax];
    int ngroups = dfltOpts.gidsMax;

    // Fulup TBD add encryption/decrypting based on session UUID
    // html5 var encrypted = CryptoJS.AES.encrypt("Message", "Secret
    // Passphrase"); AES_set_decrypt_key(const unsigned char *userKey, const int
    // bits, AES_KEY *key); AES_cbc_encrypt((unsigned char *)&ticket, enc_out,
    // encslength, &enc_key, iv_enc, AES_ENCRYPT);

    // pam challenge callback to retrieve user input (e.g. passwd)
    struct pam_conv conversion = {
        .conv = pamChalengeCB,
        .appdata_ptr = (void *)(passwd != NULL ? passwd : ""),
    };

    // login/passwd match let's retrieve gids
    struct passwd *pw = getpwnam(login);
    if (pw == NULL || pw->pw_uid < dfltOpts.uidMin)
        goto OnErrorExit;

    // if passwd check passwd and retrieve groups when login/passwd match
    if (passwd) {
        // init pam transaction using scope as pam application
        status = pam_start(profile->scope, login, &conversion, &pamh);
        if (status != PAM_SUCCESS)
            goto OnErrorExit;

        status = pam_authenticate(pamh, 0);
        if (status != PAM_SUCCESS)
            goto OnErrorExit;

        // build social fedkey from idp->uid+github->id
        fedSocial->fedkey = strdup(pw->pw_name);
        fedUser->pseudo = strdup(pw->pw_name);
        fedUser->name = strdup(pw->pw_gecos);
        fedUser->avatar = strdup(dfltOpts.avatarAlias);

        // retrieve groups list and add them to fedSocial labels list
        err = getgrouplist(pw->pw_name, pw->pw_gid, groups, &ngroups);
        if (err < 0) {
            EXT_CRITICAL("[oidc-pam] opts{'gids':%d} too small",
                         dfltOpts.gidsMax);
            goto OnErrorExit;
        }
        // map pam group name as security labels attributes
        fedSocial->attrs = calloc(ngroups + 1, sizeof(char *));
        for (int idx = 0; idx < ngroups; idx++) {
            struct group *gr;
            gr = getgrgid(groups[idx]);
            fedSocial->attrs[idx] = strdup(gr->gr_name);
        }
    }
    // close pam transaction
    pam_end(pamh, status);
    return 0;

OnErrorExit:
    pam_end(pamh, status);
    return -1;
}

// Called to enter the state
static void pamLogin(const oidcIdpT *idp,
                     oidcStateT *state,
                     const char *login,
                     const char *passwd)
{
    int rc;
    const oidcProfileT *profile = oidcStateGetProfile(state);

    // Check received login/passwd
    EXT_DEBUG("[oidc-pam] login=%s", login);
    rc = pamAccessToken(idp, profile, login, passwd, oidcStateGetSocial(state),
                        oidcStateGetUser(state));
    if (rc < 0)
        oidcStateUnauthorized(state);
    else
        fedidCheck(state);
}

// check user email/pseudo attribute
static void checkLoginVerb(struct afb_req_v4 *wreq,
                           unsigned nparams,
                           struct afb_data *const params[])
{
    const oidcIdpT *idp = (const oidcIdpT *)afb_req_v4_vcbdata(wreq);
    const char *login, *passwd = NULL, *scope = NULL;
    int targetLOA;
    oidcSessionT *session;
    oidcStateT *state;
    struct json_object *obj;
    afb_data_t arg;
    int rc;

    rc = afb_req_param_convert(wreq, 0, &afb_type_predefined_json_c, &arg);
    if (rc < 0)
        EXT_NOTICE("[oidc-pam] can't get parameters");
    else {
        obj = afb_data_ro_pointer(arg);
        rc = rp_jsonc_unpack(obj, "{ss sd s?s s?s s?s}", "login", &login, "loa",
                             &targetLOA, "passwd", &passwd, "password", &passwd,
                             "scope", &scope);
        if (rc < 0)
            EXT_NOTICE("[oidc-pam] invalid JSON parameters: %s",
                       rp_jsonc_get_error_string(rc));
        else {
            rc = idpOnLoginRequest(idp, wreq, targetLOA, scope, &session,
                                   &state);
            if (rc > 0)
                pamLogin(idp, state, login, passwd);
            return;
        }
    }
    afb_req_v4_reply_hookable(wreq, AFB_ERRNO_INVALID_REQUEST, 0, NULL);
}

// Called when login page got a valid state
static int pamOnCredsCB(struct afb_hreq *hreq,
                        const oidcIdpT *idp,
                        oidcSessionT *session,
                        oidcStateT *state)
{
    // check if wreq as a code
    const char *login = afb_hreq_get_argument(hreq, "login");
    const char *passwd = afb_hreq_get_argument(hreq, "passwd");

    // if no code then set state and redirect to IDP
    if (login != NULL)
        pamLogin(idp, state, login, passwd);
    else {
        EXT_NOTICE("[oidc-pam] login is missing");
        afb_hreq_redirect_to(hreq, idp->wellknown->tokenid, HREQ_QUERY_INCL,
                             HREQ_REDIR_TMPY);
    }
    return 1;
}

// Called when on login page
int pamLoginCB(struct afb_hreq *hreq, void *ctx)
{
    const oidcIdpT *idp = (const oidcIdpT *)ctx;
    return idpOnLoginPage(hreq, idp, pamOnCredsCB, idp->wellknown->tokenid,
                          idp->statics->aliasLogin, NULL, NULL, NULL);
}

int pamRegisterVerbs(const oidcIdpT *idp, struct afb_api_v4 *sgApi)
{
    int err;

    // add a dedicate verb to check login/passwd from websocket
    // err= afb_api_add_verb(idp->oidc->apiv4, idp->uid, idp->info,
    // checkLoginVerb, idp, NULL, 0, 0);
    err = afb_api_v4_add_verb_hookable(sgApi, idp->uid, idp->info,
                                       checkLoginVerb, (void *)idp, NULL, 0, 0);
    if (err)
        goto OnErrorExit;

    return 0;

OnErrorExit:
    return 1;
}

static int pamRegisterAlias(const oidcIdpT *idp, struct afb_hsrv *hsrv)
{
    int err;
    EXT_DEBUG("[oidc-pam] uid=%s login='%s'", idp->uid,
              idp->statics->aliasLogin);

    err = afb_hsrv_add_handler(hsrv, idp->statics->aliasLogin, pamLoginCB,
                               (void *)idp, EXT_HIGHEST_PRIO);
    if (!err)
        goto OnErrorExit;

    return 0;

OnErrorExit:
    EXT_ERROR("[oidc-pam] idp=%s fail to register alias=%s", idp->uid,
              idp->statics->aliasLogin);
    return 1;
}

// pam is a fake openid authority as it get everyting locally
static int pamRegisterConfig(oidcIdpT *idp, json_object *idpJ)
{
    int err;

    // only default profile is usefull
    oidcDefaultsT defaults = {
        .profiles = dfltProfiles,
        .statics = &dfltstatics,
        .credentials = &noCredentials,
        .wellknown = &dfltWellknown,
        .headers = &noHeaders,
    };

    // check is we have custom options
    json_object *pluginJ = json_object_object_get(idpJ, "plugin");
    if (pluginJ) {
        err = rp_jsonc_unpack(
            pluginJ, "{s?i s?s s?i}", "gids", &dfltOpts.gidsMax, "avatar",
            &dfltOpts.avatarAlias, "uidmin", &dfltOpts.uidMin);
        if (err) {
            EXT_ERROR(
                "[oidc-pam] json parse fail 'plugin':{'gids': %d, "
                "'avatar':'%s'",
                dfltOpts.gidsMax, dfltOpts.avatarAlias);
            goto OnErrorExit;
        }
    }
    // delegate config parsing to common idp utility callbacks
    err = idpParseOidcConfig(idp, idpJ, &defaults, NULL);
    if (err)
        goto OnErrorExit;

    return 0;

OnErrorExit:
    return 1;
}

// pam sample plugin exposes only one IDP
static const idpPluginT idpPamAuth = {
    .uid = "pam",
    .info = "use Linux pam login to check user/passwd",
    .ctx = "login",
    .registerConfig = pamRegisterConfig,
    .registerVerbs = pamRegisterVerbs,
    .registerAlias = pamRegisterAlias};

// Plugin init call at config.json parsing time
int oidcPluginInit(oidcCoreHdlT *oidc)
{
    // make sure plugin get read access to shadow
    int handle = open("/etc/shadow", O_RDONLY);
    if (handle < 0) {
        EXT_CRITICAL("[oidc-pam] missing permissio=O_RDONLY file=/etc/shadow");
        goto OnErrorExit;
    }
    close(handle);

    int status = idpPluginRegister(&idpPamAuth);
    return status;

OnErrorExit:
    return -1;
}
