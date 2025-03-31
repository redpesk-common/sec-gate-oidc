/*
 * Copyright (C) 2021 "IoT.bzh"
 * Author "Fulup Ar Foll" <fulup@iot.bzh>
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at https://opensource.org/licenses/MIT.
 *
 * WARNING: pam plugin requires read access to /etc/shadow
 */

#define _GNU_SOURCE

#include <libafb/afb-v4.h>
#include <libafb/afb-core.h>
#include <libafb/afb-http.h>

#include "oidc-core.h"
#include "oidc-idp.h"
#include "oidc-alias.h"
#include "oidc-fedid.h"

#include <assert.h>
#include <string.h>
#include <locale.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <security/pam_appl.h>
#include <grp.h>
#include <pwd.h>

// keep track of oidc-idp.c generic utils callbacks
static idpGenericCbT *idpCallbacks = NULL;

// provide dummy default values to oidc callbacks
static const oidcCredentialsT noCredentials = { };
static const httpKeyValT noHeaders = { };

typedef struct {
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
    {.loa = 1,.scope = "login"},
    {NULL}                      // terminator
};

static const oidcStaticsT dfltstatics = {
    .aliasLogin = "/sgate/pam/login",
    .aliasLogo = "/sgate/pam/logo-64px.png",
    .sTimeout = 600
};

static const oidcWellknownT dfltWellknown = {
    .tokenid = "/sgate/pam/login.html",
    .userinfo = NULL,
    .authorize = NULL,
};

// simulate a user UI for passwd input
static int pamChalengeCB (int num_msg, const struct pam_message **msg, struct pam_response **resp, void *passwd)
{
    struct pam_response *reply = malloc (sizeof (struct pam_response));
    reply->resp = strdup (passwd);
    reply->resp_retcode = 0;

    *resp = reply;
    return PAM_SUCCESS;
}

// check pam login/passwd using scope as pam application
static int pamAccessToken (oidcIdpT * idp, const oidcProfileT * profile, const char *login, const char *passwd, fedSocialRawT ** social, fedUserRawT ** user)
{
    int status = 0, err;
    pam_handle_t *pamh = NULL;
    gid_t groups[dfltOpts.gidsMax];
    int ngroups = dfltOpts.gidsMax;

    // Fulup TBD add encryption/decrypting based on session UUID
    // html5 var encrypted = CryptoJS.AES.encrypt("Message", "Secret Passphrase");
    // AES_set_decrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);
    // AES_cbc_encrypt((unsigned char *)&ticket, enc_out, encslength, &enc_key, iv_enc, AES_ENCRYPT);

    // pam challenge callback to retreive user input (e.g. passwd)
    struct pam_conv conversion = {
        .conv = pamChalengeCB,
        .appdata_ptr = (void *) passwd,
    };

    // login/passwd match let's retreive gids
    struct passwd *pw = getpwnam (login);
    if (pw == NULL || pw->pw_uid < dfltOpts.uidMin) goto OnErrorExit;

    // if passwd check passwd and retreive groups when login/passwd match
    if (passwd) {
        // init pam transaction using scope as pam application
        status = pam_start (profile->scope, login, &conversion, &pamh);
        if (status != PAM_SUCCESS) goto OnErrorExit;

        status = pam_authenticate (pamh, 0);
        if (status != PAM_SUCCESS) goto OnErrorExit;

        // build social fedkey from idp->uid+github->id
        fedSocialRawT *fedSocial = calloc (1, sizeof (fedSocialRawT));
        char *fedId;
        asprintf (&fedId, "id:%d", pw->pw_uid);
        fedSocial->fedkey = fedId;
        fedSocial->idp = strdup (idp->uid);

        fedUserRawT *fedUser = calloc (1, sizeof (fedUserRawT));
        fedUser->pseudo = strdup (pw->pw_name);
        fedUser->avatar = strdup (dfltOpts.avatarAlias);
        fedUser->name = strdup (pw->pw_gecos);
        fedUser->company = NULL;
        fedUser->email = NULL;

        // retreive groups list and add then to fedSocial labels list
        err = getgrouplist (pw->pw_name, pw->pw_gid, groups, &ngroups);
        if (err < 0) {
            EXT_CRITICAL ("[pam-auth-gids] opts{'gids':%d} too small", dfltOpts.gidsMax);
            goto OnErrorExit;
        }
        // map pam group name as security labels attributes
        fedSocial->attrs = calloc (ngroups + 1, sizeof (char *));
        for (int idx = 0; idx < ngroups; idx++) {
            struct group *gr;
            gr = getgrgid (groups[idx]);
            fedSocial->attrs[idx] = strdup (gr->gr_name);
        }

        *user = fedUser;
        *social = fedSocial;
    }
    // close pam transaction
    pam_end (pamh, status);
    return 0;

  OnErrorExit:
    pam_end (pamh, status);
    return 1;
}

// check user email/pseudo attribute
static void checkLoginVerb (struct afb_req_v4 *wreq, unsigned nparams, struct afb_data *const params[])
{
    const char *errmsg = "[pam-login] invalid credentials";
    oidcIdpT *idp = (oidcIdpT *) afb_req_v4_vcbdata (wreq);
    struct afb_data *args[nparams];
    const char *login, *passwd = NULL, *scope = NULL;
    const oidcProfileT *profile = NULL;
    const oidcAliasT *alias = NULL;
    afb_data_t reply;
    const char *state;
    int aliasLoa;
    int err;

    err = afb_data_convert (params[0], &afb_type_predefined_json_c, &args[0]);
    json_object *queryJ = afb_data_ro_pointer (args[0]);
    err = wrap_json_unpack (queryJ, "{ss ss s?s s?s s?s}", "login", &login, "state", &state, "passwd", &passwd, "password", &passwd, "scope", &scope);
    if (err) goto OnErrorExit;

    // search for a scope fiting wreqing loa
    afb_session *session = afb_req_v4_get_common (wreq)->session;
    if (!state || strcmp (state, afb_session_uuid (session))) goto OnErrorExit;

    afb_session_cookie_get (session, oidcAliasCookie, (void **) &alias);
    if (alias) aliasLoa = alias->loa;
    else aliasLoa = 0;

    // search for a matching profile if scope is selected then scope&loa should match
    for (int idx = 0; idp->profiles[idx].uid; idx++) {
        profile = &idp->profiles[idx];
        if (idp->profiles[idx].loa >= aliasLoa) {
            if (scope && strcasecmp (scope, idp->profiles[idx].scope)) continue;
            profile = &idp->profiles[idx];
            break;
        }
    }
    if (!profile) {
        EXT_NOTICE ("[pam-check-scope] scope=%s does not match working loa=%d", scope, aliasLoa);
        goto OnErrorExit;
    }
    // check password
    fedUserRawT *fedUser = NULL;
    fedSocialRawT *fedSocial = NULL;
    err = pamAccessToken (idp, profile, login, passwd, &fedSocial, &fedUser);
    if (err) goto OnErrorExit;

    // do no check federation when only login
    if (fedUser) {
        afb_req_addref (wreq);
        idpRqtCtxT *idpRqtCtx= calloc (1,sizeof(idpRqtCtxT));
        idpRqtCtx->idp = idp;
        idpRqtCtx->fedSocial= fedSocial;
        idpRqtCtx->fedUser= fedUser;
        idpRqtCtx->wreq= wreq;
        err = idpCallbacks->fedidCheck (idpRqtCtx);
        if (err) {
            afb_req_unref (wreq);
            goto OnErrorExit;
        }
    } else {
        afb_req_v4_reply_hookable (wreq, 0, 0, NULL);        // login exist
    }
    return;

  OnErrorExit:

    afb_create_data_raw (&reply, AFB_PREDEFINED_TYPE_STRINGZ, errmsg, strlen (errmsg) + 1, NULL, NULL);
    afb_req_v4_reply_hookable (wreq, -1, 1, &reply);
}


// when call with no login/passwd display form otherwise try to log user
int pamLoginCB (afb_hreq * hreq, void *ctx)
{
    oidcIdpT *idp = (oidcIdpT *) ctx;
    assert (idp->magic == MAGIC_OIDC_IDP);
    char redirectUrl[EXT_HEADER_MAX_LEN];
    const oidcProfileT *profile = NULL;
    const oidcAliasT *alias = NULL;
    int err, status, aliasLoa;

    // check if wreq as a code
    const char *login = afb_hreq_get_argument (hreq, "login");
    const char *passwd = afb_hreq_get_argument (hreq, "passwd");
    const char *scope = afb_hreq_get_argument (hreq, "scope");

    afb_session_cookie_get (hreq->comreq.session, oidcAliasCookie, (void **) &alias);
    if (alias) aliasLoa = alias->loa;
    else aliasLoa = 0;

    // add afb-binder endpoint to login redirect alias
    status = afb_hreq_make_here_url (hreq, idp->statics->aliasLogin, redirectUrl, sizeof (redirectUrl));
    if (status < 0) goto OnErrorExit;

    // if no code then set state and redirect to IDP
    if (!login || !passwd) {
        char url[EXT_URL_MAX_LEN];

        // search for a scope fiting wreqing loa
        for (int idx = 0; idp->profiles[idx].uid; idx++) {
            profile = &idp->profiles[idx];
            if (idp->profiles[idx].loa >= aliasLoa) {
                // if no scope take the 1st profile with valid LOA
                if (scope && (strcmp (scope, idp->profiles[idx].scope))) continue;
                profile = &idp->profiles[idx];
                break;
            }
        }

        // if loa working and no profile fit exit without trying authentication
        if (!profile) goto OnErrorExit;

        httpKeyValT query[] = {
            {.tag = "state",.value = afb_session_uuid (hreq->comreq.session)},
            {.tag = "scope",.value = profile->scope},
            {.tag = "redirect_uri",.value = redirectUrl},
            {.tag = "language",.value = setlocale (LC_CTYPE, "")},
            {NULL}              // terminator
        };

        // store working profile to retreive attached loa and role filter if login succeded
        afb_session_cookie_set (hreq->comreq.session, oidcIdpProfilCookie, (void *) profile, NULL, NULL);

        // build wreq and send it
        err = httpBuildQuery (idp->uid, url, sizeof (url), NULL /* prefix */ , idp->wellknown->tokenid, query);
        if (err) goto OnErrorExit;

        EXT_DEBUG ("[pam-redirect-url] %s (pamLoginCB)", url);
        afb_hreq_redirect_to (hreq, url, HREQ_QUERY_EXCL, HREQ_REDIR_TMPY);

    } else {

        // we have a code check state to assert that the response was generated by us then wreq authentication token
        const char *state = afb_hreq_get_argument (hreq, "state");
        if (!state || strcmp (state, afb_session_uuid (hreq->comreq.session))) goto OnErrorExit;

        EXT_DEBUG ("[pam-auth-code] login=%s (pamLoginCB)", login);
        afb_session_cookie_get (hreq->comreq.session, oidcIdpProfilCookie, (void **) &profile);
        if (!profile) goto OnErrorExit;

        // Check received login/passwd
        fedUserRawT *fedUser;
        fedSocialRawT *fedSocial;
        err = pamAccessToken (idp, profile, login, passwd, &fedSocial, &fedUser);
        if (err) goto OnErrorExit;

        // check if federated id is already present or not
        idpRqtCtxT *idpRqtCtx= calloc (1,sizeof(idpRqtCtxT));
        idpRqtCtx->idp = idp;
        idpRqtCtx->fedSocial= fedSocial;
        idpRqtCtx->fedUser= fedUser;
        idpRqtCtx->hreq= hreq;
        err = idpCallbacks->fedidCheck (idpRqtCtx);
        if (err) {
            goto OnErrorExit;
        }
    }

    return 1;   // we're done

  OnErrorExit:
    afb_hreq_redirect_to (hreq, idp->wellknown->tokenid, HREQ_QUERY_INCL, HREQ_REDIR_TMPY);
    return 1;
}

int pamRegisterApis (oidcIdpT * idp, struct afb_apiset *declare_set, struct afb_apiset *call_set)
{
    int err;

    // add a dedicate verb to check login/passwd from websocket
    //err= afb_api_add_verb(idp->oidc->apiv4, idp->uid, idp->info, checkLoginVerb, idp, NULL, 0, 0);
    err = afb_api_v4_add_verb_hookable (idp->oidc->apiv4, idp->uid, idp->info, checkLoginVerb, idp, NULL, 0, 0);
    if (err) goto OnErrorExit;

    return 0;

  OnErrorExit:
    return 1;
}

static int pamRegisterAlias (oidcIdpT * idp, afb_hsrv * hsrv)
{
    int err;
    EXT_DEBUG ("[pam-register-alias] uid=%s login='%s'", idp->uid, idp->statics->aliasLogin);

    err = afb_hsrv_add_handler (hsrv, idp->statics->aliasLogin, pamLoginCB, idp, EXT_HIGHEST_PRIO);
    if (!err) goto OnErrorExit;

    return 0;

  OnErrorExit:
    EXT_ERROR ("[pam-register-alias] idp=%s fail to register alias=%s (pamRegisterAlias)", idp->uid, idp->statics->aliasLogin);
    return 1;
}

// pam is a fake openid authority as it get everyting locally
static int pamRegisterConfig (oidcIdpT * idp, json_object * idpJ)
{
    int err;
    assert (idpCallbacks);

    // only default profile is usefull
    oidcDefaultsT defaults = {
        .profiles = dfltProfiles,
        .statics = &dfltstatics,
        .credentials = &noCredentials,
        .wellknown = &dfltWellknown,
        .headers = &noHeaders,
    };

    // check is we have custom options
    json_object *pluginJ = json_object_object_get (idpJ, "plugin");
    if (pluginJ) {
        err = wrap_json_unpack (pluginJ, "{s?i s?s s?i}", "gids", &dfltOpts.gidsMax, "avatar", &dfltOpts.avatarAlias, "uidmin", &dfltOpts.uidMin);
        if (err) {
            EXT_ERROR ("[pam-config-opts] json parse fail 'plugin':{'gids': %d, 'avatar':'%s'", dfltOpts.gidsMax, dfltOpts.avatarAlias);
            goto OnErrorExit;
        }
    }
    // delegate config parsing to common idp utility callbacks
    err = idpCallbacks->parseConfig (idp, idpJ, &defaults, NULL);
    if (err) goto OnErrorExit;

    return 0;

  OnErrorExit:
    return 1;
}

// pam sample plugin exposes only one IDP
idpPluginT idpPamAuth[] = {
    {.uid = "pam",.info = "use Linux pam login to check user/passwd",.ctx = "login",.registerConfig = pamRegisterConfig,.registerApis = pamRegisterApis,.registerAlias= pamRegisterAlias},
    {.uid = NULL}               // must be null terminated
};

// Plugin init call at config.json parsing time
int oidcPluginInit (oidcCoreHdlT * oidc, idpGenericCbT * idpGenericCbs)
{
    assert (idpGenericCbs->magic == MAGIC_OIDC_CBS);    // check provided callback magic

    // plugin is already loaded
    if (idpCallbacks) return 0;
    idpCallbacks = idpGenericCbs;

    // make sure plugin get read access to shadow
    int handle = open ("/etc/shadow", O_RDONLY);
    if (handle < 0) {
        EXT_CRITICAL ("[pam-auth-permission] missing permissio=O_RDONLY file=/etc/shadow (pamLoginCB)");
        goto OnErrorExit;
    }
    close (handle);

    int status = idpCallbacks->pluginRegister ("pam-plugin", idpPamAuth);
    return status;

  OnErrorExit:
    return -1;
}
