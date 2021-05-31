/*
 * Copyright (C) 2021 "IoT.bzh"
 * Author "Fulup Ar Foll" <fulup@iot.bzh>
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at https://opensource.org/licenses/MIT.
 *
 * WARNING: pcsc plugin requires read access to /etc/shadow
 * Reference: 
 *  https://buzz.smartcardfocus.com/category/get-the-code/
 *  http://pcscworkgroup.com/Download/Specifications/pcsc3_v2.01.09_sup.pdf
 */

#define _GNU_SOURCE

#include <libafb/afb-v4.h>
#include <libafb/afb-core.h>
#include <libafb/afb-http.h>

#include "oidc-core.h"
#include "oidc-idp.h"
#include "oidc-alias.h"
#include "oidc-fedid.h"
#include "oidc-utils.h"
#include "pcsc-config.h"

#include <pcsclite.h>
#include <assert.h>
#include <string.h>
#include <locale.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

// import pcsc-little API
#include "pcsc-glue.h"
#include "pcsc-config.h"

// keep track of oidc-idp.c generic utils callbacks
static idpGenericCbT *idpCallbacks = NULL;

// provide dummy default values to oidc callbacks
static const oidcCredentialsT noCredentials = { };
static const httpKeyValT noHeaders = { };

typedef struct {
    const char *avatarAlias;
    int readerMax;
    int labelMax;
    pcscHandleT *handle;
    pcscConfigT *config;
} pcscOptsT;

// dflt_xxxx config.json default options
static pcscOptsT dfltOpts = {
    .readerMax = 4,
    .labelMax = 16,
    .avatarAlias = "/sgate/pcsc/avatar-dflt.png",
};

static const oidcProfileT dfltProfiles[] = {
    {.loa = 1,.scope = "login"},
    {NULL}                      // terminator
};

static const oidcStaticsT dfltstatics = {
    .aliasLogin = "/sgate/pcsc/login",
    .aliasLogo = "/sgate/pcsc/logo-64px.png",
    .sTimeout = 600
};

static const oidcWellknownT dfltWellknown = {
    .tokenid = "/sgate/pcsc/login.html",
    .userinfo = NULL,
    .authorize = NULL,
};

typedef struct {
   unsigned long pin;
   idpRqtCtxT *idpRqtCtx;
   pcscOptsT *opts;
   const char *scope;
   const char *label;
   afb_session *session;
   int done;
} pcscRqtCtxT;

static void pcscRqtCtxFree (pcscRqtCtxT *rqt) {
    free(rqt);
}

// if needed stop pcsc thread when session finish
static void pcscResetSession (oidcProfileT *idpProfil, void *ctx) {
    pcscHandleT *handle= (pcscHandleT*)ctx;
    pcscMonitorWait (handle, PCSC_MONITOR_CANCEL);
}

static int readerMonitorCB (pcscHandleT *handle, unsigned long state) {
    extern const nsKeyEnumT oidcFedidSchema[];
    pcscRqtCtxT *pcscRqtCtx= (pcscRqtCtxT*) pcscGetCtx(handle);
    idpRqtCtxT  *idpRqtCtx= pcscRqtCtx->idpRqtCtx;
    pcscOptsT   *pcscOpts= pcscRqtCtx->opts;
    int status=0;
    int err;

    // is card was previously inserted logout user (session loa=0)
    if ((state & SCARD_STATE_EMPTY) && pcscRqtCtx->done) {
        EXT_DEBUG ("[pcsc-monitor-absent] card removed from reader (reseting session)\n");
        assert (pcscRqtCtx->session);
        fedidsessionReset (0, pcscRqtCtx->session);
        pcscRqtCtxFree(pcscRqtCtx);
        status=1; // terminate thread 
    } 

    if (state & SCARD_STATE_PRESENT) {
        EXT_DEBUG ("[pcsc-monitor-present] card=0x%lx inserted\n", pcscGetCardUuid(handle));
        // reserve federation and social user structure
        idpRqtCtx->fedSocial= calloc (1, sizeof (fedSocialRawT));
        idpRqtCtx->fedUser= calloc (1, sizeof (fedUserRawT));
        u_int64_t uuid;
        char *data;

        // map scope to pcsc commands
        str2TokenT scopeTkn;
        for (char *scope=utilStr2Token(&scopeTkn,',',pcscRqtCtx->scope); scope; scope=utilStr2Token(&scopeTkn,0,0)) {

            pcscCmdT *cmd = pcscCmdByUid (pcscOpts->config, scope);
            if (!cmd) {
                EXT_ERROR ("[pcsc-cmd-uid] command=%s not found", scope);
                goto OnErrorExit;
            }

            switch (cmd->action) {
                case PCSC_ACTION_UUID: 
                    uuid= pcscGetCardUuid (handle);
                    if (uuid == 0) {
                        EXT_ERROR ("[pcsc-cmd-uuid] command=%s fail getting uuid error=%s", cmd->uid, pcscErrorMsg(handle));
                        goto OnErrorExit;
                    }
                    idpRqtCtx->fedSocial->idp = strdup (idpRqtCtx->idp->uid);
                    asprintf ((char**)&idpRqtCtx->fedSocial->fedkey, "%ld", uuid);
                    break;

                case PCSC_ACTION_READ: 
                    data=malloc(cmd->dlen);
                    err= pcscExecOneCmd (pcscOpts->handle, cmd, (u_int8_t*)data);
                    if (err) {
                        EXT_ERROR ("[pcsc-cmd-exec] command=%s execution fail error=%s", cmd->uid, pcscErrorMsg(handle));
                        goto OnErrorExit;
                    }
                    switch (utilLabel2Value(oidcFedidSchema, cmd->uid)) {
                        case OIDC_SCHEMA_PSEUDO: 
                            idpRqtCtx->fedUser->pseudo= strdup(data);
                            break;
                        case OIDC_SCHEMA_NAME: 
                            idpRqtCtx->fedUser->name= strdup(data);
                            break;
                        case OIDC_SCHEMA_EMAIL: 
                            idpRqtCtx->fedUser->email= strdup(data);
                            break;
                        case OIDC_SCHEMA_COMPANY: 
                            idpRqtCtx->fedUser->company= strdup(data);
                            break;
                        case OIDC_SCHEMA_AVATAR: 
                            idpRqtCtx->fedUser->avatar= strdup(data);
                            break;
                        default: 
                            EXT_ERROR ("[pcsc-cmd-schema] command=%s no schema mapping [pseudo,name,email,company,avatar]", cmd->uid);
                            goto OnErrorExit;
                    }
                    break;

                default:
                    EXT_ERROR ("[pcsc-cmd-action] command=%s action=%d not supported for authentication", cmd->uid, cmd->action);
                    goto OnErrorExit;
            }     
        }

        // map security atributes to pcsc read commands
        if (pcscRqtCtx->label) {
            str2TokenT tokenLabel;
            int index=0;
            idpRqtCtx->fedSocial->attrs= calloc (pcscOpts->labelMax+1, sizeof(char*));
            for (char *label=utilStr2Token(&tokenLabel,',', pcscRqtCtx->label); label; label=utilStr2Token(&tokenLabel,0,0)) {
                pcscCmdT *cmd = pcscCmdByUid (pcscOpts->config, label);
                if (!cmd || cmd->action != PCSC_ACTION_READ) {
                    EXT_ERROR ("[pcsc-cmd-label] label=%s does does match any read command", label);
                    goto OnErrorExit;
                }

                err= pcscExecOneCmd (pcscOpts->handle, cmd, (u_int8_t*)data);
                if (err) {
                    EXT_ERROR ("[pcsc-cmd-label] command=%s execution fail error=%s", cmd->uid, pcscErrorMsg(handle));
                    goto OnErrorExit;
                }

                // parse ttrs string to extract multi-attributes if any
                str2TokenT tokenAttr;
                for (char *attr=utilStr2Token(&tokenAttr, ',', data); attr; attr=utilStr2Token(&tokenAttr,0,0)) {
                    idpRqtCtx->fedSocial->attrs[index++] = strdup(attr);
                    if (index == pcscOpts->labelMax) {
                        EXT_ERROR ("[pcsc-cmd-label] ignored labels command=%s maxlabel=%d too small labels=%s", cmd->uid, pcscOpts->labelMax, pcscRqtCtx->scope);
                    }
                }
            }
        }
        // do federate authentication
        idpRqtCtx->userData = (void*) handle;
        err = fedidCheck (idpRqtCtx);
        if (err) goto OnErrorExit;

        pcscRqtCtx->done=1; // stop thread as soon as card is removed
        status=0;   // keep thread running
    }

    // we done idpRqtCtx is cleared by fedidCheck
    return status;

OnErrorExit:
    {
        static char errorMsg[]= "[pcsc-monitor-fail] Fail to get user profile from pscs (nfc/smartcard)";
        EXT_CRITICAL (errorMsg);
        if (idpRqtCtx->hreq) {
            afb_hreq_reply_error (idpRqtCtx->hreq, EXT_HTTP_UNAUTHORIZED);
        } else {
            afb_data_t reply;
            afb_create_data_raw (&reply, AFB_PREDEFINED_TYPE_STRINGZ, errorMsg, sizeof(errorMsg), NULL, NULL);
            afb_req_v4_reply_hookable (idpRqtCtx->wreq, -1, 1, &reply);
        }
    }
    fedSocialFreeCB(idpRqtCtx->fedSocial);
    fedUserFreeCB(idpRqtCtx->fedUser);
    pcscRqtCtxFree(pcscRqtCtx);
    idpRqtCtxFree(idpRqtCtx);
	return -1;  // on error exit kill thread
}

// check pcsc login/passwd using scope as pcsc application
static int pcscScardGet (oidcIdpT * idp, const oidcProfileT *profile, unsigned long pin, afb_hreq *hreq, struct afb_req_v4 *wreq)
{
    pcscOptsT *pcscOpts= (pcscOptsT*) idp->ctx;

    // store pcsc context within idp request one
    idpRqtCtxT *idpRqtCtx= calloc (1, sizeof(idpRqtCtxT));
    idpRqtCtx->hreq= hreq;
    idpRqtCtx->wreq= wreq;
    idpRqtCtx->idp= idp;

    // prepare context for pcsc monitor callbacks
    pcscRqtCtxT *pcscRqtCtx= calloc (1, sizeof(pcscRqtCtxT));
    pcscRqtCtx->pin=pin;
    pcscRqtCtx->scope=profile->scope;
    pcscRqtCtx->label=profile->attrs;
    pcscRqtCtx->opts= pcscOpts;
    pcscRqtCtx->idpRqtCtx= idpRqtCtx;

    if (idpRqtCtx->hreq) pcscRqtCtx->session= idpRqtCtx->hreq->comreq.session;
    if (idpRqtCtx->wreq) pcscRqtCtx->session= afb_req_v4_get_common (wreq)->session;

    unsigned long tid= pcscMonitorReader (pcscOpts->handle, readerMonitorCB, (void*)pcscRqtCtx);
    if (tid <= 0) goto OnErrorExit;

    return 0;

OnErrorExit:
    {
        static char errorMsg[]= "[pcsc-monitor-fail] Fail to get user profile from pscs (nfc/smartcard)";
        EXT_CRITICAL (errorMsg);
        if (idpRqtCtx->hreq) {
            afb_hreq_reply_error (idpRqtCtx->hreq, EXT_HTTP_UNAUTHORIZED);
        } else {
            afb_data_t reply;
            afb_create_data_raw (&reply, AFB_PREDEFINED_TYPE_STRINGZ, errorMsg, sizeof(errorMsg), NULL, NULL);
            afb_req_v4_reply_hookable (idpRqtCtx->wreq, -1, 1, &reply);
        }
    }
    pcscRqtCtxFree(pcscRqtCtx);
    idpRqtCtxFree(idpRqtCtx);
    return 1;
}

// check user email/pseudo attribute
static void checkLoginVerb (struct afb_req_v4 *wreq, unsigned nparams, struct afb_data *const params[])
{
    const char *errmsg = "[pcsc-login] invalid credentials";
    oidcIdpT *idp = (oidcIdpT *) afb_req_v4_vcbdata (wreq);
    struct afb_data *args[nparams];
    const char *scope = NULL;
    const oidcProfileT *profile = NULL;
    const oidcAliasT *alias = NULL;
    afb_data_t reply;
    const char *state;
    unsigned long pinCode;
    int aliasLoa;
    int err;

    err = afb_data_convert (params[0], &afb_type_predefined_json_c, &args[0]);
    json_object *queryJ = afb_data_ro_pointer (args[0]);
    err = wrap_json_unpack (queryJ, "{ss s?i s?s}", "state", &state, "pin", &pinCode, "scope", &scope);
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
        EXT_NOTICE ("[pcsc-check-scope] scope=%s does not match working loa=%d", scope, aliasLoa);
        goto OnErrorExit;
    }

    // store working profile to retreive attached loa and role filter if login succeeded
    afb_session_cookie_set (session, oidcIdpProfilCookie, (void*)profile, NULL, NULL);

    // try to access smart card
    err = pcscScardGet (idp, profile, pinCode, /*hreq*/NULL, wreq);
    if (err) goto OnErrorExit;

    // response is handle asynchronously
    afb_req_addref (wreq);
    return;

  OnErrorExit:
    afb_create_data_raw (&reply, AFB_PREDEFINED_TYPE_STRINGZ, errmsg, strlen (errmsg) + 1, NULL, NULL);
    afb_req_v4_reply_hookable (wreq, -1, 1, &reply);
}

// when call with no login/passwd display form otherwise try to log user
int pcscLoginCB (afb_hreq * hreq, void *ctx)
{
    oidcIdpT *idp = (oidcIdpT *) ctx;
    assert (idp->magic == MAGIC_OIDC_IDP);
    const oidcProfileT *profile = NULL;
    const oidcAliasT *alias = NULL;
    int err, aliasLoa;

    // Initial redirect redirect user on web page to enter login
    char url[EXT_URL_MAX_LEN];

    afb_session_cookie_get (hreq->comreq.session, oidcAliasCookie, (void **) &alias);
    if (alias) aliasLoa = alias->loa;
    else aliasLoa = 0;

    // search a working loa scope
    const char *scope = afb_hreq_get_argument (hreq, "scope");
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
    afb_session_cookie_set (hreq->comreq.session, oidcIdpProfilCookie, (void *)profile, NULL, NULL);

    httpKeyValT query[] = {
        {.tag = "state",.value= afb_session_uuid (hreq->comreq.session)},
        {.tag = "scope",.value= profile->scope},
        {.tag = "language",.value = setlocale (LC_CTYPE, "")},
        {NULL}  // terminator
    };

    // build wreq and send it
    err = httpBuildQuery (idp->uid, url, sizeof (url), NULL /* prefix */ , idp->wellknown->tokenid, query);
    if (err) goto OnErrorExit;

    EXT_DEBUG ("[pcsc-redirect-url] %s (pcscLoginCB)", url);
    afb_hreq_redirect_to (hreq, url, HREQ_QUERY_EXCL, HREQ_REDIR_TMPY);

    return 1; // we're done

  OnErrorExit:
    afb_hreq_redirect_to (hreq, idp->oidc->globals->loginUrl, HREQ_QUERY_INCL, HREQ_REDIR_TMPY);
    return 1;
}

int pcscRegisterApis (oidcIdpT * idp, struct afb_apiset *declare_set, struct afb_apiset *call_set)
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

static int pcscRegisterAlias (oidcIdpT * idp, afb_hsrv * hsrv)
{
    int err;
    EXT_DEBUG ("[pcsc-register-alias] uid=%s login='%s'", idp->uid, idp->statics->aliasLogin);

    err = afb_hsrv_add_handler (hsrv, idp->statics->aliasLogin, pcscLoginCB, idp, EXT_HIGHEST_PRIO);
    if (!err) goto OnErrorExit;

    return 0;

  OnErrorExit:
    EXT_ERROR ("[pcsc-register-alias] idp=%s fail to register alias=%s (pcscRegisterAlias)", idp->uid, idp->statics->aliasLogin);
    return 1;
}

// pcsc is a fake openid authority as it get everyting locally
static int pcscRegisterConfig (oidcIdpT * idp, json_object * idpJ)
{
    int err;
    pcscOptsT *pcscOpts= malloc(sizeof(pcscOptsT));
    memcpy (pcscOpts, &dfltOpts, sizeof(pcscOptsT));
    json_object *pcscConfJ;
    int verbosity;
    const char*ldpath;

    // check is we have custom options
    json_object *pluginJ = json_object_object_get (idpJ, "plugin");
    if (pluginJ) {
        err = wrap_json_unpack (pluginJ, "{ss s?i s?i s?s s?b so !}"
            , "ldpath", &ldpath
            , "maxdev", &pcscOpts->readerMax
            , "maxlabel", &pcscOpts->labelMax
            , "avatar", &pcscOpts->avatarAlias
            , "verbose", &verbosity
            , "config", &pcscConfJ
        );
        if (err) {
            EXT_ERROR ("[pcsc-config-opts] json parse fail 'plugin':{'config':{myconf},'verbose':true,'avatar':'%s','maxdev':%d", pcscOpts->avatarAlias,pcscOpts->readerMax);
            goto OnErrorExit;
        }
    }

    pcscOpts->config= pcscParseConfig (pcscConfJ, verbosity);
    if (!pcscOpts->config) goto OnErrorExit;

    // create pcsc handle and set options
    pcscOpts->handle =pcscConnect (pcscOpts->config->reader);
    if (!pcscOpts->handle) {
        EXT_CRITICAL ("[pcsc-config-reader] Fail to connect to reader=%s\n", pcscOpts->config->reader);
        goto OnErrorExit;
    }

    // set reader option options
    pcscSetOpt (pcscOpts->handle, PCSC_OPT_VERBOSE, pcscOpts->config->verbose);
    pcscSetOpt (pcscOpts->handle, PCSC_OPT_TIMEOUT, pcscOpts->config->timeout);

    // only default profile is usefull
    oidcDefaultsT defaults = {
        .profiles = dfltProfiles,
        .statics = &dfltstatics,
        .credentials = &noCredentials,
        .wellknown = &dfltWellknown,
        .headers = &noHeaders,
    };

    // delegate config parsing to common idp utility callbacks
    err = idpCallbacks->parseConfig (idp, idpJ, &defaults, pcscOpts);
    if (err) goto OnErrorExit;

    return 0;

  OnErrorExit:
    return 1;
}

// pcsc sample plugin exposes only one IDP
idpPluginT idppcscAuth[] = {
    {.uid = "pcsc",.info = "SmartCard/NFC pscd client"
        ,.registerConfig = pcscRegisterConfig
        ,.registerApis = pcscRegisterApis
        ,.registerAlias= pcscRegisterAlias
        ,.resetSession = pcscResetSession
    },
    {.uid = NULL}               // must be null terminated
};

// Plugin init call at config.json parsing time
int oidcPluginInit (oidcCoreHdlT * oidc, idpGenericCbT * idpGenericCbs)
{
    assert (idpGenericCbs->magic == MAGIC_OIDC_CBS);    // check provided callback magic

    // plugin is already loaded
    if (idpCallbacks) return 0;
    idpCallbacks = idpGenericCbs;

    int status = idpCallbacks->pluginRegister ("pcsc-plugin", idppcscAuth);
    return status;
}
