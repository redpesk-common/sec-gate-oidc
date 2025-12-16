/*
 * Copyright (C) 2021 "IoT.bzh"
 * Author "Fulup Ar Foll" <fulup@iot.bzh>
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 *
 * WARNING: pcsc plugin requires read access to /etc/shadow
 * Reference:
 *  https://buzz.smartcardfocus.com/category/get-the-code/
 *  http://pcscworkgroup.com/Download/Specifications/pcsc3_v2.01.09_sup.pdf
 */

#define _GNU_SOURCE

#include <assert.h>
#include <locale.h>
#include <pcsclite.h>
#include <string.h>

#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <rp-utils/rp-escape.h>
#include <rp-utils/rp-jsonc.h>
#include <rp-utils/rp-enum-map.h>

#include <libafb/afb-core.h>
#include <libafb/afb-http.h>
#include <libafb/afb-v4.h>

#include "oidc-core.h"
#include "oidc-fedid.h"
#include "oidc-idp.h"
#include "oidc-session.h"
//#include "oidc-utils.h"
#include "pcsc-config.h"

// import pcsc-little API
#include "pcsc-config.h"
#include "pcsc-glue.h"

// keep track of oidc-idp.c generic utils callbacks
static idpGenericCbT *idpCallbacks = NULL;

// provide dummy default values to oidc callbacks
static const oidcCredentialsT noCredentials = {};
static const httpKeyValT noHeaders = {};

typedef struct
{
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
    {.loa = 1, .scope = "login"},
    {NULL}  // terminator
};

static const oidcStaticsT dfltstatics = {
    .aliasLogin = "/sgate/pcsc/login",
    .aliasLogo = "/sgate/pcsc/logo-64px.png",
    .sTimeout = 600};

static const oidcWellknownT dfltWellknown = {
    .tokenid = "/sgate/pcsc/login.html",
    .userinfo = NULL,
    .authorize = NULL,
};

typedef enum {
    PCSC_STATUS_UNKNOWN = 0,
    PCSC_STATUS_AUTHENTICATED,
    PCSC_STATUS_WAITING,
    PCSC_STATUS_REFUSED,

} pcscCardStatusE;

typedef struct
{
    ulong pin;
    idpRqtCtxT *idpRqtCtx;
    pcscOptsT *opts;
    const char *scope;
    const char *label;
    oidcSessionT *session;
    pcscCardStatusE status;
} pcscRqtCtxT;

static void pcscRqtCtxFree(pcscRqtCtxT *rqt)
{
    free(rqt);
}

// if needed stop pcsc thread when session finish
static void pcscResetSession(const oidcProfileT *idpProfile, void *ctx)
{
    pcscHandleT *handle = (pcscHandleT *)ctx;
    pcscMonitorWait(handle, PCSC_MONITOR_CANCEL, 0);
}

static int readerMonitorCB(pcscHandleT *handle, ulong state, void *ctx)
{
    extern const rp_enum_map_t oidcFedidSchema[];
    pcscRqtCtxT *pcscRqtCtx = (pcscRqtCtxT *)ctx;
    idpRqtCtxT *idpRqtCtx = pcscRqtCtx->idpRqtCtx;
    pcscOptsT *pcscOpts = pcscRqtCtx->opts;
    const oidcProfileT *idpProfile;
    int status = 0;
    int err;
    char *copy, *save;

    assert(pcscRqtCtx->session);

    // is card was previously inserted logout user (session loa=0)
    if (state & SCARD_STATE_EMPTY) {
        EXT_DEBUG("[pcsc-scard-absent] tid=0x%lx card=absent status=%d",
                  pthread_self(), pcscRqtCtx->status);
        // prevent double detection

        switch (pcscRqtCtx->status) {
            // session was authenticated logout session and kill thread
        case PCSC_STATUS_AUTHENTICATED:
            idpProfile = oidcSessionGetIdpProfile(pcscRqtCtx->session);
            fedidsessionReset(pcscRqtCtx->session, idpProfile);
            pcscRqtCtxFree(pcscRqtCtx);
            status = 1;  // terminate thread
            break;

            // scard was refused wait for card removal and restart a fresh
            // authen session
        case PCSC_STATUS_REFUSED:
            status = 1;
            break;

            // all other case just wait for new card insertion
        default:
            pcscRqtCtx->status = PCSC_STATUS_WAITING;
        }
    }

    else if (state & SCARD_STATE_PRESENT) {
        EXT_DEBUG(
            "[pcsc-scard-present] tid=0x%lx card=0x%lx ctx=0x%p status=%d",
            pthread_self(), pcscGetCardUuid(handle), pcscRqtCtx,
            pcscRqtCtx->status);

        // prevent from double detection
        if (pcscRqtCtx->status == PCSC_STATUS_WAITING) {
            // reserve federation and social user structure
            idpRqtCtx->fedSocial = calloc(1, sizeof(fedSocialRawT));
            idpRqtCtx->fedUser = calloc(1, sizeof(fedUserRawT));
            u_int64_t uuid;
            char *data = NULL;

            // map scope to pcsc commands
            copy = strdup(pcscRqtCtx->scope);
            if (copy == NULL)
                goto OnErrorExit;
            save = NULL;
            for (char *scope = strtok_r(copy, ",", &save);
                 scope; scope = strtok_r(NULL, ",", &save)) {
                pcscCmdT *cmd = pcscCmdByUid(pcscOpts->config, scope);
                if (!cmd) {
                    free(copy);
                    EXT_ERROR("[pcsc-cmd-uid] command=%s not found", scope);
                    goto OnErrorExit;
                }

                switch (cmd->action) {
                case PCSC_ACTION_UUID:
                    uuid = pcscGetCardUuid(handle);
                    if (uuid == 0) {
                        EXT_ERROR(
                            "[pcsc-cmd-uuid] command=%s fail getting uuid "
                            "error=%s",
                            cmd->uid, pcscErrorMsg(handle));
                        free(copy);
                        goto OnErrorExit;
                    }
                    idpRqtCtx->fedSocial->idp = strdup(idpRqtCtx->idp->uid);
                    asprintf((char **)&idpRqtCtx->fedSocial->fedkey, "%ld",
                             uuid);
                    break;

                case PCSC_ACTION_READ:
                    data = malloc(cmd->dlen);
                    err = pcscExecOneCmd(handle, cmd, (u_int8_t *)data);
                    if (err) {
                        EXT_ERROR(
                            "[pcsc-cmd-exec] command=%s execution fail "
                            "error=%s",
                            cmd->uid, pcscErrorMsg(handle));
                        free(copy);
                        goto OnErrorExit;
                    }
                    switch (rp_enum_map_value_def(oidcFedidSchema, cmd->uid, OIDC_SCHEMA_UNKNOWN)) {
                    case OIDC_SCHEMA_PSEUDO:
                        idpRqtCtx->fedUser->pseudo = strdup(data);
                        break;
                    case OIDC_SCHEMA_NAME:
                        idpRqtCtx->fedUser->name = strdup(data);
                        break;
                    case OIDC_SCHEMA_EMAIL:
                        idpRqtCtx->fedUser->email = strdup(data);
                        break;
                    case OIDC_SCHEMA_COMPANY:
                        idpRqtCtx->fedUser->company = strdup(data);
                        break;
                    case OIDC_SCHEMA_AVATAR:
                        idpRqtCtx->fedUser->avatar = strdup(data);
                        break;
                    default:
                        EXT_ERROR(
                            "[pcsc-cmd-schema] command=%s no schema mapping "
                            "[pseudo,name,email,company,avatar]",
                            cmd->uid);
                        free(copy);
                        goto OnErrorExit;
                    }
                    break;

                default:
                    EXT_ERROR(
                        "[pcsc-cmd-action] command=%s action=%d not supported "
                        "for authentication",
                        cmd->uid, cmd->action);
                        free(copy);
                    goto OnErrorExit;
                }
            }
            free(copy);

            // map security atributes to pcsc read commands
            if (pcscRqtCtx->label) {
                int index = 0;
                idpRqtCtx->fedSocial->attrs =
                    calloc(pcscOpts->labelMax + 1, sizeof(char *));
                copy = strdup(pcscRqtCtx->label);
                if (copy == NULL)
                    goto OnErrorExit;
                save = NULL;
                for (char *label = strtok_r(copy, ",", &save);
                     label; label = strtok_r(NULL, ",", &save)) {
                    pcscCmdT *cmd = pcscCmdByUid(pcscOpts->config, label);
                    if (!cmd || cmd->action != PCSC_ACTION_READ) {
                        EXT_ERROR(
                            "[pcsc-cmd-label] label=%s does does match any "
                            "read command",
                            label);
                        free(copy);
                        goto OnErrorExit;
                    }

                    err =
                        pcscExecOneCmd(pcscOpts->handle, cmd, (u_int8_t *)data);
                    if (err) {
                        EXT_ERROR(
                            "[pcsc-cmd-label] command=%s execution fail "
                            "error=%s",
                            cmd->uid, pcscErrorMsg(handle));
                        free(copy);
                        goto OnErrorExit;
                    }
                    // parse attrs string to extract multi-attributes if any
                    char *copy2, *save2;
                    copy2 = strdup(data); /* !!! TODO check origin of data !!! */
                    if (copy2 == NULL)
                        goto OnErrorExit;
                    save2 = NULL;
                    for (char *attr = strtok_r(copy2, ",", &save2);
                         attr; attr = strtok_r(NULL, ",", &save2)) {
                        idpRqtCtx->fedSocial->attrs[index++] = strdup(attr);
                        if (index == pcscOpts->labelMax) {
                            EXT_ERROR(
                                "[pcsc-cmd-label] ignored labels command=%s "
                                "maxlabel=%d too small labels=%s",
                                cmd->uid, pcscOpts->labelMax,
                                pcscRqtCtx->scope);
                            /* !!! TODO and continue to loop ???? */
                        }
                    }
                    free(copy2);
                }
                free(copy);
            }
            // try do federate user
            idpRqtCtx->userData = (void *)handle;
            err = fedidCheck(idpRqtCtx);
            if (err)
                goto OnErrorExit;

            // authentication was successful
            pcscRqtCtx->status = PCSC_STATUS_AUTHENTICATED;
        }
    }
    // we done idpRqtCtx is cleared by fedidCheck
    return status;

OnErrorExit: {
    static char errorMsg[] =
        "[pcsc-scard-fail] invalid token/smartcard (check scard/config)";
    EXT_CRITICAL(errorMsg);
    if (idpRqtCtx->hreq) {
        afb_hreq_reply_error(idpRqtCtx->hreq, EXT_HTTP_UNAUTHORIZED);
    }
    else {
        afb_data_t reply;
        afb_create_data_raw(&reply, AFB_PREDEFINED_TYPE_STRINGZ, errorMsg,
                            sizeof(errorMsg), NULL, NULL);
        afb_req_v4_reply_hookable(idpRqtCtx->wreq, -1, 1, &reply);
    }
}
    pcscRqtCtx->status = PCSC_STATUS_REFUSED;
    fedSocialUnRef(idpRqtCtx->fedSocial);
    fedUserUnRef(idpRqtCtx->fedUser);
    return 0;  // keep thread waiting for card to be removed
}

// check pcsc login/passwd using scope as pcsc application
static int pcscScardGet(oidcIdpT *idp,
                        const oidcProfileT *profile,
                        ulong pin,
                        afb_hreq *hreq,
                        struct afb_req_v4 *wreq)
{
    pcscOptsT *pcscOpts = (pcscOptsT *)idp->ctx;

    // store pcsc context within idp request one
    idpRqtCtxT *idpRqtCtx = calloc(1, sizeof(idpRqtCtxT));
    idpRqtCtx->hreq = hreq;
    idpRqtCtx->wreq = wreq;
    idpRqtCtx->idp = idp;

    // prepare context for pcsc monitor callbacks
    pcscRqtCtxT *pcscRqtCtx = calloc(1, sizeof(pcscRqtCtxT));
    pcscRqtCtx->pin = pin;
    pcscRqtCtx->scope = profile->scope;
    pcscRqtCtx->label = profile->attrs;
    pcscRqtCtx->opts = pcscOpts;
    pcscRqtCtx->idpRqtCtx = idpRqtCtx;

    if (idpRqtCtx->hreq)
        pcscRqtCtx->session = oidcSessionOfHttpReq(idpRqtCtx->hreq);
    if (idpRqtCtx->wreq)
        pcscRqtCtx->session = oidcSessionOfReq(wreq);

    ulong tid = pcscMonitorReader(pcscOpts->handle, readerMonitorCB,
                                  (void *)pcscRqtCtx);
    if (tid <= 0)
        goto OnErrorExit;

    return 0;

OnErrorExit:
    pcscRqtCtxFree(pcscRqtCtx);
    return -1;
}

// check user email/pseudo attribute
static void checkLoginVerb(struct afb_req_v4 *wreq,
                           unsigned nparams,
                           struct afb_data *const params[])
{
    const char *errmsg =
        "[pcsc-login-fail] invalid credentials (insert a valid scard)";
    oidcIdpT *idp = (oidcIdpT *)afb_req_v4_vcbdata(wreq);
    struct afb_data *args[nparams];
    const char *scope = NULL;
    const oidcProfileT *profile = NULL;
    afb_data_t reply;
    const char *state;
    ulong pinCode;
    int targetLOA;
    int err;

    err = afb_data_convert(params[0], &afb_type_predefined_json_c, &args[0]);
    json_object *queryJ = afb_data_ro_pointer(args[0]);
    err = rp_jsonc_unpack(queryJ, "{ss s?i s?s}", "state", &state, "pin",
                          &pinCode, "scope", &scope);
    if (err)
        goto OnErrorExit;

    // search for a scope fiting wreqing loa
    oidcSessionT *session = oidcSessionOfReq(wreq);
    if (!state || strcmp(state, oidcSessionUUID(session)))
        goto OnErrorExit;

    targetLOA = oidcSessionGetTargetLOA(session);

    // search for a matching profile if scope is selected then scope&loa should
    // match
    for (int idx = 0; idp->profiles[idx].uid; idx++) {
        profile = &idp->profiles[idx];
        if (idp->profiles[idx].loa >= targetLOA) {
            if (scope && strcasecmp(scope, idp->profiles[idx].scope))
                continue;
            profile = &idp->profiles[idx];
            break;
        }
    }
    if (!profile) {
        EXT_NOTICE("[pcsc-check-scope] scope=%s does not match working loa=%d",
                   scope, targetLOA);
        goto OnErrorExit;
    }
    // store working profile to retreive attached loa and role filter if login
    // succeeded
    oidcSessionSetIdpProfile(session, profile);

    // try to access smart card
    err = pcscScardGet(idp, profile, pinCode, /*hreq */ NULL, wreq);
    if (err)
        goto OnErrorExit;

    // response is handle asynchronously
    afb_req_addref(wreq);
    return;

OnErrorExit:
    afb_create_data_raw(&reply, AFB_PREDEFINED_TYPE_STRINGZ, errmsg,
                        strlen(errmsg) + 1, NULL, NULL);
    afb_req_v4_reply_hookable(wreq, -1, 1, &reply);
}

// when call with no login/passwd display form otherwise try to log user
int pcscLoginCB(afb_hreq *hreq, void *ctx)
{
    oidcIdpT *idp = (oidcIdpT *)ctx;
    assert(idp->magic == MAGIC_OIDC_IDP);
    const oidcProfileT *profile = NULL;
    int err, targetLOA;

    // Initial redirect redirect user on web page to enter login
    char url[EXT_URL_MAX_LEN];

    oidcSessionT *session = oidcSessionOfHttpReq(hreq);
    targetLOA = oidcSessionGetTargetLOA(session);

    // search a working loa scope
    const char *scope = afb_hreq_get_argument(hreq, "scope");
    // search for a scope fiting wreqing loa
    for (int idx = 0; idp->profiles[idx].uid; idx++) {
        profile = &idp->profiles[idx];
        if (idp->profiles[idx].loa >= targetLOA) {
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
    oidcSessionSetIdpProfile(session, profile);

    const char *params[] = {
        "state",    oidcSessionUUID(session),
        "scope",    profile->scope,
#if FORCELANG
        "language", setlocale(LC_CTYPE, ""),
#endif
        NULL  // terminator
    };

    // build wreq and send it
    size_t sz = rp_escape_url_to(NULL, idp->wellknown->tokenid, params, url,
                                 sizeof url);
    if (sz >= sizeof url)
        goto OnErrorExit;

    EXT_DEBUG("[pcsc-redirect-url] %s (pcscLoginCB)", url);
    afb_hreq_redirect_to(hreq, url, HREQ_QUERY_EXCL, HREQ_REDIR_TMPY);

    return 1;  // we're done

OnErrorExit:
    afb_hreq_redirect_to(hreq, idp->oidc->globals.loginUrl, HREQ_QUERY_INCL,
                         HREQ_REDIR_TMPY);
    return 1;
}

int pcscRegisterApis(oidcIdpT *idp,
                     struct afb_apiset *declare_set,
                     struct afb_apiset *call_set)
{
    int err;

    // add a dedicate verb to check login/passwd from websocket
    // err= afb_api_add_verb(idp->oidc->apiv4, idp->uid, idp->info,
    // checkLoginVerb, idp, NULL, 0, 0);
    err = afb_api_v4_add_verb_hookable(idp->oidc->apiv4, idp->uid, idp->info,
                                       checkLoginVerb, idp, NULL, 0, 0);
    if (err)
        goto OnErrorExit;
    return 0;

OnErrorExit:
    return 1;
}

static int pcscRegisterAlias(oidcIdpT *idp, afb_hsrv *hsrv)
{
    int err;
    EXT_DEBUG("[pcsc-register-alias] uid=%s login='%s'", idp->uid,
              idp->statics->aliasLogin);

    err = afb_hsrv_add_handler(hsrv, idp->statics->aliasLogin, pcscLoginCB, idp,
                               EXT_HIGHEST_PRIO);
    if (!err)
        goto OnErrorExit;

    return 0;

OnErrorExit:
    EXT_ERROR(
        "[pcsc-register-alias] idp=%s fail to register alias=%s "
        "(pcscRegisterAlias)",
        idp->uid, idp->statics->aliasLogin);
    return 1;
}

// pcsc is a fake openid authority as it get everyting locally
static int pcscRegisterConfig(oidcIdpT *idp, json_object *idpJ)
{
    int err;
    pcscOptsT *pcscOpts = malloc(sizeof(pcscOptsT));
    memcpy(pcscOpts, &dfltOpts, sizeof(pcscOptsT));
    json_object *pcscConfJ;
    int verbosity;
    const char *ldpath;

    // check is we have custom options
    json_object *pluginJ = json_object_object_get(idpJ, "plugin");
    if (pluginJ) {
        err = rp_jsonc_unpack(pluginJ, "{ss s?i s?i s?s s?b so !}", "ldpath",
                              &ldpath, "maxdev", &pcscOpts->readerMax,
                              "maxlabel", &pcscOpts->labelMax, "avatar",
                              &pcscOpts->avatarAlias, "verbose", &verbosity,
                              "config", &pcscConfJ);
        if (err) {
            EXT_ERROR(
                "[pcsc-config-opts] json parse fail "
                "'plugin':{'config':{myconf},'verbose':true,'avatar':'%s','"
                "maxdev':%d",
                pcscOpts->avatarAlias, pcscOpts->readerMax);
            goto OnErrorExit;
        }
    }

    pcscOpts->config = pcscParseConfig(pcscConfJ, verbosity);
    if (!pcscOpts->config)
        goto OnErrorExit;

    // create pcsc handle and set options
    pcscOpts->handle =
        pcscConnect(pcscOpts->config->uid, pcscOpts->config->reader);
    if (!pcscOpts->handle) {
        EXT_CRITICAL("[pcsc-config-reader] Fail to connect to reader=%s\n",
                     pcscOpts->config->reader);
        goto OnErrorExit;
    }
    // set reader option options
    pcscSetOpt(pcscOpts->handle, PCSC_OPT_VERBOSE, pcscOpts->config->verbose);
    pcscSetOpt(pcscOpts->handle, PCSC_OPT_TIMEOUT, pcscOpts->config->timeout);

    // only default profile is usefull
    oidcDefaultsT defaults = {
        .profiles = dfltProfiles,
        .statics = &dfltstatics,
        .credentials = &noCredentials,
        .wellknown = &dfltWellknown,
        .headers = &noHeaders,
    };

    // delegate config parsing to common idp utility callbacks
    err = idpCallbacks->parseConfig(idp, idpJ, &defaults, pcscOpts);
    if (err)
        goto OnErrorExit;

    return 0;

OnErrorExit:
    return 1;
}

// pcsc sample plugin exposes only one IDP
static const idpPluginT idppcscAuth = {
    .uid = "pcsc",
    .info = "SmartCard/NFC pscd client",
    .registerConfig = pcscRegisterConfig,
    .registerApis = pcscRegisterApis,
    .registerAlias = pcscRegisterAlias,
    .resetSession = pcscResetSession
};

// Plugin init call at config.json parsing time
int oidcPluginInit(oidcCoreHdlT *oidc, idpGenericCbT *idpGenericCbs)
{
    assert(idpGenericCbs->magic ==
           MAGIC_OIDC_CBS);  // check provided callback magic

    // plugin is already loaded
    if (idpCallbacks)
        return 0;
    idpCallbacks = idpGenericCbs;

    int status = idpCallbacks->pluginRegister(&idppcscAuth);
    return status;
}
