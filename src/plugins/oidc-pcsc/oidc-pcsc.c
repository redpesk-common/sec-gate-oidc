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

#include <rp-utils/rp-enum-map.h>
#include <rp-utils/rp-escape.h>
#include <rp-utils/rp-jsonc.h>

#include <libafb/afb-core.h>
#include <libafb/afb-http.h>
#include <libafb/afb-v4.h>

#include "oidc-core.h"
#include "oidc-login.h"
#include "oidc-idp-plugin.h"
#include "oidc-idp.h"
#include "oidc-session.h"

// import pcsc-little API
#include "pcsc-config.h"
#include "pcsc-glue.h"

// provide dummy default values to oidc callbacks
static const oidcCredentialsT noCredentials = {};
static const httpKeyValT noHeaders = {};

typedef enum {
    OIDC_SCHEMA_UNKNOWN = 0,
    OIDC_SCHEMA_PSEUDO,
    OIDC_SCHEMA_NAME,
    OIDC_SCHEMA_EMAIL,
    OIDC_SCHEMA_AVATAR,
    OIDC_SCHEMA_COMPANY,
} oidcFedidSchemaE;

// clang-format off
static const rp_enum_map_t oidcFedidSchema[] = {
    {"pseudo", OIDC_SCHEMA_PSEUDO},
    {"name", OIDC_SCHEMA_NAME},
    {"email", OIDC_SCHEMA_EMAIL},
    {"avatar", OIDC_SCHEMA_AVATAR},
    {"company", OIDC_SCHEMA_COMPANY},
    {NULL}                      // terminator
};
// clang-format on

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
    oidcStateT *state;
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

static int readerMonitorCB(pcscHandleT *handle, ulong status, void *ctx)
{
    pcscRqtCtxT *pcscRqtCtx = (pcscRqtCtxT *)ctx;
    oidcStateT *state = pcscRqtCtx->state;
    pcscOptsT *pcscOpts = pcscRqtCtx->opts;
    int result = 0;
    int err;
    char *copy, *save;

    assert(pcscRqtCtx->session);

    // is card was previously inserted logout user (session loa=0)
    if (status & SCARD_STATE_EMPTY) {
        EXT_DEBUG("[oidc-psc] tid=0x%lx card=absent status=%d",
                  pthread_self(), pcscRqtCtx->status);
        // prevent double detection

        switch (pcscRqtCtx->status) {
            // session was authenticated logout session and kill thread
        case PCSC_STATUS_AUTHENTICATED:
            oidcSessionReset(pcscRqtCtx->session);
            pcscRqtCtxFree(pcscRqtCtx);
            result = 1;  // terminate thread
            break;

            // scard was refused wait for card removal and restart a fresh
            // authen session
        case PCSC_STATUS_REFUSED:
            result = 1;
            break;

            // all other case just wait for new card insertion
        default:
            pcscRqtCtx->status = PCSC_STATUS_WAITING;
        }
    }

    else if (status & SCARD_STATE_PRESENT) {
        fedUserRawT *fedUser = oidcStateGetUser(state);
        fedSocialRawT *fedSocial = oidcStateGetSocial(state);

        EXT_DEBUG(
            "[oidc-psc] tid=0x%lx card=0x%lx ctx=0x%p status=%d",
            pthread_self(), pcscGetCardUuid(handle), (void*)pcscRqtCtx,
            pcscRqtCtx->status);

        // prevent from double detection
        if (pcscRqtCtx->status == PCSC_STATUS_WAITING) {
            // reserve federation and social user structure
            u_int64_t uuid;
            char *data = NULL;

            // map scope to pcsc commands
            copy = strdup(pcscRqtCtx->scope);
            if (copy == NULL)
                goto OnErrorExit;
            save = NULL;
            for (char *scope = strtok_r(copy, ",", &save); scope;
                 scope = strtok_r(NULL, ",", &save)) {
                pcscCmdT *cmd = pcscCmdByUid(pcscOpts->config, scope);
                if (!cmd) {
                    free(copy);
                    EXT_ERROR("[oidc-psc] command=%s not found", scope);
                    goto OnErrorExit;
                }

                switch (cmd->action) {
                case PCSC_ACTION_UUID:
                    uuid = pcscGetCardUuid(handle);
                    if (uuid == 0) {
                        EXT_ERROR(
                            "[oidc-psc] command=%s fail getting uuid "
                            "error=%s",
                            cmd->uid, pcscErrorMsg(handle));
                        free(copy);
                        goto OnErrorExit;
                    }
                    if (0 > asprintf((char **)&fedSocial->fedkey, "%llu",
                                     (unsigned long long)uuid)) {
                        EXT_ERROR("Out of memory");
                        goto OnErrorExit;
                    }
                    break;

                case PCSC_ACTION_READ:
                    data = malloc(cmd->dlen);
                    err = pcscExecOneCmd(handle, cmd, (u_int8_t *)data);
                    if (err) {
                        EXT_ERROR(
                            "[oidc-psc] command=%s execution fail "
                            "error=%s",
                            cmd->uid, pcscErrorMsg(handle));
                        free(data);
                        free(copy);
                        goto OnErrorExit;
                    }
                    switch (rp_enum_map_value_def(oidcFedidSchema, cmd->uid,
                                                  OIDC_SCHEMA_UNKNOWN)) {
                    case OIDC_SCHEMA_PSEUDO:
                        fedUser->pseudo = strdup(data);
                        break;
                    case OIDC_SCHEMA_NAME:
                        fedUser->name = strdup(data);
                        break;
                    case OIDC_SCHEMA_EMAIL:
                        fedUser->email = strdup(data);
                        break;
                    case OIDC_SCHEMA_COMPANY:
                        fedUser->company = strdup(data);
                        break;
                    case OIDC_SCHEMA_AVATAR:
                        fedUser->avatar = strdup(data);
                        break;
                    default:
                        EXT_ERROR(
                            "[oidc-psc] command=%s no schema mapping "
                            "[pseudo,name,email,company,avatar]",
                            cmd->uid);
                        free(data);
                        free(copy);
                        goto OnErrorExit;
                    }
                    free(data); /* not used directly for when copy is shorter */
                    break;

                default:
                    EXT_ERROR(
                        "[oidc-psc] command=%s action=%d not supported "
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
                fedSocial->attrs =
                    calloc(pcscOpts->labelMax + 1, sizeof(char *));
                copy = strdup(pcscRqtCtx->label);
                if (copy == NULL)
                    goto OnErrorExit;
                save = NULL;
                for (char *label = strtok_r(copy, ",", &save); label;
                     label = strtok_r(NULL, ",", &save)) {
                    pcscCmdT *cmd = pcscCmdByUid(pcscOpts->config, label);
                    if (!cmd || cmd->action != PCSC_ACTION_READ) {
                        EXT_ERROR(
                            "[oidc-psc] label=%s does does match any "
                            "read command",
                            label);
                        free(copy);
                        goto OnErrorExit;
                    }

                    data = malloc(cmd->dlen);
                    err =
                        pcscExecOneCmd(pcscOpts->handle, cmd, (u_int8_t *)data);
                    if (err) {
                        EXT_ERROR(
                            "[oidc-psc] command=%s execution fail "
                            "error=%s",
                            cmd->uid, pcscErrorMsg(handle));
                        free(copy);
                        goto OnErrorExit;
                    }
                    // parse attrs string to extract multi-attributes if any
                    char *save2 = NULL;
                    for (char *attr = strtok_r(data, ",", &save2); attr;
                         attr = strtok_r(NULL, ",", &save2)) {
                        fedSocial->attrs[index++] = strdup(attr);
                        if (index == pcscOpts->labelMax) {
                            EXT_ERROR(
                                "[oidc-psc] ignored labels command=%s "
                                "maxlabel=%d too small labels=%s",
                                cmd->uid, pcscOpts->labelMax,
                                pcscRqtCtx->scope);
                            /* !!! TODO and continue to loop ???? */
                        }
                    }
                    free(data);
                }
                free(copy);
            }
            // try do federate user
            oidcLogin(state);

            // authentication was successful
            pcscRqtCtx->status = PCSC_STATUS_AUTHENTICATED;
        }
    }
    return result;

OnErrorExit:
    EXT_CRITICAL("[oidc-psc] invalid token/smartcard (check scard/config)");
    oidcStateReplyUnauthorized(state);
    pcscRqtCtx->status = PCSC_STATUS_REFUSED;
    return 0;  // keep thread waiting for card to be removed
}

// check pcsc login/passwd using scope as pcsc application
static int pcscScardGet(oidcStateT *state, ulong pin)
{
    pcscOptsT *pcscOpts = (pcscOptsT *)oidcStateGetIdp(state)->ctx;
    const oidcProfileT *profile = oidcStateGetProfile(state);

    // prepare context for pcsc monitor callbacks
    pcscRqtCtxT *pcscRqtCtx = calloc(1, sizeof(pcscRqtCtxT));
    pcscRqtCtx->pin = pin;
    pcscRqtCtx->scope = profile->scope;
    pcscRqtCtx->label = profile->attrs;
    pcscRqtCtx->opts = pcscOpts;
    pcscRqtCtx->session = oidcStateGetSession(state);
    pcscRqtCtx->state = state;

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
    const oidcIdpT *idp = (const oidcIdpT *)afb_req_v4_vcbdata(wreq);
    struct afb_data *data;
    json_object *queryJ;
    const char *scope = NULL;
    oidcSessionT *session;
    oidcStateT *state;
    const char *stateid;
    ulong pinCode;
    int targetLOA;
    int err;

    err = afb_req_param_convert(wreq, 0, &afb_type_predefined_json_c, &data);
    if (err >= 0) {
        queryJ = afb_data_ro_pointer(data);
        err = rp_jsonc_unpack(queryJ, "{ss s?i s?s}", "state", &stateid, "pin",
                              &pinCode, "scope", &scope);
    }
    if (err < 0)
        goto OnErrorExit;

    // search for a scope fiting wreqing loa
    session = oidcSessionOfReq(wreq);
    if (!stateid || strcmp(stateid, oidcSessionUUID(session)))
        goto OnErrorExit;

    targetLOA = oidcSessionGetTargetLOA(session);

    err = idpMakeState(idp, targetLOA, scope, session, &state);
    if (err <= 0) {
        EXT_NOTICE("[oidc-psc] can't get state for scope=%s and loa=%d (got %d)",
                   scope, targetLOA, err);
        goto OnErrorExit;
    }
    oidcStateSetAfbReq(state, wreq);

    // store working profile to retrieve attached loa and role filter if login
    // succeeded
    oidcSessionSetTargetState(session, state);

    // try to access smart card
    err = pcscScardGet(state, pinCode);
    if (err)
        goto OnErrorExit;

    return;

OnErrorExit:
    afb_req_v4_reply_hookable(wreq, AFB_ERRNO_INVALID_REQUEST, 0, NULL);
}

// when call with no login/passwd display form otherwise try to log user
int pcscLoginCB(struct afb_hreq *hreq, void *ctx)
{
    const oidcIdpT *idp = (const oidcIdpT *)ctx;
    oidcSessionT *session = oidcSessionOfHttpReq(hreq);

    return idpRedirectLogin(idp, hreq, session, idp->wellknown->tokenid, NULL,
                            NULL, NULL, NULL);
}

int pcscRegisterVerbs(const oidcIdpT *idp, struct afb_api_v4 *sgApi)
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

static int pcscRegisterAlias(const oidcIdpT *idp, struct afb_hsrv *hsrv)
{
    int err;
    EXT_DEBUG("[oidc-psc] uid=%s login='%s'", idp->uid,
              idp->statics->aliasLogin);

    err = afb_hsrv_add_handler(hsrv, idp->statics->aliasLogin, pcscLoginCB,
                               (void *)idp, EXT_HIGHEST_PRIO);
    if (!err)
        goto OnErrorExit;

    return 0;

OnErrorExit:
    EXT_ERROR(
        "[oidc-psc] idp=%s fail to register alias=%s "
        "(pcscRegisterAlias)",
        idp->uid, idp->statics->aliasLogin);
    return 1;
}

// pcsc is a fake openid authority as it get everyting locally
static int pcscRegisterConfig(oidcIdpT *idp, json_object *idpJ)
{
    int err;
    json_object *pcscConfJ = NULL;
    int verbosity = 0;
    const char *ldpath;
    pcscOptsT *pcscOpts = malloc(sizeof(pcscOptsT));
    memcpy(pcscOpts, &dfltOpts, sizeof(pcscOptsT));

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
                "[oidc-psc] json parse fail "
                "'plugin':{'config':{myconf},'verbose':true,'avatar':'%s','"
                "maxdev':%d",
                pcscOpts->avatarAlias, pcscOpts->readerMax);
            goto OnErrorExit;
        }
    }
    else
        pcscConfJ = json_object_object_get(idpJ, "config");

    pcscOpts->config = pcscParseConfig(pcscConfJ, verbosity);
    if (!pcscOpts->config)
        goto OnErrorExit;

    // create pcsc handle and set options
    pcscOpts->handle =
        pcscConnect(pcscOpts->config->uid, pcscOpts->config->reader);
    if (!pcscOpts->handle) {
        EXT_CRITICAL("[oidc-psc] Fail to connect to reader=%s\n",
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
    err = idpParseOidcConfig(idp, idpJ, &defaults, pcscOpts);
    if (err)
        goto OnErrorExit;

    return 0;

OnErrorExit:
    return 1;
}

// pcsc sample plugin exposes only one IDP
static const idpPluginT idppcscAuth = {.uid = "pcsc",
                                       .info = "SmartCard/NFC pscd client",
                                       .registerConfig = pcscRegisterConfig,
                                       .registerVerbs = pcscRegisterVerbs,
                                       .registerAlias = pcscRegisterAlias,
                                       .resetSession = pcscResetSession};

// Plugin init call at config.json parsing time
int oidcPluginInit(oidcCoreHdlT *oidc)
{
    return idpPluginRegister(&idppcscAuth);
}
