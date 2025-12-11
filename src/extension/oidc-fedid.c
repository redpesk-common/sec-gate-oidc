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
 */

#include <assert.h>
#include <locale.h>
#include <string.h>

#include <rp-utils/rp-escape.h>
#include <rp-utils/rp-jsonc.h>
#include <rp-utils/rp-enum-map.h>

#include <libafb/afb-core.h>
#include <libafb/afb-http.h>
#include <libafb/afb-v4.h>

#include <fedid-types-glue.h>

#include <curl-glue.h>
#include "oidc-alias.h"
#include "oidc-core.h"
#include "oidc-fedid.h"
#include "oidc-idsvc.h"
#include "oidc-session.h"
//#include "oidc-utils.h"

// clang-format off
const rp_enum_map_t oidcFedidSchema[] = {
    {"pseudo", OIDC_SCHEMA_PSEUDO},
    {"name", OIDC_SCHEMA_NAME},
    {"email", OIDC_SCHEMA_EMAIL},
    {"avatar", OIDC_SCHEMA_AVATAR},
    {"company", OIDC_SCHEMA_COMPANY},
    {NULL}  // terminator
};
// clang-format on

// session timeout, reset LOA
void fedidsessionReset(oidcSessionT *session, const oidcProfileT *idpProfile)
{
    int err;
    int count = -1;

    // reset session and alias LOA (this will force authentication)
    oidcSessionSetLOA(session, 0);
    oidcSessionSetExpiration(session, 0);
    EXT_DEBUG("[fedid-session-reset] logout/timeout session uuid=%s ?",
              oidcSessionUUID(session));

    if (idpProfile) {
        if (idpProfile->idp->plugin && idpProfile->idp->plugin->resetSession) {
            void *ctx = oidcSessionGetOpaqueData(session);
            if (ctx != NULL) {
                idpProfile->idp->plugin->resetSession(idpProfile, ctx);
                oidcSessionSetOpaqueData(session, NULL);
            }
        }

        json_object *eventJ;
        err = rp_jsonc_pack(&eventJ, "{ss ss ss* ss*}", "status", "loa-reset",
                            "home",
                            idpProfile->idp->oidc->globals.homeUrl ?: "/",
                            "login", idpProfile->idp->oidc->globals.loginUrl,
                            "error", idpProfile->idp->oidc->globals.errorUrl);
        if (!err)
            count = idscvPushEvent(session, eventJ);
        if (!count)
            EXT_DEBUG("[fedid-session-reset] no client subscribed uuid=%s ?",
                      oidcSessionUUID(session));
    }
}

static void fedidTimerCB(int signal, void *ctx)
{
    oidcSessionT *session = (oidcSessionT *)ctx;
    const oidcProfileT *idpProfile;

    // signal should be null
    if (signal)
        return;
    idpProfile = oidcSessionGetIdpProfile(session);
    fedidsessionReset(session, idpProfile);
}

// if fedkey exists callback receive local store user profile otherwise we
// should create it
static void fedidCheckCB(void *ctx,
                         int status,
                         unsigned argc,
                         afb_data_x4_t const argv[],
                         struct afb_api_v4 *api)
{
    char *errorMsg =
        "[invalid-profile] Fail to process user profile (fedidCheckCB)";
    idpRqtCtxT *idpRqtCtx = (idpRqtCtxT *)ctx;
    char url[EXT_URL_MAX_LEN];
    const char *target;
    afb_data_x4_t reply[1], argd[argc];
    fedUserRawT *fedUser;
    const oidcProfileT *idpProfile;
    const oidcAliasT *alias;
    oidcSessionT *session = NULL;
    const char *redirect;
    afb_hreq *hreq = NULL;
    struct afb_req_v4 *wreq = NULL;
    int err;

    // internal API error
    if (status < 0)
        goto OnErrorExit;

    // session is in hreq for REST and in comreq for wbesocket
    if (idpRqtCtx->hreq) {
        hreq = idpRqtCtx->hreq;
        session = oidcSessionOfHttpReq(idpRqtCtx->hreq);
    }

    if (idpRqtCtx->wreq) {
        wreq = idpRqtCtx->wreq;
        session = oidcSessionOfReq(wreq);
    }

    if (!session) {
        EXT_DEBUG("[fedid-register-fail] session missing");
        goto OnErrorExit;
    }

    // user try to login if loa set then reset session
    int sessionLoa = oidcSessionGetLOA(session);
    if (sessionLoa)
        fedidsessionReset(session, NULL);

    idpProfile = oidcSessionGetIdpProfile(session);

    if (argc != 1) {  // fedid is not registered and we are not facing a
                      // secondary authentication
        const char *targetUrl;

        // fedkey not found let's store social authority profile into session
        // and redirect user on userprofil creation
        oidcSessionSetFedUser(session, idpRqtCtx->fedUser);
        oidcSessionSetFedSocial(session, idpRqtCtx->fedSocial);
        if (idpProfile->slave) {
            targetUrl = idpRqtCtx->idp->oidc->globals.fedlinkUrl;
            oidcSessionSetFedIdLinkRequest(session, FEDID_LINK_REQUESTED);
        }
        else {
            targetUrl = idpRqtCtx->idp->oidc->globals.registerUrl;
        }
        if (hreq) {
            const char *params[] = {
#if FORCELANG
                "language", setlocale(LC_CTYPE, ""),
#endif
                NULL};
            size_t sz =
                rp_escape_url_to(NULL, targetUrl, params, url, sizeof url);
            if (sz >= sizeof url) {
                EXT_ERROR(
                    "[fedid-register-unknown] fail to build redirect url");
                goto OnErrorExit;
            }
        }
        else {
            target = targetUrl;
        }
    }
    else {  // fedid is already registered

        err = afb_data_convert(argv[0], fedUserObjType, &argd[0]);
        if (err < 0)
            goto OnErrorExit;
        fedUser = (fedUserRawT *)afb_data_ro_pointer(argd[0]);

        // check if federation linking is pending
        const fedSocialRawT *fedSocial;
        fedSocial = oidcSessionGetFedSocial(session);
        int fedLoa = oidcSessionGetFedIdLinkRequest(session);

        // if we have to link two accounts do it before cleaning
        if (fedLoa == FEDID_LINK_REQUESTED) {
            assert(fedSocial);
            afb_data_x4_t params[2];
            int status;
            unsigned int count;
            afb_data_t data;

            // make sure we do not link account twice
            oidcSessionSetFedIdLinkRequest(session, FEDID_LINK_RESET);

            // delegate account federation linking to fedid binding
            params[0] = afb_data_addref(argd[0]);
            err = afb_create_data_raw(&params[1], fedSocialObjType, fedSocial,
                                      0, NULL, NULL);
            if (err < 0)
                goto OnErrorExit;
            err = afb_api_v4_call_sync_hookable(api, API_OIDC_USR_SVC,
                                                "user-federate", 2, params,
                                                &status, &count, &data);
            if (err < 0 || status != 0) {
                EXT_ERROR(
                    "[fedid-link-account] fail to link account pseudo=%s "
                    "email=%s",
                    fedUser->pseudo, fedUser->email);
                goto OnErrorExit;
            }
        }
        // let's store user profile into session cookie (/oidc/profile/get
        // serves it)
        oidcSessionSetFedUser(session, fedUserAddRef(fedUser));
        oidcSessionSetFedSocial(session, idpRqtCtx->fedSocial);

        // everyting looks good let's return user to original page
        idpProfile = oidcSessionGetIdpProfile(session);
        alias = oidcSessionGetAlias(session);

        size_t sz = rp_escape_url_to(NULL, alias->url, NULL, url, sizeof url);
        if (sz >= sizeof url) {
            EXT_ERROR("[fedid-register-exist] fail to build redirect url");
            goto OnErrorExit;
        }

        if (hreq) {
            // add afb-binder endpoint to login redirect alias
            err = afb_hreq_make_here_url(hreq, alias->url, url, sizeof(url));
            if (err < 0) {
                EXT_ERROR("[fedid-register-exist] fail to build redirect url");
                goto OnErrorExit;
            }
        }
        else {
            target = alias->url;
        }

        // if idp session as a timeout start a rtimer
        if (idpProfile->sTimeout) {
            fedidSessionT *fedSession = oidcSessionGetFedId(session);
            if (fedSession && fedSession->timerId) {
                afb_jobs_abort(fedSession->timerId);
                fedSession->timerId = 0;
            }
            else {
                fedSession = calloc(1, sizeof(fedSession));
                oidcSessionSetFedId(session, fedSession);
            }

#if LIBAFB_BEFORE_VERSION(4, 0, 4)
            fedSession->timerId =
                afb_sched_post_job(NULL /*group */, idpProfile->sTimeout * 1000,
                                   0 /*max-exec-time */, fedidTimerCB, session);
#else
            fedSession->timerId =
                afb_sched_post_job(NULL /*group */, idpProfile->sTimeout * 1000,
                                   0 /*max-exec-time */, fedidTimerCB, session,
                                   Afb_Sched_Mode_Normal);
#endif
            if (fedSession->timerId < 0) {
                EXT_ERROR(
                    "[fedid-register-timeout] fail to set idp profile session "
                    "loa");
                goto OnErrorExit;
            }
        }
        // user successfully loggin set session loa to current idp login profile
        oidcSessionSetLOA(session, idpProfile->loa);

        // if idp request get userdata keep track of them (needed by pcscd to
        // kill monitoring thread)
        if (idpRqtCtx->userData)
            oidcSessionSetOpaqueData(session, idpRqtCtx->userData);
    }

    // free user info handle and redirect to initial targeted url
    if (hreq) {
        EXT_DEBUG("[fedid-check-redirect] redirect to %s", url);
        afb_hreq_redirect_to(hreq, url, HREQ_QUERY_EXCL, HREQ_REDIR_TMPY);
    }
    else {
        struct afb_data *reply;
        json_object *responseJ;

        rp_jsonc_pack(&responseJ, "{ss}", "target", target);

        EXT_DEBUG("[fedid-check-reply] {'target':'%s'}", target);
        afb_data_create_raw(&reply, &afb_type_predefined_json_c, responseJ, 0,
                            (void *)json_object_put, responseJ);
        afb_req_v4_reply_hookable(wreq, status, 1, &reply);
    }

    idpRqtCtxFree(idpRqtCtx);
    return;

OnErrorExit:
    EXT_NOTICE("[fedid-authent-redirect] (hoops!!!) internal error");
    if (hreq)
        afb_hreq_redirect_to(hreq, idpRqtCtx->idp->oidc->globals.errorUrl,
                             HREQ_QUERY_EXCL, HREQ_REDIR_TMPY);
    if (wreq)
        afb_req_v4_reply_hookable(wreq, -1, 0, NULL);
    idpRqtCtxFree(idpRqtCtx);
}

// try to wreq user profile from its federation key
int fedidCheck(idpRqtCtxT *idpRqtCtx)
{
    int err;
    afb_data_x4_t params[1];

    // fedSocial should remain valid after subcall for fedsocial cookie
    err = afb_data_create_raw(&params[0], fedSocialObjType,
                              idpRqtCtx->fedSocial, 0, NULL, NULL);
    if (err)
        goto OnErrorExit;

    afb_data_addref(params[0]);  // prevent params to be deleted
    afb_api_v4_call_hookable(idpRqtCtx->idp->oidc->apiv4, API_OIDC_USR_SVC,
                             "social-check", 1, params, fedidCheckCB,
                             idpRqtCtx);
    return 0;

OnErrorExit:
    return -1;
}

// check if an attribute equal to value exists in the session
// return 1 if that is the case
// return 0 if none matches
int fedidsessionHasAttribute(oidcSessionT *session, const char *value)
{
    const fedSocialRawT *fedSocial = oidcSessionGetFedSocial(session);
    if (fedSocial != NULL) {
        const char **attrs = fedSocial->attrs;
        if (attrs != NULL) {
            for (; *attrs != NULL; attrs++) {
                if (!strcasecmp(value, *attrs))
                    return 1;
            }
        }
    }
    return 0;
}
