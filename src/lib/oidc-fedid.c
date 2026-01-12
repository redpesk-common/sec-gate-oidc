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
 */

#include <assert.h>
#include <locale.h>
#include <string.h>

#include <rp-utils/rp-escape.h>
#include <rp-utils/rp-jsonc.h>

#include <libafb/afb-core.h>
#include <libafb/afb-http.h>
#include <libafb/afb-v4.h>

#include <fedid-types-glue.h>

#include <curl-glue.h>

#include "fedid-client.h"
#include "oidc-alias.h"
#include "oidc-core.h"
#include "oidc-fedid.h"
#include "oidc-idp-plugin.h"
#include "oidc-session.h"

// if fedkey exists callback receive local store user profile otherwise we
// should create it
static void onSocialCheckResult(void *closure,
                                int status,
                                fedSocialRawT *fedSoc,
                                fedUserRawT *fedUsr)
{
    oidcStateT *state = (oidcStateT *)closure;
    char url[EXT_URL_MAX_LEN];
    const char *target;
    fedUserRawT *fedUser;
    const oidcProfileT *profile = oidcStateGetProfile(state);
    const oidcAliasT *alias;
    oidcSessionT *session = oidcStateGetSession(state);
    const char *redirect;
    struct afb_hreq *hreq = state->hreq;
    struct afb_req_v4 *wreq = state->wreq;
    int err;

    EXT_WARNING("*** entering Social check status=%d ***", status);

    // internal API error
    if (status < 0) {
        EXT_WARNING("Social check got error %d", status);
        goto OnErrorExit;
    }

    // user try to login if loa set then reset session
    int sessionLoa = oidcSessionGetActualLOA(session);
    if (sessionLoa)
        fedidsessionReset(session, NULL);

    if (status != 1) {  // fedid is not registered and we are not facing a
        // secondary authentication
        const char *targetUrl;

        // fedkey not found let's store social authority profile into session
        // and redirect user on userprofil creation
        oidcSessionSetFedUser(session, state->fedUser);
        oidcSessionSetFedSocial(session, state->fedSocial);
        if (profile->slave) {
            oidcSessionSetFedIdLinkRequest(session, FEDID_LINK_REQUESTED);
            targetUrl = oidcCoreGlobals(state->idp->oidc)->fedlinkUrl;
        }
        else {
            targetUrl = oidcCoreGlobals(state->idp->oidc)->registerUrl;
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
        fedUser = fedUserAddRef(fedUsr);

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
            err = afb_create_data_raw(&params[0], fedUserObjType, fedUser, 0,
                                      NULL, NULL);
            if (err < 0)
                goto OnErrorExit;
            err = afb_create_data_raw(&params[1], fedSocialObjType, fedSocial,
                                      0, NULL, NULL);
            if (err < 0)
                goto OnErrorExit;
            afb_api_t api = oidcCoreAfbApi(state->idp->oidc);
            err = fedIdClientCallSync(api, "user-federate", 2, params, &status,
                                      &count, &data);
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
        oidcSessionSetFedSocial(session, state->fedSocial);

        // everything looks good let's return user to original page
        alias = oidcSessionGetAlias(session);

        size_t sz = rp_escape_url_to(NULL, alias->url, NULL, url, sizeof url);
        if (sz >= sizeof url) {
            EXT_ERROR("[oidc-fedid] fail to build redirect url");
            goto OnErrorExit;
        }

        if (hreq) {
            // add afb-binder endpoint to login redirect alias
            err = afb_hreq_make_here_url(hreq, alias->url, url, sizeof(url));
            if (err < 0) {
                EXT_ERROR("[oidc-fedid] fail to build redirect url");
                goto OnErrorExit;
            }
        }
        else {
            target = alias->url;
        }

        // user successfully loggin set session loa to current idp login profile
        EXT_DEBUG("[oidc-fedid] setting actual profile %s/%s/%d",
                  profile->idp->uid, profile->uid, profile->loa);
        oidcSessionSetActualLOA(session, profile->loa);
        oidcSessionSetActualProfile(session, profile);
        oidcSessionAutoValidate(session);
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

    oidcStateUnRef(state);
    return;

OnErrorExit:
    EXT_NOTICE("[fedid-authent-redirect] (hoops!!!) internal error");
    if (hreq)
        afb_hreq_redirect_to(hreq, oidcCoreGlobals(state->idp->oidc)->errorUrl,
                             HREQ_QUERY_EXCL, HREQ_REDIR_TMPY);
    if (wreq)
        afb_req_v4_reply_hookable(wreq, -1, 0, NULL);
    oidcStateUnRef(state);
}

// try to wreq user profile from its federation key
int fedidCheck(oidcStateT *state)
{
    afb_api_t api = oidcCoreAfbApi(state->idp->oidc);
    fedIdClientSocialCheck(api, state->fedSocial, onSocialCheckResult, state);
    return 0;
}
