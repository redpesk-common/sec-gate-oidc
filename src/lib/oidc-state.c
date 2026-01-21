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

#define _GNU_SOURCE

#include "oidc-state.h"

#include <assert.h>
#include <stdlib.h>

#include "oidc-idp-plugin.h"

struct oidcStateS {
    unsigned ucount;
    oidcSessionT* session;
    const oidcProfileT* profile;
    const oidcIdpT* idp;
    struct afb_hreq* hreq;
    struct afb_req_v4* wreq;
    fedSocialRawT* fedSocial;
    fedUserRawT* fedUser;
    char* authorization;
};

static const char bearer[] = "Bearer";

void oidcStateUnRef(oidcStateT *state)
{
    if (state != NULL && state->ucount-- == 0) {
        oidcSessionUnRef(state->session);
        if (state->hreq != NULL)
            afb_hreq_unref(state->hreq);
        if (state->wreq != NULL)
            afb_req_v4_unref_hookable(state->wreq);
        free(state->authorization);
        free(state);
    }
}

oidcStateT *oidcStateAddRef(oidcStateT *state)
{
    if (state != NULL)
        state->ucount++;
    return state;
}

oidcStateT *oidcStateCreate(const oidcIdpT *idp,
                            oidcSessionT *session,
                            const oidcProfileT *profile)
{
    oidcStateT *state;

    if (idp == NULL)
        idp = profile->idp;

    state = calloc(1, sizeof *state);
    if (state == NULL)
        goto error;

    state->ucount = 1;
    state->session = oidcSessionAddRef(session);
    state->profile = profile;
    state->idp = idp;
    state->fedSocial = calloc(1, sizeof *state->fedSocial);
    if (state->fedSocial == NULL)
        goto error2;
    state->fedSocial->refcount = 1;
    state->fedUser = calloc(1, sizeof *state->fedUser);
    if (state->fedUser == NULL)
        goto error3;
    state->fedUser->refcount = 1;
    state->fedSocial->idp = strdup(idp->uid);
    if (state->fedSocial->idp == NULL)
        goto error4;
    return state;

error4:
    free(state->fedUser);
error3:
    free(state->fedSocial);
error2:
    free(state);
error:
    EXT_ERROR("allocation failed");
    return NULL;
}

const oidcIdpT* oidcStateGetIdp(oidcStateT* state)
{
    return state->idp;
}

const oidcProfileT* oidcStateGetProfile(oidcStateT* state)
{
    return state->profile;
}

oidcSessionT* oidcStateGetSession(oidcStateT* state)
{
    return state->session;
}

struct afb_hreq* oidcStateGetHttpReq(oidcStateT* state)
{
    return state->hreq;
}

void oidcStateSetReq(oidcStateT* state, struct afb_req_v4* wreq)
{
    state->wreq = wreq;
}

struct afb_req_v4* oidcStateGetAfbReq(oidcStateT* state)
{
    return state->wreq;
}

const char* oidcStateGetAuthorization(oidcStateT* state)
{
    return state->authorization;
}

const oidGlobalsT *oidcStateGetGlobals(oidcStateT *state)
{
    return oidcCoreGlobals(state->idp->oidc);
}

struct afb_api_v4 *oidcStateGetAfbApi(oidcStateT *state)
{
    return oidcCoreAfbApi(state->idp->oidc);
}

fedUserRawT *oidcStateGetUser(oidcStateT* state)
{
    return state->fedUser;
}

fedSocialRawT *oidcStateGetSocial(oidcStateT* state)
{
    return state->fedSocial;
}

const char *oidcStateGetSessionUUID(oidcStateT* state)
{
    return oidcSessionUUID(state->session);
}

void oidcStateSetHttpReq(oidcStateT* state, struct afb_hreq* hreq)
{
    afb_hreq_addref(hreq);
    if (state->hreq != NULL)
        afb_hreq_unref(state->hreq);
    state->hreq = hreq;
}

void oidcStateSetAfbReq(oidcStateT* state, struct afb_req_v4* wreq)
{
    afb_req_v4_addref_hookable(wreq);
    if (state->wreq != NULL)
        afb_req_v4_unref_hookable(state->wreq);
    state->wreq = wreq;
}

int oidcStateSetAuthorization(oidcStateT *state, const char *type, const char *token)
{
    size_t sz1, sz2;
    char *auth;
    
    if (type == NULL)
        type = bearer;

    sz1 = strlen(type);
    sz2 = strlen(token);
    auth = malloc(sz1 + sz2 + 2);
    if (auth == NULL)
        return -1;

    memcpy(auth, type, sz1);
    auth[sz1] = ' ';
    memcpy(&auth[sz1 + 1], token, sz2 + 1);

    free(state->authorization);
    state->authorization = auth;
    return 0;
}

// session timeout, reset LOA
void fedidsessionReset(oidcSessionT *session, const oidcProfileT *idpProfile)
{
    int count = -1;

    // reset session and alias LOA (this will force authentication)
    oidcSessionSetActualLOA(session, 0);
    oidcSessionSetNextCheck(session, 0);
    EXT_DEBUG("[oidc-state] logout/timeout session uuid=%s ?",
              oidcSessionUUID(session));

    if (idpProfile) {
/*
  TODO
        if (idpProfile->idp->plugin && idpProfile->idp->plugin->resetSession) {
            void *ctx = oidcSessionGetOpaqueData(session);
            if (ctx != NULL) {
                idpProfile->idp->plugin->resetSession(idpProfile, ctx);
                oidcSessionSetOpaqueData(session, NULL);
            }
        }
*/

        const oidGlobalsT *globals = oidcCoreGlobals(idpProfile->idp->oidc);
        count = oidcSessionEventPush(
            session, "{ss ss ss* ss*}", "status", "loa-reset", "home",
            globals->homeUrl != NULL ? globals->homeUrl : "/", "login", globals->loginUrl, "error",
            globals->errorUrl);
        if (!count)
            EXT_DEBUG("[oidc-state] no client subscribed uuid=%s ?",
                      oidcSessionUUID(session));
    }
}

static void reply(oidcStateT *state, int hrc, int wrc)
{
    if (state->hreq)
        afb_hreq_reply_error(state->hreq, hrc);
    if (state->wreq)
        afb_req_v4_reply_hookable(state->wreq, wrc, 0, NULL);
}

void oidcStateUnauthorized(oidcStateT *state)
{
    reply(state, EXT_HTTP_UNAUTHORIZED, AFB_ERRNO_UNAUTHORIZED);
}

void oidcStateInternalError(oidcStateT* state)
{
    reply(state, EXT_HTTP_SERVER_ERROR, AFB_ERRNO_INTERNAL_ERROR);
}

#ifndef MHD_HTTP_SEE_OTHER
#define MHD_HTTP_SEE_OTHER           303
#define MHD_HTTP_TEMPORARY_REDIRECT  307
#define MHD_HTTP_HEADER_LOCATION     "Location"
#endif
void oidcStateRedirect(oidcStateT *state, int status, const char *url)
{
	EXT_DEBUG("redirect to [%s]", url);
    if (state->hreq) {
        unsigned status = (state->hreq->method & afb_method_post) ? MHD_HTTP_SEE_OTHER : MHD_HTTP_TEMPORARY_REDIRECT;
	    afb_hreq_reply_static(state->hreq, status, 0, NULL, MHD_HTTP_HEADER_LOCATION, url, NULL);
    }
    if (state->wreq) {
        struct afb_data *data;
        afb_data_create_copy(&data, &afb_type_predefined_stringz, url, 1 + strlen(url));
        afb_req_v4_reply_hookable(state->wreq, status, 1, &data);
    }
}

