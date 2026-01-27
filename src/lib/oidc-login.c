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

#include "oidc-login.h"

#include <assert.h>

#include <fedid-types-glue.h>
#include "fedid-client.h"

/* Send the final status */
static void oidcLoginEnd(oidcStateT *state, oidcSessionT *session, int status, const char *url)
{
    EXT_DEBUG("[oidc-login] oidcLoginEnd");
    EXT_DEBUG("[oidc-login] end %d redirect to %s", status, url);
    oidcStateReplyRedirect(state, status, url);
    oidcSessionSetTargetState(session, NULL);
    oidcStateUnRef(state);
}

// if fedkey exists callback receive local store user profile otherwise we
// should create it
static void oidcLoginDone(oidcStateT *state, oidcSessionT *session)
{
    // everything looks good let's return user to original page
    const oidcAliasT *alias = oidcSessionGetTargetPage(session);
    const char *url = alias != NULL ? alias->url : "/"; /* TODO what global home page ? */

    EXT_DEBUG("[oidc-login] oidcLoginDone");
    /* set actual login (TODO an what if federating?) */
    oidcSessionSetTargetPage(session, NULL);
    oidcLoginEnd(state, session, 1, url);
}

// if fedkey exists callback receive local store user profile otherwise we
// should create it
static void oidcLoginFederateDone(oidcStateT *state, oidcSessionT *session)
{
    EXT_DEBUG("[oidc-login] oidcLoginFederateDone");
    oidcSessionClearFederating(session);
    oidcSessionSetTargetState(session, NULL);
    oidcLoginDone(state, session);
}

/* verb call callback */
static void on_user_federate_result(void *closure,
                                    int status,
                                    unsigned argc,
                                    afb_data_x4_t const argv[],
                                    struct afb_api_v4 *api)
{
    oidcStateT *state = (oidcStateT *)closure;
    oidcSessionT *session = oidcStateGetSession(state);
    EXT_DEBUG("[oidc-login] on_user_federate_result %d", status);
    if (status < 0)
        EXT_ERROR("[oidc-login] user-federate failed, %d", status);
    oidcLoginFederateDone(state, session);
}

/**
 * perform federation of the user
 */
static void oidcLoginFederate(oidcStateT *state, oidcSessionT *session)
{
    oidcStateT *actual = oidcSessionGetActualState(session);
    int rc, federating = oidcSessionIsFederating(session);
    const fedUserRawT *fedUsr;
    const fedSocialRawT *fedSocial;
    afb_data_x4_t data[2];

    EXT_DEBUG("[oidc-login] oidcLoginFederate");
    assert(state == oidcSessionGetTargetState(session));
    assert(federating != 0);

    /* build parameter of call to user-federate */
    fedUsr = oidcSessionGetUser(session);
    fedSocial = oidcStateGetSocial(actual);
    rc = afb_create_data_raw(&data[0], fedUserObjType, fedUsr, 0, NULL, NULL);
    if (rc >= 0) {
        rc = afb_create_data_raw(&data[1], fedSocialObjType, fedSocial, 0, NULL,
                                  NULL);
        if (rc >= 0) {
            /* call to user federate */
            return fedIdClientCall(oidcStateGetAfbApi(state), "user-federate",
                                   2, data, on_user_federate_result, state);
        }
        afb_data_unref(data[0]);
    }
    EXT_ERROR("[oidc-login] can't call user-federate");
    oidcLoginFederateDone(state, session);
}


/* verb call callback */
static void on_social_check_result(void *closure,
                                   int status,
                                   unsigned argc,
                                   afb_data_x4_t const argv[],
                                   struct afb_api_v4 *api)
{
    oidcStateT *state = (oidcStateT *)closure;
    oidcSessionT *session = oidcStateGetSession(state);
    int federating = oidcSessionIsFederating(session);

    EXT_DEBUG("[oidc-login] on_social_check_result %d %d", status, federating);
    /* get the federated user if existing */
    if (status < 0) {
        /* got an issue while calling fedid service */
        EXT_ERROR("[oidc-login] social-check got error %d", status);
        /* identification is done so shift to granted page */
        return oidcLoginDone(state, session);
    }

    if (status > 0) {
        /* got a recorded user for the social identity record it */
        afb_data_x4_t data;
        int rc = afb_data_convert(argv[0], fedUserObjType, &data);
        if (rc < 0)
            EXT_ERROR("[oidc-login] can't get social-check result, %d", rc);
        else {
            /* record the user data in the session */
            fedUserRawT *fedUsr = (fedUserRawT *)afb_data_ro_pointer(data);
            oidcSessionSetUser(session, fedUsr);
            afb_data_unref(data);
            /* if federating, do the federation */
            if (federating)
                return oidcLoginFederate(state, session);
        }
        return oidcLoginDone(state, session);
    }

    /* the user isn't recorded (status == 0) */
    if (federating) {
        /* federating with unknown user is an error */
        EXT_ERROR("[oidc-login] can't federate with unknown user");
    }
    else if (oidcStateGetProfile(state)->slave != 0) {
        /* slave profiles must federate */
        oidcSessionSetFederating(session);
    }
    else {
        return oidcLoginEnd(state, session, 0, oidcStateGetGlobals(state)->registerUrl);
    }
    return oidcLoginEnd(state, session, 0, oidcStateGetGlobals(state)->fedlinkUrl);
}

/**
 * Login the user as represented by the fedSoc of the state.
 *
 */
void oidcLogin(oidcStateT *state)
{
    oidcSessionT *session = oidcStateGetSession(state);
    int federating = oidcSessionIsFederating(session);

    if (state != oidcSessionGetTargetState(session)) {
        EXT_ERROR("[oidc-login] state != oidcSessionGetTargetState(session)");
        EXT_ERROR("[oidc-login] state == %p", state);
        EXT_ERROR("[oidc-login] oidcSessionGetTargetState(session) == %p", oidcSessionGetTargetState(session));
    }


    EXT_DEBUG("[oidc-login] oidcLogin %d", federating);
    if (!federating) {
        /* not federating, do login */
        oidcSessionSetActualState(session, state);
        oidcSessionSetTargetState(session, NULL);
        oidcSessionSetUser(session, NULL); /* hum? should be the case but... */
        oidcSessionAutoValidate(session);
    }

    if (1 || federating) { /* TODO check mode, if mode exist without DB of users */
        afb_data_x4_t data;
        fedSocialRawT *fedSoc = oidcStateGetSocial(state);
        int rc = afb_data_create_raw(&data, fedSocialObjType, fedSoc, 0, NULL, NULL);
        if (rc >= 0) {
           /* call fedid binding */
            afb_api_t api = oidcStateGetAfbApi(state);
            return fedIdClientCall(api, "social-check", 1, &data,
                                   on_social_check_result, state);
        }
        EXT_ERROR("[oidc-login] can't create social-check arg");
    }

    /* identification is done so shift to granted page */
    return oidcLoginDone(state, session);
}

