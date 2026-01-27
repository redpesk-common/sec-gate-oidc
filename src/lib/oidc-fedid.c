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

/* Send the final status */
static void fedidEnd(oidcStateT *state, int status, const char *url)
{
    EXT_DEBUG("[oidc-fedid] end %d redirect to %s", status, url);
    oidcStateReplyRedirect(state, status, url);
    oidcStateUnRef(state);
}

/* Send the final error status */
static void fedidError(oidcStateT *state)
{
    EXT_NOTICE("[oidc-fedid] (hoops!!!) internal error");
    fedidEnd(state, AFB_ERRNO_INTERNAL_ERROR,
             oidcStateGetGlobals(state)->errorUrl);
}

/*
 * Process a new user
 * Redirect to the page register or federate to fulfill user data
 */
static void fedidNewUser(oidcStateT *state,
                         oidcSessionT *session,
                         fedSocialRawT *fedSoc,
                         fedUserRawT *fedUsr)
{
    const char *targetUrl;
    const oidcProfileT *profile = oidcStateGetProfile(state);

    // fedkey not found let's store social authority profile into session
    // and redirect user on userprofil creation
    oidcSessionSetFedUser(session, oidcStateGetUser(state));
    oidcSessionSetFedSocial(session, oidcStateGetSocial(state));
    if (profile->slave) {
        oidcSessionSetFedIdUser(session, oidcStateGetUser(state));
        targetUrl = oidcStateGetGlobals(state)->fedlinkUrl;
    }
    else {
        targetUrl = oidcStateGetGlobals(state)->registerUrl;
    }
    fedidEnd(state, 0, targetUrl);
}

// if fedkey exists callback receive local store user profile otherwise we
// should create it
static void fedidLoginUser(oidcStateT *state,
                           oidcSessionT *session,
                           fedSocialRawT *fedSoc,
                           fedUserRawT *fedUsr)
{
    const oidcProfileT *profile = oidcStateGetProfile(state);
    const oidcAliasT *alias;

    // let's store user profile into session cookie (/oidc/profile/get
    // serves it)
    oidcSessionSetFedUser(session, fedUserAddRef(fedUsr));
    oidcSessionSetFedSocial(session, oidcStateGetSocial(state));

    // everything looks good let's return user to original page
    alias = oidcSessionGetTargetPage(session);

    // user successfully loggin set session loa to current idp login profile
    EXT_DEBUG("[oidc-fedid] setting actual profile %s/%s/%d", profile->idp->uid,
              profile->uid, profile->loa);
    oidcSessionSetActualLOA(session, profile->loa);
    oidcSessionAutoValidate(session);

    fedidEnd(state, 1, alias->url);
}

static void fedidFederateUser(oidcStateT *state,
                              oidcSessionT *session,
                              fedSocialRawT *fedSoc,
                              fedUserRawT *fedUsr)
{
    int err;

    // fedid is already registered
    fedUsr = fedUserAddRef(fedUsr);

    // check if federation linking is pending
    const fedSocialRawT *fedSocial;
    fedSocial = oidcSessionGetFedSocial(session);

    // if we have to link two accounts do it before cleaning
    assert(fedSocial);
    afb_data_x4_t params[2];
    int status;
    unsigned int count;
    afb_data_t data;

    // make sure we do not link account twice
    oidcSessionDropFedIdUser(session);

    // delegate account federation linking to fedid binding
    err =
        afb_create_data_raw(&params[0], fedUserObjType, fedUsr, 0, NULL, NULL);
    if (err < 0)
        return fedidError(state);
    err = afb_create_data_raw(&params[1], fedSocialObjType, fedSocial, 0, NULL,
                              NULL);
    if (err < 0)
        return fedidError(state);
    afb_api_t api = oidcStateGetAfbApi(state);
    err = fedIdClientCallSync(api, "user-federate", 2, params, &status, &count,
                              &data);
    if (err < 0 || status != 0) {
        EXT_ERROR(
            "[oidc-fedid] fail to link account pseudo=%s "
            "email=%s",
            fedUsr->pseudo, fedUsr->email);
        return fedidError(state);
    }
    return fedidLoginUser(state, session, fedSoc, fedUsr);
}

static void fedidExistingUser(oidcStateT *state,
                              oidcSessionT *session,
                              fedSocialRawT *fedSoc,
                              fedUserRawT *fedUsr)
{
    fedUserRawT *fedUser = oidcSessionGetFedIdUser(session);
    if (fedUser != NULL)
        fedidFederateUser(state, session, fedSoc, fedUsr);
    else
        fedidLoginUser(state, session, fedSoc, fedUsr);
}

// if fedkey exists callback receive local store user profile otherwise we
// should create it
static void onSocialCheckResult(void *closure,
                                int status,
                                fedSocialRawT *fedSoc,
                                fedUserRawT *fedUsr)
{
    oidcStateT *state = (oidcStateT *)closure;
    oidcSessionT *session = oidcStateGetSession(state);
    int sessionLoa = oidcSessionGetActualLOA(session);

    EXT_WARNING("*** entering Social check status=%d ***", status);

    // internal API error
    if (status < 0) {
        EXT_WARNING("Social check got error %d", status);
        return fedidError(state);
    }

    // user try to login if loa set then reset session
    if (sessionLoa)
        fedidsessionReset(session, NULL);

    if (status == 0)
        fedidNewUser(state, session, fedSoc, fedUsr);
    else
        fedidExistingUser(state, session, fedSoc, fedUsr);
}

// try to wreq user profile from its federation key
void fedidCheck(oidcStateT *state)
{
    afb_api_t api = oidcStateGetAfbApi(state);
    fedIdClientSocialCheck(api, oidcStateGetSocial(state), onSocialCheckResult,
                           state);
}
