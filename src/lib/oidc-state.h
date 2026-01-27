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

#pragma once

#include "oidc-alias.h"
#include "oidc-common.h"
#include "oidc-idp.h"
#include "oidc-session.h"

// request handle store federation attribute during multiple IDP async calls
typedef struct oidcStateS idpRqtCtxT;
typedef struct oidcStateS oidcStateT;

void fedidsessionReset(oidcSessionT* session, const oidcProfileT* idpProfile);

oidcStateT* oidcStateCreate(const oidcIdpT* idp,
                            oidcSessionT* session,
                            const oidcProfileT* profile);

oidcStateT* oidcStateAddRef(oidcStateT* state);
void oidcStateUnRef(oidcStateT* state);

const oidcIdpT* oidcStateGetIdp(oidcStateT* state);
const oidcProfileT* oidcStateGetProfile(oidcStateT* state);
oidcSessionT* oidcStateGetSession(oidcStateT* state);
struct afb_hreq* oidcStateGetHttpReq(oidcStateT* state);
struct afb_req_v4* oidcStateGetAfbReq(oidcStateT* state);
const oidGlobalsT* oidcStateGetGlobals(oidcStateT* state);
struct afb_api_v4* oidcStateGetAfbApi(oidcStateT* state);
fedUserRawT* oidcStateGetUser(oidcStateT* state);
fedSocialRawT* oidcStateGetSocial(oidcStateT* state);
const char* oidcStateGetAuthorization(oidcStateT* state);
const char* oidcStateGetSessionUUID(oidcStateT* state);
const char* oidcStateGetUUID(oidcStateT *state);

void oidcStateSetHttpReq(oidcStateT* state, struct afb_hreq* hreq);
void oidcStateSetAfbReq(oidcStateT* state, struct afb_req_v4* wreq);
int oidcStateSetAuthorization(oidcStateT* state,
                              const char* type,
                              const char* token);

void oidcStateUnauthorized(oidcStateT* state);
void oidcStateInternalError(oidcStateT* state);
void oidcStateRedirect(oidcStateT* state, int status, const char* url);
