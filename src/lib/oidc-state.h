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

struct oidcStateS {
    unsigned ucount;
    oidcSessionT *session;
    const oidcProfileT* profile;
    const oidcIdpT *idp;
    struct afb_hreq *hreq;
    struct afb_req_v4 *wreq;
    const char *uuid;
    fedSocialRawT *fedSocial;
    fedUserRawT *fedUser;
    char *token;
    void *userData;
};

void idpRqtCtxFree(idpRqtCtxT* rqtCtx);

void fedidsessionReset(oidcSessionT* session, const oidcProfileT* idpProfile);


oidcStateT *oidcStateCreateForHttpReq(
                struct afb_hreq* hreq,
                oidcSessionT *session,
                const oidcProfileT* profile,
                const oidcIdpT *idp);

oidcStateT *oidcStateAddRef(oidcStateT *state);
void oidcStateUnRef(oidcStateT *state);

