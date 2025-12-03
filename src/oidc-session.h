/*
 * Copyright (C) 2015-2025 IoT.bzh Company
 * Author <dev-team@iot.bzh>
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

#define _GNU_SOURCE

#include "oidc-common.h"
#include "oidc-alias.h"
#include "oidc-idp.h"

typedef struct
{
    int timerId;
} fedidSessionT;

typedef struct afb_session afb_session;

afb_session *oidcSessionOfHttpReq(afb_hreq *hreq);
afb_session *oidcSessionOfReq(afb_req_v4 *wreq);

int oidcSessionGetLOA(afb_session *session);
int oidcSessionSetLOA(afb_session *session, int LOA);

int oidcSessionGetExpiration(afb_session *session);
int oidcSessionSetExpiration(afb_session *session, int expiration);

const oidcAliasT *oidcSessionGetAlias(afb_session *session);
int oidcSessionSetAlias(afb_session *session, const oidcAliasT *alias);

const oidcProfileT *oidcSessionGetIdpProfile(afb_session *session);
int oidcSessionSetIdpProfile(afb_session *session, const oidcProfileT *profile);

fedidSessionT *oidcSessionGetFedId(afb_session *session);
int oidcSessionSetFedId(afb_session *session, fedidSessionT *fedid);

