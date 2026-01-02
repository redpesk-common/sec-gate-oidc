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

#include "oidc-common.h"
#include "oidc-alias.h"
#include "oidc-idp.h"

typedef struct
{
    char *pseudo;
    char *email;
} fedidLinkT;

#define FEDID_LINK_REQUESTED -1
#define FEDID_LINK_RESET     0

typedef struct oidcSessionS oidcSessionT;

oidcSessionT *oidcSessionOfAfbSession(struct afb_session *ases);
oidcSessionT *oidcSessionOfHttpReq(struct afb_hreq *hreq);
oidcSessionT *oidcSessionOfReq(struct afb_req_v4 *wreq);
oidcSessionT *oidcSessionOfUUID(const char *uuid);

const char *oidcSessionUUID(const oidcSessionT *session);

int oidcSessionIsValid(oidcSessionT *session);
void oidcSessionValidate(oidcSessionT *session, long seconds);
void oidcSessionAutoValidate(oidcSessionT *session);

int oidcSessionShouldCheck(oidcSessionT *session);
void oidcSessionSetNextCheck(oidcSessionT *session, long millisec);

int oidcSessionGetTargetLOA(oidcSessionT *session);
int oidcSessionGetLOA(oidcSessionT *session);
void oidcSessionSetLOA(oidcSessionT *session, int LOA);

const oidcAliasT *oidcSessionGetAlias(oidcSessionT *session);
void oidcSessionSetAlias(oidcSessionT *session, const oidcAliasT *alias);

const oidcProfileT *oidcSessionGetIdpProfile(oidcSessionT *session);
void oidcSessionSetIdpProfile(oidcSessionT *session,
                              const oidcProfileT *profile);

int oidcSessionSetFedIdLink(oidcSessionT *session,
                            const char *pseudo,
                            const char *email);
const fedidLinkT *oidcSessionGetFedIdLink(oidcSessionT *session);
void oidcSessionDropFedIdLink(oidcSessionT *session);
void oidcSessionSetFedIdLinkRequest(oidcSessionT *session, int request);
int oidcSessionGetFedIdLinkRequest(oidcSessionT *session);

int oidcSessionEventSubscribe(afb_req_t wreq);
int oidcSessionEventPush(oidcSessionT *session, const char *desc, ...);

const fedSocialRawT *oidcSessionGetFedSocial(oidcSessionT *session);
void oidcSessionSetFedSocial(oidcSessionT *session, fedSocialRawT *fedSocial);
int oidcSessionHasAttribute(oidcSessionT *session, const char *value);

const fedUserRawT *oidcSessionGetUser(oidcSessionT *session);
void oidcSessionSetFedUser(oidcSessionT *session, fedUserRawT *fedUser);

void *oidcSessionGetOpaqueData(oidcSessionT *session);
void oidcSessionSetOpaqueData(oidcSessionT *session, void *data);
