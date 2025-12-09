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

#include "oidc-alias.h"
#include "oidc-common.h"
#include "oidc-idp.h"

typedef struct
{
    int timerId;
} fedidSessionT;

typedef struct
{
    char *pseudo;
    char *email;
} fedidLinkT;

#define FEDID_LINK_REQUESTED -1
#define FEDID_LINK_RESET     0

typedef struct oidcSessionS oidcSessionT;

oidcSessionT *oidcSessionOfAfbSession(struct afb_session *ases);
oidcSessionT *oidcSessionOfHttpReq(afb_hreq *hreq);
oidcSessionT *oidcSessionOfReq(afb_req_v4 *wreq);
oidcSessionT *oidcSessionOfUUID(const char *uuid);

const char *oidcSessionUUID(oidcSessionT *session);

int oidcSessionGetLOA(oidcSessionT *session);
int oidcSessionSetLOA(oidcSessionT *session, int LOA);

int oidcSessionGetExpiration(oidcSessionT *session);
int oidcSessionSetExpiration(oidcSessionT *session, int expiration);

const oidcAliasT *oidcSessionGetAlias(oidcSessionT *session);
int oidcSessionSetAlias(oidcSessionT *session, const oidcAliasT *alias);

const oidcProfileT *oidcSessionGetIdpProfile(oidcSessionT *session);
int oidcSessionSetIdpProfile(oidcSessionT *session, const oidcProfileT *profile);

fedidSessionT *oidcSessionGetFedId(oidcSessionT *session);
int oidcSessionSetFedId(oidcSessionT *session, fedidSessionT *fedid);

int oidcSessionSetFedIdLink(oidcSessionT *session,
                            const char *pseudo,
                            const char *email);
const fedidLinkT *oidcSessionGetFedIdLink(oidcSessionT *session);
void oidcSessionDropFedIdLink(oidcSessionT *session);
int oidcSessionSetFedIdLinkRequest(oidcSessionT *session, int request);
int oidcSessionGetFedIdLinkRequest(oidcSessionT *session);

int oidcSessionEventSubscribe(afb_req_t wreq);
int oidcSessionEventPush(oidcSessionT *session, json_object *eventJ);

const fedSocialRawT *oidcSessionGetFedSocial(oidcSessionT *session);
int oidcSessionSetFedSocial(oidcSessionT *session, fedSocialRawT *fedSocial);

int oidcSessionSetFedUser(oidcSessionT *session, fedUserRawT *fedUser);
const fedUserRawT *oidcSessionGetUser(oidcSessionT *session);

void *oidcSessionGetOpaqueData(oidcSessionT *session);
int oidcSessionSetOpaqueData(oidcSessionT *session, void *data);

