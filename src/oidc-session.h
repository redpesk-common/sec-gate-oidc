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

typedef struct afb_session oidcSession;

oidcSession *oidcSessionOfHttpReq(afb_hreq *hreq);
oidcSession *oidcSessionOfReq(afb_req_v4 *wreq);
oidcSession *oidcSessionOfUUID(const char *uuid);

const char *oidcSessionUUID(oidcSession *session);

int oidcSessionGetLOA(oidcSession *session);
int oidcSessionSetLOA(oidcSession *session, int LOA);

int oidcSessionGetExpiration(oidcSession *session);
int oidcSessionSetExpiration(oidcSession *session, int expiration);

const oidcAliasT *oidcSessionGetAlias(oidcSession *session);
int oidcSessionSetAlias(oidcSession *session, const oidcAliasT *alias);

const oidcProfileT *oidcSessionGetIdpProfile(oidcSession *session);
int oidcSessionSetIdpProfile(oidcSession *session, const oidcProfileT *profile);

fedidSessionT *oidcSessionGetFedId(oidcSession *session);
int oidcSessionSetFedId(oidcSession *session, fedidSessionT *fedid);

int oidcSessionSetFedIdLink(oidcSession *session,
                            const char *pseudo,
                            const char *email);
const fedidLinkT *oidcSessionGetFedIdLink(oidcSession *session);
void oidcSessionDropFedIdLink(oidcSession *session);
int oidcSessionSetFedIdLinkRequest(oidcSession *session, int request);
int oidcSessionGetFedIdLinkRequest(oidcSession *session);

int oidcSessionEventSubscribe(afb_req_t wreq);
int oidcSessionEventPush(oidcSession *session, json_object *eventJ);

const fedSocialRawT *oidcSessionGetFedSocial(oidcSession *session);
int oidcSessionSetFedSocial(oidcSession *session, fedSocialRawT *fedSocial);

int oidcSessionSetFedUser(oidcSession *session, fedUserRawT *fedUser);
const fedUserRawT *oidcSessionGetUser(oidcSession *session);

void *oidcSessionGetOpaqueData(oidcSession *session);
int oidcSessionSetOpaqueData(oidcSession *session, void *data);
