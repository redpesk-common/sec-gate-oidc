/*
 * Copyright (C) 2015-2021 IoT.bzh Company
 * Author "Fulup Ar Foll"
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

#include "oidc-defaults.h"
#include "oidc-idp.h"
#include <fedid-types.h>

#define FEDID_LINK_REQUESTED -1
#define FEDID_LINK_RESET 0

typedef struct {
    int timerId;
} fedidSessionT;


typedef enum {
    OIDC_SCHEMA_UNKNOWN=0,
    OIDC_SCHEMA_PSEUDO,
    OIDC_SCHEMA_NAME,
    OIDC_SCHEMA_EMAIL,
    OIDC_SCHEMA_AVATAR,
    OIDC_SCHEMA_COMPANY,
} oidcFedidSchemaE;

int fedidCheck (idpRqtCtxT *rqtCtx);
void fedidsessionReset (int signal, void *ctx);

extern void *oidcFedUserCookie;
extern void *oidcFedSocialCookie;