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

#include "oidc-core.h"

// MAGIC_OIDC_SESSION() used as session key
extern void *oidcSessionCookie;
extern void *oidcAliasCookie;


typedef struct oidcAliasesS {
    const char *uid;
    const char *info;
    int loa;
    int priority;
    const char *url;
    const char *path;
    const char **roles;
    oidcCoreHdlT *oidc;
    ulong tCache;
} oidcAliasT;

oidcAliasT *aliasParseConfig (oidcCoreHdlT * oidc, json_object * aliasesJ);
int aliasRegisterOne (oidcCoreHdlT * oidc, oidcAliasT * alias, afb_hsrv * hsrv);
