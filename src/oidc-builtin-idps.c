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
 *
 *  References:
 *      https://onelogin.com
 *      https://www.phantauth.net/
 *      https://benmcollins.github.io/libjwt/group__jwt__header.html#ga308c00b85ab5ebfa76b1d2485a494104
 */

#define _GNU_SOURCE

#include <libafb/afb-core.h>
#include <libafb/afb-http.h>
#include <libafb/afb-v4.h>

#include "oidc-idp.h"
#include "builtin-idps/idp-github.h"
#include "builtin-idps/idp-ldap.h"
#include "builtin-idps/idp-oidc.h"

// Builtin in output formater. Note that first one is used when cmd does not
// define a format
static
idpPluginT idpBuiltins[] = {
    {.uid = "oidc",
     .info = "openid connect idp",
     .registerConfig = oidcRegisterConfig,
     .registerAlias = oidcRegisterAlias},
    {.uid = "github",
     .info = "github public oauth2 idp",
     .registerConfig = githubRegisterConfig,
     .registerAlias = githubRegisterAlias},
    {.uid = "ldap",
     .info = "ldap internal users",
     .registerConfig = ldapRegsterConfig,
     .registerAlias = ldapRegisterAlias,
     .registerApis = ldapRegisterApis},
    {.uid = NULL}  // must be null terminated
};

int registerBuiltinIdps(void)
{
    return idpRegisterPlugin("built-in", idpBuiltins);
}
