/*
 * Copyright (C) 2015-2021 IoT.bzh Company
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
 *
 *  References:
 *      https://onelogin.com
 *      https://www.phantauth.net/
 *      https://benmcollins.github.io/libjwt/group__jwt__header.html#ga308c00b85ab5ebfa76b1d2485a494104
 */

#define _GNU_SOURCE

#include "builtin-idps/idp-github.h"
#include "builtin-idps/idp-ldap.h"
#include "builtin-idps/idp-oidc.h"
#include "oidc-idp.h"

int registerBuiltinIdps(void)
{
    int rc = idpPluginRegister(&oidcPluginDesc);
    if (rc == 0)
        rc = idpPluginRegister(&githubPluginDesc);
    if (rc == 0)
        rc = idpPluginRegister(&ldapPluginDesc);
    return rc;
}
