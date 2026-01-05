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

// few defaults
#define EXT_HIGHEST_PRIO 100
#define EXT_URL_MAX_LEN 512
#define EXT_TOKEN_MAX_LEN 256
#define EXT_HEADER_MAX_LEN 256
#define EXT_HTTP_UNAUTHORIZED 401
#define EXT_HTTP_CONFLICT 409
#define EXT_HTTP_SERVER_ERROR 500
#define EXT_SESSION_TIMEOUT 600  // session timeout in seconds

#define HREQ_REDIR_TMPY 0  // temporary redirection
#define HREQ_REDIR_PERM 1  // permanent redirection
#define HREQ_QUERY_INCL 1  // include request parameter in redirection
#define HREQ_QUERY_EXCL 0  // exclude request parameter of redirection
