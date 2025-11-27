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

#include <json-c/json.h>
#include <wrap-json.h>

#define AFB_BINDING_NO_ROOT 1
#include <libafb/afb-extension.h>
#include <libafb/misc/afb-verbose.h>

// few magic to help debugging
typedef enum { MAGIC_OIDC_IDP = 12345678, MAGIC_OIDC_CBS = 654852 } oidcMagicT;

// redefine debug/log to avoid conflict
#ifndef EXT_EMERGENCY
#define EXT_EMERGENCY(...) \
    _LIBAFB_VERBOSE_(afb_Log_Level_Emergency, __VA_ARGS__)
#define EXT_ALERT(...)    _LIBAFB_VERBOSE_(afb_Log_Level_Alert, __VA_ARGS__)
#define EXT_CRITICAL(...) _LIBAFB_VERBOSE_(afb_Log_Level_Critical, __VA_ARGS__)
#define EXT_ERROR(...)    _LIBAFB_VERBOSE_(afb_Log_Level_Error, __VA_ARGS__)
#define EXT_WARNING(...)  _LIBAFB_VERBOSE_(afb_Log_Level_Warning, __VA_ARGS__)
#define EXT_NOTICE(...)   _LIBAFB_VERBOSE_(afb_Log_Level_Notice, __VA_ARGS__)
#define EXT_INFO(...)     _LIBAFB_VERBOSE_(afb_Log_Level_Info, __VA_ARGS__)
#define EXT_DEBUG(...)    _LIBAFB_VERBOSE_(afb_Log_Level_Debug, __VA_ARGS__)
#endif

// few defaults
#define EXT_HIGHEST_PRIO      100
#define EXT_URL_MAX_LEN       512
#define EXT_TOKEN_MAX_LEN     256
#define EXT_HEADER_MAX_LEN    256
#define EXT_HTTP_UNAUTHORIZED 401
#define EXT_HTTP_CONFLICT     409
#define EXT_SESSION_TIMEOUT   600  // session timeout in seconds

#define HREQ_REDIR_TMPY 0
#define HREQ_REDIR_TERM 1
#define HREQ_QUERY_INCL 1
#define HREQ_QUERY_EXCL 0

// local or remote federated identity service api name
#define API_OIDC_USR_SVC "fedid"

// return code
#define AFB_HSRV_OK 1

// make our live simpler
typedef struct afb_hsrv afb_hsrv;
typedef struct afb_hreq afb_hreq;
typedef struct afb_session afb_session;
typedef struct afb_apiset afb_apiset;
typedef struct afb_apiset afb_apiset;
typedef struct afb_verb_v4 afb_verb_v4;
typedef struct afb_api_v4 afb_api_v4;
typedef struct afb_req_v4 afb_req_v4;
typedef struct afb_data afb_data;
