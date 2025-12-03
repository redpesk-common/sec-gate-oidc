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

#define _GNU_SOURCE

#include <libafb/afb-v4.h>
#include "oidc-session.h"

#include <libafb/afb-core.h>
#include <libafb/afb-http.h>

static void *oidcSessionCookie = &oidcSessionCookie;
static void *oidcAliasCookie = &oidcAliasCookie;
static void *oidcIdpProfilCookie = &oidcIdpProfilCookie;

afb_session *oidcSessionOfHttpReq(afb_hreq *hreq)
{
    return hreq->comreq.session;
}

afb_session *oidcSessionOfReq(afb_req_v4 *wreq)
{
    afb_session *session = afb_req_v4_get_common(wreq)->session;
}

int oidcSessionGetLOA(afb_session *session)
{
    return afb_session_get_loa(session, oidcSessionCookie);
}

int oidcSessionSetLOA(afb_session *session, int LOA)
{
    return afb_session_set_loa(session, oidcSessionCookie, LOA);
}

int oidcSessionGetExpiration(afb_session *session)
{
    return afb_session_get_loa(session, oidcAliasCookie);
}

int oidcSessionSetExpiration(afb_session *session, int expiration)
{
    return afb_session_set_loa(session, oidcAliasCookie, expiration);
}

const oidcAliasT *oidcSessionGetAlias(afb_session *session)
{
    void *ptr = NULL;
    int rc = afb_session_cookie_get(session, oidcAliasCookie, &ptr);
    return (oidcAliasT*)(rc ? NULL : ptr);
}

int oidcSessionSetAlias(afb_session *session, const oidcAliasT *alias)
{
    return afb_session_cookie_set(session, oidcAliasCookie, (void*)alias, NULL, NULL);
}

const oidcProfileT *oidcSessionGetIdpProfile(afb_session *session)
{
    void *ptr = NULL;
    int rc = afb_session_cookie_get(session, oidcIdpProfilCookie, &ptr);
    return (const oidcProfileT*)(rc ? NULL : ptr);
}

int oidcSessionSetIdpProfile(afb_session *session, const oidcProfileT *profile)
{
    return afb_session_cookie_set(session, oidcIdpProfilCookie, (void*)profile, NULL, NULL);
}

fedidSessionT *oidcSessionGetFedId(afb_session *session)
{
    void *ptr = NULL;
    int rc = afb_session_cookie_get(session, oidcSessionCookie, &ptr);
    return (fedidSessionT*)(rc ? NULL : ptr);
}

int oidcSessionSetFedId(afb_session *session, fedidSessionT *fedid)
{
    return afb_session_cookie_set(session, oidcSessionCookie, fedid, NULL, NULL);
}

