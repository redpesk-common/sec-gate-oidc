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
static void *oidcFedLinkCookie = &oidcFedLinkCookie;
static void *idsvcEvtCookie = &idsvcEvtCookie;
static void *oidcFedSocialCookie = &oidcFedSocialCookie;
static void *oidcFedUserCookie = &oidcFedUserCookie;
static void *oidcUsrDataCookie = &oidcUsrDataCookie;

oidcSession *oidcSessionOfHttpReq(afb_hreq *hreq)
{
    return hreq->comreq.session;
}

oidcSession *oidcSessionOfReq(afb_req_v4 *wreq)
{
    oidcSession *session = afb_req_v4_get_common(wreq)->session;
}

oidcSession *oidcSessionOfUUID(const char *uuid)
{
    return afb_session_search(uuid);
}

const char *oidcSessionUUID(oidcSession *session)
{
    return afb_session_uuid(session);
}

int oidcSessionGetLOA(oidcSession *session)
{
    return afb_session_get_loa(session, oidcSessionCookie);
}

int oidcSessionSetLOA(oidcSession *session, int LOA)
{
    return afb_session_set_loa(session, oidcSessionCookie, LOA);
}

int oidcSessionGetExpiration(oidcSession *session)
{
    return afb_session_get_loa(session, oidcAliasCookie);
}

int oidcSessionSetExpiration(oidcSession *session, int expiration)
{
    return afb_session_set_loa(session, oidcAliasCookie, expiration);
}

const oidcAliasT *oidcSessionGetAlias(oidcSession *session)
{
    void *ptr = NULL;
    int rc = afb_session_cookie_get(session, oidcAliasCookie, &ptr);
    return (oidcAliasT*)(rc ? NULL : ptr);
}

int oidcSessionSetAlias(oidcSession *session, const oidcAliasT *alias)
{
    return afb_session_cookie_set(session, oidcAliasCookie, (void*)alias, NULL, NULL);
}

const oidcProfileT *oidcSessionGetIdpProfile(oidcSession *session)
{
    void *ptr = NULL;
    int rc = afb_session_cookie_get(session, oidcIdpProfilCookie, &ptr);
    return (const oidcProfileT*)(rc ? NULL : ptr);
}

int oidcSessionSetIdpProfile(oidcSession *session, const oidcProfileT *profile)
{
    return afb_session_cookie_set(session, oidcIdpProfilCookie, (void*)profile, NULL, NULL);
}

fedidSessionT *oidcSessionGetFedId(oidcSession *session)
{
    void *ptr = NULL;
    int rc = afb_session_cookie_get(session, oidcSessionCookie, &ptr);
    return (fedidSessionT*)(rc ? NULL : ptr);
}

int oidcSessionSetFedId(oidcSession *session, fedidSessionT *fedid)
{
    return afb_session_cookie_set(session, oidcSessionCookie, fedid, NULL, NULL);
}

const fedidLinkT *oidcSessionGetFedIdLink(oidcSession *session)
{
    void *ptr = NULL;
    int rc = afb_session_cookie_get(session, oidcFedLinkCookie, &ptr);
    return (const fedidLinkT*)(rc ? NULL : ptr);
}

void oidcSessionDropFedIdLink(oidcSession *session)
{
    afb_session_cookie_delete(session, oidcFedLinkCookie);
}

int oidcSessionSetFedIdLink(oidcSession *session, const char *pseudo, const char *email)
{
    size_t sz_pseudo = 1 + strlen(pseudo);
    size_t sz_email = 1 + strlen(email);
    fedidLinkT *fedlink = malloc(sz_pseudo + sz_email + sizeof *fedlink);
    if (fedlink == NULL)
        return -1;
    fedlink->pseudo = (char*)(fedlink + 1);
    memcpy(fedlink->pseudo, pseudo, sz_pseudo);
    fedlink->email = fedlink->pseudo + sz_pseudo;
    memcpy(fedlink->email, email, sz_email);
    return afb_session_cookie_set(session, oidcFedLinkCookie, fedlink, free, fedlink);
}

int oidcSessionSetFedIdLinkRequest(oidcSession *session, int request)
{
    return afb_session_set_loa(session, oidcFedSocialCookie, request);
}

int oidcSessionGetFedIdLinkRequest(oidcSession *session)
{
    return afb_session_get_loa(session, oidcFedSocialCookie);
}

int oidcSessionEventSubscribe(afb_req_t wreq)
{
    afb_event_t event = NULL;
    oidcSession *session = oidcSessionOfReq(wreq);
    afb_session_cookie_get(session, idsvcEvtCookie, (void **)&event);
    if (event == NULL) {
        int rc = afb_api_new_event(afb_req_get_api(wreq), "session", &event);
        if (rc < 0) {
            EXT_INFO("failed to create session event");
            return rc;
        }
        afb_session_cookie_set(session, idsvcEvtCookie, event, (void*)afb_event_unref, event);
    }
    afb_req_subscribe(wreq, event);
}

int oidcSessionEventPush(oidcSession *session, json_object *eventJ)
{
    int rc, count;
    afb_event_t event = NULL;
    afb_data_t data;

    afb_session_cookie_get(session, idsvcEvtCookie, (void **)&event);
    if (event == NULL) {
        json_object_put(eventJ);
        return 0;
    }

    rc = afb_create_data_raw(&data, AFB_PREDEFINED_TYPE_JSON_C, eventJ, 0,
                        (void *)json_object_put, eventJ);
    if (rc < 0)
        return rc;

    count = afb_event_push(event, 1, &data);

    // no one listening clear event and cookie
    if (count <= 0)
        afb_session_cookie_set(session, idsvcEvtCookie, NULL, NULL, NULL);

    return count;
}

const fedSocialRawT *oidcSessionGetFedSocial(oidcSession *session)
{
    void *ptr = NULL;
    int rc = afb_session_cookie_get(session, oidcFedSocialCookie, &ptr);
    return (const fedSocialRawT*)(rc ? NULL : ptr);
}

int oidcSessionSetFedSocial(oidcSession *session, fedSocialRawT *fedSocial)
{
    return afb_session_cookie_set(session, oidcFedSocialCookie, fedSocial,
                                  (void*)fedSocialUnRef, fedSocial);
}

const fedUserRawT *oidcSessionGetUser(oidcSession *session)
{
    void *ptr = NULL;
    int rc = afb_session_cookie_get(session, oidcFedUserCookie, &ptr);
    return (const fedUserRawT*)(rc ? NULL : ptr);
}

int oidcSessionSetFedUser(oidcSession *session, fedUserRawT *fedUser)
{
    return afb_session_cookie_set(session, oidcFedUserCookie, fedUser,
                                  (void*)fedUserUnRef, fedUser);
}

void *oidcSessionGetOpaqueData(oidcSession *session)
{
    void *ptr = NULL;
    int rc = afb_session_cookie_get(session, oidcUsrDataCookie, &ptr);
    return (void*)(rc ? NULL : ptr);
}

int oidcSessionSetOpaqueData(oidcSession *session, void *data)
{
    return afb_session_cookie_set(session, oidcUsrDataCookie, data, NULL, NULL);
}

