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

#include "oidc-session.h"
#include <libafb/afb-v4.h>

#include <libafb/afb-core.h>
#include <libafb/afb-http.h>

struct oidcSessionS
{
    int loa;
    int expiration;
    const char *uuid;
    const oidcAliasT *alias;
    const oidcProfileT *profile;
    const fedUserRawT *user;
    const fedSocialRawT *social;
    fedidSessionT *fedid;
    int fedidLinkRequest;
    fedidLinkT fedlink;
    afb_event_t event;
    void *data;
};

// free memory used by the session
static void destroySession(oidcSessionT *session)
{
    free(session);
}

// callback for creating session object
static int createSession(void *closure, void **value, void (**freecb)(void*), void **freeclo)
{
    oidcSessionT *session = calloc(1, sizeof *session);
    if (session == NULL)
        return -1;
    session->uuid = afb_session_uuid(closure);
    *value = session;
    *freeclo = session;
    *freecb = (void*)destroySession;
    return 0;
}

// get the session object of the afb session
oidcSessionT *oidcSessionOfAfbSession(struct afb_session *ases)
{
    oidcSessionT *session = NULL;
    if (ases == NULL)
        EXT_CRITICAL("[oidc-session] AFB session is NULL");
    else {
        int rc = afb_session_cookie_getinit(ases, oidcSessionOfAfbSession, (void*)&session, createSession, ases);
        if (rc < 0) {
            EXT_CRITICAL("[oidc-session] iCreation of session failed");
            return NULL;
        }
    }
    return session;
}

oidcSessionT *oidcSessionOfHttpReq(afb_hreq *hreq)
{
    struct afb_session *ases = hreq->comreq.session;
    return oidcSessionOfAfbSession(ases);
}

oidcSessionT *oidcSessionOfReq(afb_req_v4 *wreq)
{
    struct afb_session *ases = afb_req_v4_get_common(wreq)->session;
    return oidcSessionOfAfbSession(ases);
}

oidcSessionT *oidcSessionOfUUID(const char *uuid)
{
    struct afb_session *ases = afb_session_search(uuid);
    return ases == NULL ? NULL : oidcSessionOfAfbSession(ases);
}

const char *oidcSessionUUID(oidcSessionT *session)
{
    return session->uuid;
}

int oidcSessionGetLOA(oidcSessionT *session)
{
    return session->loa;
}

int oidcSessionSetLOA(oidcSessionT *session, int LOA)
{
    session->loa = LOA;
    return 0;
}

int oidcSessionGetExpiration(oidcSessionT *session)
{
    return session->expiration;
}

int oidcSessionSetExpiration(oidcSessionT *session, int expiration)
{
    session->expiration = expiration;
    return 0;
}

const oidcAliasT *oidcSessionGetAlias(oidcSessionT *session)
{
    return session->alias;
}

int oidcSessionSetAlias(oidcSessionT *session, const oidcAliasT *alias)
{
    session->alias = alias;
    return 0;
}

const oidcProfileT *oidcSessionGetIdpProfile(oidcSessionT *session)
{
    return session->profile;
}

int oidcSessionSetIdpProfile(oidcSessionT *session, const oidcProfileT *profile)
{
    session->profile = profile;
    return 0;
}

fedidSessionT *oidcSessionGetFedId(oidcSessionT *session)
{
    return session->fedid;
}

int oidcSessionSetFedId(oidcSessionT *session, fedidSessionT *fedid)
{
    session->fedid = fedid;
    return 0;
}

const fedidLinkT *oidcSessionGetFedIdLink(oidcSessionT *session)
{
    return session->fedlink.pseudo == NULL ? NULL : &session->fedlink;
}

void oidcSessionDropFedIdLink(oidcSessionT *session)
{
    free(session->fedlink.pseudo);
    free(session->fedlink.email);
    session->fedlink.pseudo = NULL;
    session->fedlink.email = NULL;
}

int oidcSessionSetFedIdLink(oidcSessionT *session, const char *pseudo, const char *email)
{
    oidcSessionDropFedIdLink(session);
    session->fedlink.pseudo = strdup(pseudo);
    session->fedlink.email = strdup(email);
    if (session->fedlink.pseudo != NULL && session->fedlink.email != NULL)
        return 0;
    oidcSessionDropFedIdLink(session);
    return -1;
}

int oidcSessionGetFedIdLinkRequest(oidcSessionT *session)
{
    return session->fedidLinkRequest;
}

int oidcSessionSetFedIdLinkRequest(oidcSessionT *session, int request)
{
    session->fedidLinkRequest = request;
    return 0;
}

const fedSocialRawT *oidcSessionGetFedSocial(oidcSessionT *session)
{
    return session->social;
}

int oidcSessionSetFedSocial(oidcSessionT *session, fedSocialRawT *fedSocial)
{
    session->social = fedSocial;
    return 0;
}

const fedUserRawT *oidcSessionGetUser(oidcSessionT *session)
{
    return session->user;
}

int oidcSessionSetFedUser(oidcSessionT *session, fedUserRawT *fedUser)
{
    session->user = fedUser;
    return 0;
}

void *oidcSessionGetOpaqueData(oidcSessionT *session)
{
    return session->data;
}

int oidcSessionSetOpaqueData(oidcSessionT *session, void *data)
{
    session->data = data;
    return 0;
}

int oidcSessionEventSubscribe(afb_req_t wreq)
{
    oidcSessionT *session = oidcSessionOfReq(wreq);
    if (session->event == NULL) {
        int rc = afb_api_new_event(afb_req_get_api(wreq), "session", &session->event);
        if (rc < 0) {
            EXT_INFO("failed to create session event");
            return rc;
        }
    }
    afb_req_subscribe(wreq, session->event);
}

int oidcSessionEventPush(oidcSessionT *session, json_object *eventJ)
{
    int rc, count;
    afb_data_t data;

    if (session->event == NULL) {
        json_object_put(eventJ);
        return 0;
    }

    rc = afb_create_data_raw(&data, AFB_PREDEFINED_TYPE_JSON_C, eventJ, 0,
                             (void *)json_object_put, eventJ);
    if (rc < 0)
        return rc;

    count = afb_event_push(session->event, 1, &data);

    // no listener, clear event and cookie
    if (count <= 0) {
        afb_event_unref(session->event);
        session->event = NULL;
    }

    return count;
}

