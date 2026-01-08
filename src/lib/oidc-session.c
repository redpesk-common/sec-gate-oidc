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

#define _GNU_SOURCE

#include "oidc-session.h"

#include <stdlib.h>

#include <rp-utils/rp-jsonc.h>

#include <libafb/afb-core.h>
#include <libafb/afb-http.h>
#include <libafb/afb-v4.h>

#include "oidc-alias.h"

struct oidcSessionS
{
    unsigned refcount;
    int nowset;
    int loa;
    const char *uuid;
    const oidcAliasT *alias;
    const oidcProfileT *targetProfile;
    const oidcProfileT *actualProfile;
    oidcStateT *targetState;
    fedUserRawT *user;
    fedSocialRawT *social;
    int fedidLinkRequest;
    fedidLinkT fedlink;
    struct afb_evt *event;
    void *data;
    void (*freeData)(void*);
    struct timespec now;
    struct timespec nextCheck;
    struct timespec endValid;
};

// release memory used by the session
void oidcSessionUnRef(oidcSessionT *session)
{
    if (session != NULL && --session->refcount == 0) {
        free(session);
    }
}

// add a reference to the session
oidcSessionT *oidcSessionAddRef(oidcSessionT *session)
{
    if (session != NULL)
        session->refcount++;
    return session;
}

// callback for creating session object
static int createSession(void *closure,
                         void **value,
                         void (**freecb)(void *),
                         void **freeclo)
{
    oidcSessionT *session = calloc(1, sizeof *session);
    if (session == NULL)
        return -1;
    session->refcount = 1;
    session->uuid = afb_session_uuid(closure);
    *value = session;
    *freeclo = session;
    *freecb = (void *)oidcSessionUnRef;
    return 0;
}

// get the session object of the afb session
oidcSessionT *oidcSessionOfAfbSession(struct afb_session *ases)
{
    oidcSessionT *session = NULL;
    if (ases == NULL)
        EXT_CRITICAL("[oidc-session] AFB session is NULL");
    else {
        int rc =
            afb_session_cookie_getinit(ases, oidcSessionOfAfbSession,
                                       (void *)&session, createSession, ases);
        if (rc < 0) {
            EXT_CRITICAL("[oidc-session] iCreation of session failed");
            return NULL;
        }
        session->nowset = 0;
    }
    return session;
}

oidcSessionT *oidcSessionOfHttpReq(struct afb_hreq *hreq)
{
    struct afb_session *ases = hreq->comreq.session;
    return oidcSessionOfAfbSession(ases);
}

oidcSessionT *oidcSessionOfReq(struct afb_req_v4 *wreq)
{
    struct afb_session *ases = afb_req_v4_get_common(wreq)->session;
    return oidcSessionOfAfbSession(ases);
}

oidcSessionT *oidcSessionOfUUID(const char *uuid)
{
    struct afb_session *ases = afb_session_search(uuid);
    return ases == NULL ? NULL : oidcSessionOfAfbSession(ases);
}

const char *oidcSessionUUID(const oidcSessionT *session)
{
    return session->uuid;
}

static void ensureNowIsSet(oidcSessionT *session)
{
    if (!session->nowset) {
        clock_gettime(CLOCK_MONOTONIC, &session->now);
        session->nowset = 1;
    }
}

static int timeLesser(const struct timespec *a, const struct timespec *b)
{
    return a->tv_sec < b->tv_sec ||
           (a->tv_sec == b->tv_sec && a->tv_nsec < b->tv_nsec);
}

static void timeAdd(struct timespec *dest,
                    const struct timespec *src,
                    long sec,
                    long nsec)
{
    dest->tv_sec = src->tv_sec + sec;
    dest->tv_nsec = src->tv_nsec + nsec;
    if (dest->tv_nsec >= 1000000000) {
        dest->tv_nsec -= 1000000000;
        dest->tv_sec++;
    }
    else if (dest->tv_nsec < 0) {
        dest->tv_nsec += 1000000000;
        dest->tv_sec--;
    }
}

int oidcSessionIsValid(oidcSessionT *session)
{
    ensureNowIsSet(session);
    return timeLesser(&session->now, &session->endValid);
}

void oidcSessionValidate(oidcSessionT *session, long seconds)
{
    ensureNowIsSet(session);
    timeAdd(&session->endValid, &session->now, seconds, 0);
}

void oidcSessionAutoValidate(oidcSessionT *session)
{
    long to = EXT_SESSION_TIMEOUT;
    if (session->targetProfile != NULL && session->targetProfile->sTimeout > 0)
        to = session->targetProfile->sTimeout;
    oidcSessionValidate(session, to);
}

int oidcSessionShouldCheck(oidcSessionT *session)
{
    ensureNowIsSet(session);
    return timeLesser(&session->nextCheck, &session->now);
}

void oidcSessionSetNextCheck(oidcSessionT *session, long millisec)
{
    ldiv_t d = ldiv(millisec, 1000);
    ensureNowIsSet(session);
    timeAdd(&session->nextCheck, &session->now, d.quot, d.rem * 1000000);
}

int oidcSessionGetTargetLOA(oidcSessionT *session)
{
    return session->alias ? session->alias->loa : 0;
}

int oidcSessionGetActualLOA(oidcSessionT *session)
{
    return session->loa;
}

void oidcSessionSetActualLOA(oidcSessionT *session, int LOA)
{
    session->loa = LOA;
}

const oidcAliasT *oidcSessionGetAlias(oidcSessionT *session)
{
    return session->alias;
}

void oidcSessionSetAlias(oidcSessionT *session, const oidcAliasT *alias)
{
    session->alias = alias;
}

const oidcProfileT *oidcSessionGetTargetProfile(oidcSessionT *session)
{
    return session->targetProfile;
}

void oidcSessionSetTargetProfile(oidcSessionT *session,
                              const oidcProfileT *profile)
{
    session->targetProfile = profile;
}

const oidcProfileT *oidcSessionGetActualProfile(oidcSessionT *session)
{
    return session->actualProfile;
}

void oidcSessionSetActualProfile(oidcSessionT *session,
                                 const oidcProfileT *profile)
{
    session->actualProfile = profile;
}

void oidcSessionSetTargetState(oidcSessionT* session, oidcStateT *state)
{
    session->targetState = state;
}

oidcStateT *oidcSessionGetTargetState(oidcSessionT* session)
{
    return session->targetState;
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

int oidcSessionSetFedIdLink(oidcSessionT *session,
                            const char *pseudo,
                            const char *email)
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

void oidcSessionSetFedIdLinkRequest(oidcSessionT *session, int request)
{
    session->fedidLinkRequest = request;
}

const fedSocialRawT *oidcSessionGetFedSocial(oidcSessionT *session)
{
    return session->social;
}

void oidcSessionSetFedSocial(oidcSessionT *session, fedSocialRawT *fedSocial)
{
    fedSocialUnRef(session->social);
    session->social = fedSocial;
}

// check if an attribute equal to value exists in the session
// return 1 if that is the case
// return 0 if none matches
int oidcSessionHasAttribute(oidcSessionT *session, const char *value)
{
    const fedSocialRawT *fedSocial = oidcSessionGetFedSocial(session);
    if (fedSocial != NULL) {
        const char **attrs = fedSocial->attrs;
        if (attrs != NULL) {
            for (; *attrs != NULL; attrs++) {
                if (!strcasecmp(value, *attrs))
                    return 1;
            }
        }
    }
    return 0;
}

const fedUserRawT *oidcSessionGetUser(oidcSessionT *session)
{
    return session->user;
}

void oidcSessionSetFedUser(oidcSessionT *session, fedUserRawT *fedUser)
{
    fedUserUnRef(session->user);
    session->user = fedUser;
}

void *oidcSessionGetOpaqueData(oidcSessionT *session)
{
    return oidcSessionGetActualData(session);
}

void oidcSessionSetOpaqueData(oidcSessionT *session, void *data)
{
    oidcSessionSetActualData(session, data, NULL);
}

void oidcSessionSetActualData(oidcSessionT* session, void *data, void (*freecb)(void*))
{
    if (session->freeData)
        session->freeData(session->data);
    session->data = data;
    session->freeData = freecb;
}

void *oidcSessionGetActualData(oidcSessionT* session)
{
    return session->data;
}

int oidcSessionEventSubscribe(afb_req_t wreq)
{
    oidcSessionT *session = oidcSessionOfReq(wreq);
    if (session->event == NULL) {
        int rc = afb_api_new_event(afb_req_get_api(wreq), "session",
                                   &session->event);
        if (rc < 0) {
            EXT_INFO("failed to create session event");
            return rc;
        }
    }
    afb_req_subscribe(wreq, session->event);
}

int oidcSessionEventPush(oidcSessionT *session, const char *desc, ...)
{
    int rc;
    va_list args;
    struct afb_data *data;
    struct json_object *obj = NULL;

    // no subscription made
    if (session->event == NULL)
        return 0;

    // format the json object
    va_start(args, desc);
    rc = rp_jsonc_vpack(&obj, desc, args);
    va_end(args);

    // create  the data
    if (rc >= 0)
        rc = afb_create_data_raw(&data, AFB_PREDEFINED_TYPE_JSON_C, obj, 0,
                                 (void *)json_object_put, obj);

    // check if event created
    if (rc < 0)
        EXT_ERROR("can't wrap event");
    else {
        // send the event
        rc = afb_event_push(session->event, 1, &data);
        if (rc <= 0) {
            // no listener, clear event and cookie
            afb_event_unref(session->event);
            session->event = NULL;
        }
    }
    return rc;
}

