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

#define _GNU_SOURCE

#include <string.h>

#include <rp-utils/rp-jsonc.h>

#include <libafb/afb-core.h>
#include <libafb/afb-http.h>
#include <libafb/afb-v4.h>

#include "oidc-alias.h"
#include "oidc-apis.h"
#include "oidc-core.h"
#include "oidc-fedid.h"
#include "oidc-idp.h"
#include "oidc-idsvc.h"

MAGIC_OIDC_SESSION(idsvcEvtCookie);
MAGIC_OIDC_SESSION(oidcFedLinkCookie);

typedef struct
{
    char *pseudo;
    char *email;
} fedidLinkT;

static void fedBackupFreeCB(void *ctx)
{
    fedidLinkT *backup = (fedidLinkT *)ctx;
    if (backup->pseudo)
        free(backup->pseudo);
    if (backup->email)
        free(backup->email);
    free(backup);
}

static void idsvcPing(afb_req_t wreq, unsigned argc, afb_data_t const argv[])
{
    static int count = 0;
    char *response;
    afb_data_t reply;

    asprintf(&response, "Pong=%d", count++);
    AFB_REQ_NOTICE(wreq, "idp:ping count=%d", count);

    afb_create_data_raw(&reply, AFB_PREDEFINED_TYPE_STRINGZ, response,
                        strlen(response) + 1, NULL, NULL);
    afb_req_reply(wreq, 0, 1, &reply);

    return;
}

// get result from /fedid/create-user
static void userCheckAttrCB(void *ctx,
                            int status,
                            unsigned argc,
                            const afb_data_t argv[],
                            afb_req_t wreq)
{
    static char errorMsg[] = "[user-attr-fail]  (userCheckAttrCB)";
    static char existMsg[] = "locked";
    static char freeMsg[] = "available";
    afb_data_t reply[1], argd[2];
    fedUserRawT *fedUser;
    oidcProfileT *profile;
    json_object *profileJ;

    // return creation status to HTML5
    if (status < 0)
        goto OnErrorExit;

    if (status > 0)
        afb_create_data_raw(&reply[0], AFB_PREDEFINED_TYPE_STRINGZ, existMsg,
                            sizeof(existMsg), NULL, NULL);
    else
        afb_create_data_raw(&reply[0], AFB_PREDEFINED_TYPE_STRINGZ, freeMsg,
                            sizeof(freeMsg), NULL, NULL);

    afb_req_reply(wreq, status, 1, reply);
    return;

OnErrorExit:
    afb_create_data_raw(&reply[0], AFB_PREDEFINED_TYPE_STRINGZ, errorMsg,
                        sizeof(errorMsg), NULL, NULL);
    afb_req_reply(wreq, -1, 1, reply);
    return;
}

// check user email/pseudo attribute
static void userCheckAttr(afb_req_t wreq,
                          unsigned argc,
                          afb_data_t const argv[])
{
    int err;

    if (argc != 1)
        goto OnErrorExit;
    afb_data_array_addref(argc, argv);
    afb_req_subcall(wreq, API_OIDC_USR_SVC, "user-check", argc, argv,
                    afb_req_subcall_on_behalf, userCheckAttrCB, NULL);
    return;

OnErrorExit:
    afb_req_reply(wreq, -100, 0, NULL);
}

static json_object *idpQueryList(afb_req_t wreq, const char **idps)
{
    json_object *responseJ, *idpsJ, *aliasJ;
    int err;

    // retrieve OIDC global context from API handle
    oidcCoreHdlT *oidc = afb_api_get_userdata(afb_req_get_api(wreq));
    if (!oidc || oidc->magic != MAGIC_OIDC_MAIN)
        goto OnErrorExit;

    // retrieve oidc config from current alias cookie
    oidcAliasT *alias;
    afb_session *session = afb_req_v4_get_common(wreq)->session;
    afb_session_cookie_get(session, oidcAliasCookie, (void **)&alias);

    // build IDP list with corresponding scope for requested LOA
    idpsJ = idpLoaProfilsGet(oidc, 0, idps, 1);
    if (alias)
        rp_jsonc_pack(&aliasJ, "{ss ss* ss si}", "uid", alias->uid, "info",
                      alias->info, "url", alias->url, "loa", alias->loa);
    else
        aliasJ = NULL;

    err = rp_jsonc_pack(&responseJ, "{so so*}", "idps", idpsJ, "alias", aliasJ);
    if (err)
        goto OnErrorExit;

    return responseJ;

OnErrorExit:
    return NULL;
}

// get result from /fedid/create-user
static void idpQueryUserCB(void *ctx,
                           int status,
                           unsigned argc,
                           const afb_data_t argv[],
                           afb_req_t wreq)
{
    json_object *obj;
    afb_data_t data = NULL;
    const char **idps;
    int err;

    // exit if request returned an error
    if (status < 0)
        goto OnErrorExit;

    // check that one value is returned
    status = AFB_ERRNO_INTERNAL_ERROR;
    if (argc != 1)
        goto OnErrorExit;

    // convert and retrieve input arguments
    err = afb_data_convert(argv[0], fedUserIdpsObjType, &data);
    if (err < 0)
        goto OnErrorExit;
    idps = (void *)afb_data_ro_pointer(data);

    // get the resulting object
    obj = idpQueryList(wreq, idps);
    afb_data_unref(data);
    if (obj == NULL)
        goto OnErrorExit;

    // create the replied data
    err = afb_create_data_raw(&data, AFB_PREDEFINED_TYPE_JSON_C, obj, 0,
                              (void *)json_object_put, obj);
    if (err >= 0)
        status = 0;

OnErrorExit:
    afb_req_reply(wreq, status, !status, &data);
    return;
}

// Return user register social IDPs for a given pseudo/email
static void idpQueryUser(afb_req_t wreq, unsigned argc, afb_data_t const argv[])
{
    static char errorMsg[] =
        "[idp-query-user] federated user unknown within DB (idpQueryUser) ";

    int err;
    fedidLinkT *fedBackup = NULL;
    json_object *queryJ;
    afb_data_t query, reply;

    // get current social data for further account linking
    afb_session *session = afb_req_v4_get_common(wreq)->session;
    afb_session_cookie_get(session, oidcFedLinkCookie, (void **)&fedBackup);

    // if not a slave IDP then use email/pseudo to get IDP list
    if (fedBackup) {
        rp_jsonc_pack(&queryJ, "{ss ss}", "email", fedBackup->email, "pseudo",
                      fedBackup->pseudo);
        afb_create_data_raw(&query, AFB_PREDEFINED_TYPE_JSON_C, queryJ, 0,
                            (void *)json_object_put, queryJ);
        afb_req_subcall(wreq, API_OIDC_USR_SVC, "social-idps", 1, &query,
                        afb_req_subcall_on_behalf, idpQueryUserCB, NULL);
        afb_session_cookie_delete(session, oidcFedLinkCookie);
    }
    else {
        // if no idps list provided build one from config
        oidcProfileT *profile;
        const char *idps[MAX_OIDC_IDPS + 1];
        int index = 0;
        afb_session_cookie_get(session, oidcIdpProfilCookie, (void **)&profile);
        for (int idx = 0; profile->idp->oidc->idps[idx].uid; idx++) {
            if (index == MAX_OIDC_IDPS) {
                EXT_ERROR(
                    "[idp-federate-list] too many idps in config "
                    "MAX_OIDC_IDPS=%d (remaining ignored)",
                    MAX_OIDC_IDPS);
                break;
            }
            oidcIdpT *idp = &profile->idp->oidc->idps[idx];
            if (strcasecmp(idp->uid, profile->idp->uid)) {
                idps[index++] = idp->uid;
            }
        }
        idps[index] = NULL;

        json_object *responseJ = idpQueryList(wreq, idps);
        if (!responseJ)
            goto OnErrorExit;
        afb_create_data_raw(&reply, AFB_PREDEFINED_TYPE_JSON_C, responseJ, 0,
                            (void *)json_object_put, responseJ);
        afb_req_reply(wreq, 0, 1, &reply);
    }
    return;

OnErrorExit:
    afb_create_data_raw(&reply, AFB_PREDEFINED_TYPE_STRINGZ, errorMsg,
                        strlen(errorMsg) + 1, NULL, NULL);
    afb_req_reply(wreq, -1, 1, &reply);
}

// get result from /fedid/create-user
static void userRegisterCB(void *ctx,
                           int status,
                           unsigned argc,
                           const afb_data_t argv[],
                           afb_req_t wreq)
{
    char *errorMsg = "[user-create-fail]  (idsvcuserRegisterCB)";
    afb_data_t reply[1], argd[2];
    oidcProfileT *profile;
    oidcAliasT *alias;
    json_object *aliasJ;
    afb_session *session = afb_req_v4_get_common(wreq)->session;

    // return creation status to HTML5
    if (status < 0)
        goto OnErrorExit;

    // return destination alias
    afb_session_cookie_get(session, oidcIdpProfilCookie, (void **)&profile);
    afb_session_set_loa(session, oidcSessionCookie, profile->loa);
    afb_session_cookie_get(session, oidcAliasCookie, (void **)&alias);
    rp_jsonc_pack(&aliasJ, "{ss}", "target", alias->url ?: "/");
    afb_create_data_raw(&reply[0], AFB_PREDEFINED_TYPE_JSON_C, aliasJ, 0,
                        (void *)json_object_put, aliasJ);
    afb_req_reply(wreq, status, 1, reply);
    return;

OnErrorExit:
    afb_create_data_raw(&reply[0], AFB_PREDEFINED_TYPE_STRINGZ, errorMsg,
                        strlen(errorMsg) + 1, NULL, NULL);
    afb_req_reply(wreq, -1, 1, reply);
    return;
}

// Try to store fedsocial and feduser into local store
static void userRegister(afb_req_t wreq, unsigned argc, afb_data_t const argv[])
{
    const oidcProfileT *profile;
    afb_data_t params[2];
    const fedSocialRawT *fedSocial;
    int err, status;

    // get first argument and check the request
    status = AFB_ERRNO_INVALID_REQUEST;
    if (argc != 1)
        goto OnErrorExit;

    err = afb_data_convert(argv[0], fedUserObjType, &params[0]);
    if (err < 0)
        goto OnErrorExit;

    status = AFB_ERRNO_BAD_API_STATE;

    // retrieve current wreq LOA from session (to be fixed by Jose)
    afb_session *session = afb_req_v4_get_common(wreq)->session;
    afb_session_cookie_get(session, oidcIdpProfilCookie, (void **)&profile);
    if (!profile)
        goto OnErrorExit2;

    // retrieve fedsocial from session
    afb_session_cookie_get(session, oidcFedSocialCookie, (void **)&fedSocial);
    if (!fedSocial)
        goto OnErrorExit2;

    // user is new let's register it within fedid DB (do not free fedSocial
    // after call)
    status = AFB_ERRNO_INTERNAL_ERROR;
    err = afb_create_data_raw(&params[1], fedSocialObjType, fedSocial, 0, NULL,
                              NULL);
    if (err < 0)
        goto OnErrorExit2;

    afb_req_subcall(wreq, API_OIDC_USR_SVC, "user-create", 2, params,
                    afb_req_subcall_on_behalf, userRegisterCB, NULL);
    return;

OnErrorExit2:
    afb_data_unref(params[0]);
OnErrorExit:
    AFB_REQ_ERROR(wreq, "userRegister failed %d", status);
    afb_req_reply(wreq, status, 0, NULL);
}

static void userFederateCB(void *ctx,
                           int status,
                           unsigned argc,
                           const afb_data_t argv[],
                           afb_req_t wreq)
{
    static char errorMsg[] =
        "[user-federate-unavailable] should try user-register (userFederateCB)";
    fedUserRawT *fedUser = (fedUserRawT *)ctx;
    fedidLinkT *fedBackup;
    afb_data_t reply[1];
    oidcProfileT *profile;
    oidcAliasT *alias;
    json_object *responseJ;
    int err;

    if (status <= 0)
        goto OnErrorExit;

    // get used IDP profile to access oidc wellknown urls
    afb_session *session = afb_req_v4_get_common(wreq)->session;
    afb_session_cookie_get(session, oidcIdpProfilCookie, (void **)&profile);
    if (!profile)
        goto OnErrorExit;

    // copy current user social and registration data for further federation
    // request
    fedBackup = malloc(sizeof(fedSocialRawT));
    fedBackup->pseudo = strdup(fedUser->pseudo);
    fedBackup->email = strdup(fedUser->email);
    afb_session_cookie_set(session, oidcFedLinkCookie, (void *)fedBackup,
                           fedBackupFreeCB, fedBackup);

    // force federation mode within fedidCheckCB
    afb_session_set_loa(session, oidcFedSocialCookie, FEDID_LINK_REQUESTED);
    err = rp_jsonc_pack(&responseJ, "{ss}", "target",
                        profile->idp->oidc->globals->fedlinkUrl);
    if (err)
        goto OnErrorExit;

    afb_create_data_raw(reply, AFB_PREDEFINED_TYPE_JSON_C, responseJ, 0,
                        (void *)json_object_put, responseJ);
    afb_req_reply(wreq, 0, 1, reply);

    return;

OnErrorExit:
    afb_create_data_raw(&reply[0], AFB_PREDEFINED_TYPE_STRINGZ, errorMsg,
                        sizeof(errorMsg), NULL, NULL);
    afb_req_reply(wreq, -1, 1, reply);
    return;
}

// backup social data for further federation social linking
static void userFederate(afb_req_t wreq, unsigned argc, afb_data_t const argv[])
{
    char *errorMsg = "[user-federate-fail] invalid/missing query arguments";
    afb_event_t evtCookie;
    const oidcProfileT *profile;
    const fedSocialRawT *fedSocial;
    fedUserRawT *fedUser;
    json_object *responseJ;
    afb_data_t data;
    int err, status;

    // get first argument and check the request
    status = AFB_ERRNO_INVALID_REQUEST;
    if (argc != 1)
        goto OnErrorExit;

    err = afb_req_param_convert(wreq, 0, fedUserObjType, &data);
    if (err < 0)
        goto OnErrorExit;

    // check if pseudo/email already present within user federation db
    afb_data_addref(data);
    fedUser = afb_data_ro_pointer(data);
    afb_req_subcall(wreq, API_OIDC_USR_SVC, "user-exist", 1, &data,
                    afb_req_subcall_on_behalf, userFederateCB, fedUser);
    return;

OnErrorExit:
    afb_req_reply(wreq, status, 0, NULL);
}

static void sessionReset(afb_req_t wreq, unsigned argc, afb_data_t const argv[])
{
    json_object *responseJ;
    afb_session *session = afb_req_v4_get_common(wreq)->session;
    const oidcProfileT *profile;
    afb_data_t reply;

    afb_session_cookie_get(session, oidcIdpProfilCookie, (void **)&profile);
    if (!profile)
        goto OnErrorExit;

    fedidsessionReset(session, profile);

    rp_jsonc_pack(&responseJ, "{ss ss* ss*}", "home",
                  profile->idp->oidc->globals->homeUrl ?: "/", "login",
                  profile->idp->oidc->globals->loginUrl, "error",
                  profile->idp->oidc->globals->errorUrl);
    afb_create_data_raw(&reply, AFB_PREDEFINED_TYPE_JSON_C, responseJ, 0,
                        (void *)json_object_put, responseJ);
    afb_req_reply(wreq, 0, 1, &reply);

    return;

OnErrorExit:
    afb_req_reply(wreq, -1, 0, NULL);
}

// Return all information we have on current session (profile, loa, idp, ...)
static void sessionGet(afb_req_t wreq, unsigned argc, afb_data_t const argv[])
{
    char *errorMsg = "[fail-session-get] no session running anonymous mode";
    afb_data_t reply[3];
    afb_event_t evtCookie;
    const oidcProfileT *profile;
    fedUserRawT *fedUser;
    fedSocialRawT *fedSocial;
    json_object *profileJ;

    // retrieve current wreq LOA from session (to be fixed by Jose)
    afb_session *session = afb_req_v4_get_common(wreq)->session;
    afb_session_cookie_get(session, oidcIdpProfilCookie, (void **)&profile);
    if (!profile)
        goto OnErrorExit;

    rp_jsonc_pack(&profileJ, "{ss ss si}", "uid", profile->uid, "scope",
                  profile->scope, "loa", profile->loa);

    afb_session_cookie_get(session, oidcFedUserCookie, (void **)&fedUser);
    afb_session_cookie_get(session, oidcFedSocialCookie, (void **)&fedSocial);
    afb_create_data_raw(&reply[0], fedUserObjType, fedUser, 0, NULL, NULL);
    afb_create_data_raw(&reply[1], fedSocialObjType, fedSocial, 0, NULL,
                        NULL);  // keep feduser
    afb_create_data_raw(&reply[2], AFB_PREDEFINED_TYPE_JSON_C, profileJ, 0,
                        (void *)json_object_put, profileJ);

    afb_req_reply(wreq, 0, 3, reply);
    return;

OnErrorExit:
    AFB_REQ_ERROR(wreq, "%s", errorMsg);
    afb_create_data_raw(&reply[0], AFB_PREDEFINED_TYPE_STRINGZ, errorMsg,
                        strlen(errorMsg) + 1, NULL, NULL);
    afb_req_reply(wreq, -1, 1, reply);
}

// if not already done create and register a session event
static void subscribeEvent(afb_req_t wreq,
                           unsigned argc,
                           afb_data_t const argv[])
{
    const char *errorMsg =
        "[fail-event-create] hoops internal error (idsvcSubscribe)";
    int err;
    char *response;
    afb_data_t reply;
    afb_event_t evtCookie;

    // retrieve current wreq LOA from session (to be fixed by Jose)
    afb_session *session = afb_req_v4_get_common(wreq)->session;
    afb_session_cookie_get(session, idsvcEvtCookie, (void **)&evtCookie);
    if (!evtCookie) {
        err = afb_api_new_event(afb_req_get_api(wreq), "session", &evtCookie);
        if (err < 0)
            goto OnErrorExit;
        afb_session_cookie_set(session, idsvcEvtCookie, (void *)evtCookie, NULL,
                               NULL);
    }
    EXT_DEBUG("[session-evt-sub] client subscribed session uuid=%s",
              afb_session_uuid(session));
    afb_req_subscribe(wreq, evtCookie);

    asprintf(&response, "session-uuid=%s", afb_session_uuid(session));
    afb_create_data_raw(&reply, AFB_PREDEFINED_TYPE_STRINGZ, response,
                        strlen(response) + 1, free, NULL);
    afb_req_reply(wreq, 0, 1, &reply);

    return;

OnErrorExit:
    afb_create_data_raw(&reply, AFB_PREDEFINED_TYPE_STRINGZ, errorMsg,
                        strlen(errorMsg) + 1, NULL, NULL);
    afb_req_reply(wreq, -1, 1, &reply);
}

// Push a json object event to html5 application
int idscvPushEvent(afb_session *session, json_object *eventJ)
{
    int count;
    afb_event_t evtCookie;
    afb_data_t reply;

    afb_session_cookie_get(session, idsvcEvtCookie, (void **)&evtCookie);
    if (!evtCookie)
        goto OnErrorExit;

    // create an API-V4 json param
    afb_create_data_raw(&reply, AFB_PREDEFINED_TYPE_JSON_C, eventJ, 0,
                        (void *)json_object_put, eventJ);
    count = afb_event_push(evtCookie, 1, &reply);

    // no one listening clear event and cookie
    if (count <= 0) {
        afb_event_unref(evtCookie);
        afb_session_cookie_set(session, idsvcEvtCookie, NULL, NULL, NULL);
    }

    return count;

OnErrorExit:
    json_object_put(eventJ);
    return -1;
}

// return the list of autorities matching requested LOA
static void idpQueryConf(afb_req_t wreq, unsigned argc, afb_data_t const argv[])
{
    static const char unauthorizedMsg[] =
        "[unauthorized-api-call] authenticate to upgrade session/loa "
        "(idpQueryConf)";
    int err;
    afb_data_t reply;
    json_object *idpsJ, *responseJ, *aliasJ;
    oidcAliasT *alias;

    // retrieve OIDC global context from API handle
    oidcCoreHdlT *oidc = afb_api_get_userdata(afb_req_get_api(wreq));
    if (!oidc || oidc->magic != MAGIC_OIDC_MAIN)
        goto OnErrorExit;

    // retrieve current wreq LOA from session (to be fixed by Jose)
    afb_session *session = afb_req_v4_get_common(wreq)->session;
    afb_session_cookie_get(session, oidcAliasCookie, (void **)&alias);

    // build IDP list with corresponding scope for requested LOA
    if (alias) {
        idpsJ = idpLoaProfilsGet(oidc, alias->loa, NULL, 0);
        rp_jsonc_pack(&aliasJ, "{ss ss* ss si}", "uid", alias->uid, "info",
                      alias->info, "url", alias->url, "loa", alias->loa);
    }
    else {
        idpsJ = idpLoaProfilsGet(oidc, 0, NULL, 0);
        aliasJ = NULL;
    }

    err = rp_jsonc_pack(&responseJ, "{so so*}", "idps", idpsJ, "alias", aliasJ);
    if (err)
        goto OnErrorExit;

    afb_create_data_raw(&reply, AFB_PREDEFINED_TYPE_JSON_C, responseJ, 0,
                        (void *)json_object_put, responseJ);
    afb_req_reply(wreq, 0, 1, &reply);

    return;

OnErrorExit:
    AFB_REQ_ERROR(wreq, unauthorizedMsg);
    afb_create_data_raw(&reply, AFB_PREDEFINED_TYPE_STRINGZ, unauthorizedMsg,
                        sizeof(unauthorizedMsg), NULL, NULL);
    afb_req_reply(wreq, -1, 1, &reply);
}

// return the list of autorities matching requested LOA
static void urlQuery(afb_req_t wreq, unsigned argc, afb_data_t const argv[])
{
    static const char unauthorizedMsg[] =
        "[unauthorized-api-call] authenticate to upgrade session/loa "
        "(urlQuery)";
    int err;
    afb_data_t reply;
    json_object *responseJ;

    // retrieve OIDC global context from API handle
    oidcCoreHdlT *oidc = afb_api_get_userdata(afb_req_get_api(wreq));
    if (!oidc || oidc->magic != MAGIC_OIDC_MAIN)
        goto OnErrorExit;

    err = rp_jsonc_pack(
        &responseJ, "{ss ss ss ss ss}", "home", oidc->globals->homeUrl, "login",
        oidc->globals->loginUrl, "federate", oidc->globals->fedlinkUrl,
        "register", oidc->globals->registerUrl, "error",
        oidc->globals->errorUrl);
    if (err)
        goto OnErrorExit;

    afb_create_data_raw(&reply, AFB_PREDEFINED_TYPE_JSON_C, responseJ, 0,
                        (void *)json_object_put, responseJ);
    afb_req_reply(wreq, 0, 1, &reply);

    return;

OnErrorExit:
    AFB_REQ_ERROR(wreq, unauthorizedMsg);
    afb_create_data_raw(&reply, AFB_PREDEFINED_TYPE_STRINGZ, unauthorizedMsg,
                        sizeof(unauthorizedMsg), NULL, NULL);
    afb_req_reply(wreq, -1, 1, &reply);
}

// Static verb not depending on shell json config file
static afb_verb_t idsvcVerbs[] = {
    /* VERB'S NAME         FUNCTION TO CALL         SHORT DESCRIPTION */
    {.verb = "ping", .callback = idsvcPing, .info = "ping test"},
    {.verb = "url-query-conf",
     .callback = urlQuery,
     .info = "wreq wellknown url list/tag"},
    {.verb = "idp-query-conf",
     .callback = idpQueryConf,
     .info = "wreq idp list/scope for a given LOA level"},
    {.verb = "idp-query-user",
     .callback = idpQueryUser,
     .info = "return pseudo/email idps list before linking user multiple IDPs"},
    {.verb = "session-get",
     .callback = sessionGet,
     .info = "retrieve current client session [profile, user, social]"},
    {.verb = "session-event",
     .callback = subscribeEvent,
     .info = "subscribe to sgate private client session events"},
    {.verb = "session-reset",
     .callback = sessionReset,
     .info = "reset current session [set loa=0]"},
    {.verb = "usr-register",
     .callback = userRegister,
     .info = "register federated user profile into local fedid store"},
    {.verb = "usr-check",
     .callback = userCheckAttr,
     .info = "check user attribute within local store"},
    {.verb = "usr-federate",
     .callback = userFederate,
     .info = "request federating current user with an other existing IDP"},
    {NULL}  // terminator
};

int idsvcDeclare(oidcCoreHdlT *oidc,
                 afb_apiset *declare_set,
                 afb_apiset *call_set)
{
    int err;

    oidcApisT apiSvc = {
        .uid = oidc->api,
        .info = "internal oidc idp api",
        .uri = "@oidc",
        .loa = 0,
    };

    // register fedid type
    err = fedUserObjTypesRegister();
    if (err)
        goto OnErrorExit;

    // register verbs
    err = apisCreateSvc(oidc, &apiSvc, declare_set, call_set, idsvcVerbs);
    if (err)
        goto OnErrorExit;

    return 0;

OnErrorExit:
    return 1;
}
