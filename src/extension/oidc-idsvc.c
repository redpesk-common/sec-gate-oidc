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

#include <string.h>

#include <rp-utils/rp-jsonc.h>

#include <libafb/afb-apis.h>
#include <libafb/afb-core.h>
#include <libafb/afb-http.h>
#include <libafb/afb-v4.h>

#include <fedid-types-glue.h>

#include "fedid-client.h"
#include "oidc-alias.h"
#include "oidc-apis.h"
#include "oidc-core.h"
#include "oidc-login.h"
#include "oidc-idp.h"
#include "oidc-idsvc.h"
#include "oidc-session.h"

#define MAX_OIDC_IDPS 16  // max number of IDPS in config

/*
 * Basic wrapper function for creation of string data
 * Create a data of type AFB_PREDEFINED_TYPE_STRINGZ for the
 * string. When destroy is not null, the string will be freed
 * when data is released.
 */
static int makeStringData(afb_data_t *data, const char *string, int destroy)
{
    return afb_create_data_raw(data, AFB_PREDEFINED_TYPE_STRINGZ, string,
                               string == NULL ? 0 : 1 + strlen(string),
                               destroy ? free : NULL,
                               destroy ? (void *)string : NULL);
}

/*
 * Basic wrapper function for creation of string data
 * Create a data of type AFB_PREDEFINED_TYPE_STRINGZ for the
 * string.
 */
static int makeJSONData(afb_data_t *data, struct json_object *obj)
{
    return afb_create_data_raw(data, AFB_PREDEFINED_TYPE_JSON_C, obj, 0,
                               (void (*)(void *))json_object_put, obj);
}

/*
 * helper function for getting oidc core object from a request
 */
static const oidcCoreHdlT *wreq2oidc(afb_req_t wreq)
{
    return (const oidcCoreHdlT *)afb_api_get_userdata(afb_req_get_api(wreq));
}

/*
 * helper for returning out of memory error
 */
static void replyError(afb_req_t wreq, int code, const char *message)
{
    AFB_REQ_ERROR(wreq, "%s", message);
    afb_req_reply(wreq, code, 0, NULL);
}

/*
 * helper for returning out of memory error
 */
static void replyOOM(afb_req_t wreq)
{
    return replyError(wreq, AFB_ERRNO_OUT_OF_MEMORY, "out of memory");
}

/*
 * helper for returning invalid request
 */
static void replyInvalid(afb_req_t wreq)
{
    return replyError(wreq, AFB_ERRNO_INVALID_REQUEST, "invalid request");
}

/*
 * helper for returning invalid state
 */
static void replyBadState(afb_req_t wreq)
{
    return replyError(wreq, AFB_ERRNO_BAD_API_STATE, "invalid state");
}

/*
 * helper for returning invalid state
 */
static void replyInternalError(afb_req_t wreq)
{
    return replyError(wreq, AFB_ERRNO_INTERNAL_ERROR, "internal error");
}

/*
 * build JSON reply for idps and send it as reply
 */
static void replyIdpList(afb_req_t wreq,
                         const char **idps,
                         int loa,
                         int noslave)
{
    afb_data_t reply;
    int rc = 0;
    json_object *responseJ = NULL, *idpsJ, *aliasJ = NULL;

    // retrieve OIDC global context from API handle
    const oidcCoreHdlT *oidc = wreq2oidc(wreq);

    // retrieve oidc config from current alias cookie
    oidcSessionT *session = oidcSessionOfReq(wreq);
    const oidcAliasT *alias = oidcSessionGetTargetPage(session);

    // build IDP list with corresponding scope for requested LOA
    if (alias != NULL) {
        rc = rp_jsonc_pack(&aliasJ, "{ss ss* ss si}", "uid", alias->uid, "info",
                           alias->info, "url", alias->url, "loa", alias->loa);
        if (rc < 0)
            return replyOOM(wreq);
        if (loa < 0)
            loa = alias->loa;
    }
    idpsJ = oidcCoreGetProfilesForLOA(oidc, loa, idps, noslave);

    // create the reply data
    rc = rp_jsonc_pack(&responseJ, "{so so*}", "idps", idpsJ, "alias", aliasJ);
    if (rc < 0) {
        json_object_put(aliasJ);
        json_object_put(idpsJ);
        return replyOOM(wreq);
    }
    rc = makeJSONData(&reply, responseJ);
    if (rc < 0)
        return replyOOM(wreq);

    // return the computed data
    afb_req_reply(wreq, 0, 1, &reply);
}

/************************************************************************
 * Implement verb "ping"
 *
 * Accept any argument
 *
 * Checks in the table of users if an entry exists with the given
 * value.
 *
 * Return the status 1 and the string value 'locked' if an entry
 * is found or the status 0 and the string 'available' otherwise.
 * If a negative status is returned, it indecates an error.
 */

static void idsvcPing(afb_req_t wreq, unsigned argc, afb_data_t const argv[])
{
    static int count = 0;
    char *buffer;
    afb_data_t data;
    int rc;

    // increment count
    if (++count < 0)
        count = 1;
    AFB_REQ_INFO(wreq, "idp:ping count=%d", count);

    // make output
    rc = asprintf(&buffer, "Pong=%d", count);
    if (rc >= 0)
        rc = makeStringData(&data, buffer, 1);

    // send the reply
    if (rc < 0)
        afb_req_reply(wreq, AFB_ERRNO_INTERNAL_ERROR, 0, NULL);
    else
        afb_req_reply(wreq, count, 1, &data);
}

/************************************************************************
 * Implement verb "usr-check"
 *
 * Receive a JSON object with 2 fields: label and value
 *
 * Checks in the table of users if an entry exists with the given
 * value.
 *
 * Return the status 1 and the string value 'locked' if an entry
 * is found or the status 0 and the string 'available' otherwise.
 * If a negative status is returned, it indicates an error.
 */

static void userCheckAttrCB(void *ctx,
                            int status,
                            unsigned argc,
                            const afb_data_t argv[],
                            afb_req_t wreq)
{
    if (status < 0) {
        // got an error from fedid
        EXT_NOTICE("[oidc-idsvc] usr-check got error");
        afb_data_array_addref(argc, argv);
        afb_req_reply(wreq, status, argc, argv);
    }
    else {
        // no error, try to add the string
        afb_data_t data;
        int rc = makeStringData(&data, status ? "locked" : "available", 0);
        afb_req_reply(wreq, status, rc >= 0, &data);
    }
}

static void userCheckAttr(afb_req_t wreq,
                          unsigned argc,
                          afb_data_t const argv[])
{
    afb_data_array_addref(argc, argv);
    fedIdClientSubCall(wreq, "user-check", argc, argv, userCheckAttrCB, NULL);
}

/************************************************************************
 * Implement verb "idp-query-user"
 *
 * The verb "idp-query-user" doesn't expect any parameter but looks into
 * the current state of the client session if 'fedidlink' is set or not.
 *
 * If 'fedidlink' is set, returns the list of IDP for the linked user.
 *
 * If 'fedidlink' is not set, the list of IDP is all IDPs excluding the
 * current one.
 */

/*
 * build JSON reply and send it
 */
static void idpQueryUserReply(afb_req_t wreq, const char **idps)
{
    replyIdpList(wreq, idps, 0, 1);  // TODO values of loa and noslave?
}
/*
 * receive list of IDP from fedid
 * send reply from that list
 */
static void idpQueryUserCB(void *ctx,
                           int status,
                           unsigned argc,
                           const afb_data_t argv[],
                           afb_req_t wreq)
{
    afb_data_t data;
    if (status < 0) {
        // got an error from fedid
        EXT_NOTICE("[oidc-idsvc] idp-query-user got error from fedid");
        afb_data_array_addref(argc, argv);
        afb_req_reply(wreq, status, argc, argv);
    }
    else if (argc != 1 ||
             0 > afb_data_convert(argv[0], fedUserIdpsObjType, &data)) {
        // unexpected result
        EXT_NOTICE("[oidc-idsvc] idp-query-user got strange thing from fedid");
        afb_req_reply(wreq, AFB_ERRNO_INTERNAL_ERROR, 0, NULL);
    }
    else {
        // reply to the query
        const char **idps = (void *)afb_data_ro_pointer(data);
        idpQueryUserReply(wreq, idps);
        afb_data_unref(data);
    }
}
/*
 * Return user registered social IDPs
 */
static void idpQueryUser(afb_req_t wreq, unsigned argc, afb_data_t const argv[])
{
    // get current social data for further account linking
    oidcSessionT *session = oidcSessionOfReq(wreq);
    const fedUserRawT *fedUser = oidcSessionGetUser(session);
    if (fedUser != NULL) {
        // fedUser is set
        int rc;
        afb_data_t data;
        rc = afb_data_create_raw(&data, fedUserObjType, fedUser, 0, NULL, NULL);
        if (rc < 0)
            return replyOOM(wreq);
        fedIdClientSubCall(wreq, "social-idps", 1, &data, idpQueryUserCB, NULL);
    }
    else {
        // fedUser isn't set
        oidcStateT *state = oidcSessionGetActualState(session);
        const oidcCoreHdlT *oidc = wreq2oidc(wreq);
        const oidcProfileT *profile = state ? oidcStateGetProfile(state) : NULL;
        const char *idpId = profile != NULL ? profile->idp->uid : NULL;
        const char *idps[MAX_OIDC_IDPS + 1];
        int count =
            oidcCoreGetFilteredIdpList(oidc, idps, MAX_OIDC_IDPS + 1, idpId);
        if (count > MAX_OIDC_IDPS) {
            EXT_WARNING("[oidc-idsvc] too many idps, truncates to %d firsts",
                        MAX_OIDC_IDPS);
            count = MAX_OIDC_IDPS;
        }
        idps[count] = NULL;
        idpQueryUserReply(wreq, idps);
    }
}

/************************************************************************
 * Implement the verb 'usr-register'
 *
 * The verb 'usr-register' expects a single argument: a user description
 * either as a fedUserRawT (see sec-gate-fedid-binding') or a JSON object
 * like '{pseudo, email, name, avatar, company, stamp, attrs}'
 *
 * It also expects that the current connection state has been identified
 * by some IDP and that the current Social status is known in the session.
 *
 * On success, the verbs replies a JSON object {"target":"URL"} where
 * URL is the url of the page to load after registration.
 */
// get result from /fedid/create-user
static void userRegisterCB(void *ctx,
                           int status,
                           unsigned argc,
                           const afb_data_t argv[],
                           afb_req_t wreq)
{
    oidcSessionT *session = oidcSessionOfReq(wreq);

    if (status < 0) {
        // got an error from fedid
        EXT_NOTICE("[oidc-idsvc] usr-register got error from fedid");
        oidcSessionSetUser(session, NULL);
        afb_data_array_addref(argc, argv);
        return afb_req_reply(wreq, status, argc, argv);
    }

    afb_data_t reply;
    json_object *aliasJ;
    int rc;

    // return destination alias
    const oidcAliasT *alias = oidcSessionGetTargetPage(session);

    // reply to the query
    rc = rp_jsonc_pack(&aliasJ, "{ss}", "target",
                       alias->url != NULL ? alias->url : "/");
    if (rc >= 0)
        rc = makeJSONData(&reply, aliasJ);
    if (rc < 0)
        return replyOOM(wreq);
    afb_req_reply(wreq, status, 1, &reply);
}

// Try to store fedsocial and feduser into local store
static void userRegister(afb_req_t wreq, unsigned argc, afb_data_t const argv[])
{
    afb_data_t params[2];
    oidcSessionT *session;
    oidcStateT *state;
    const oidcAliasT *alias;
    fedUserRawT *fedUser;
    const fedSocialRawT *fedSocial;
    int rc;

    // retrieve current wreq LOA from session (to be fixed by Jose)
    // Check the current API state: retrieve fedsocial from session
    session = oidcSessionOfReq(wreq);
    state = oidcSessionGetActualState(session);
    fedSocial = state == NULL ? NULL : oidcStateGetSocial(state);
    alias = oidcSessionGetTargetPage(session);
    if (state == NULL || alias == NULL || fedSocial == NULL)
        return replyBadState(wreq);

    // get first argument and check it as being a fedUser value
    rc = afb_req_param_convert(wreq, 0, fedUserObjType, &params[0]);
    if (rc < 0 || argc != 1)
        return replyInvalid(wreq);

    // record the actual user
    fedUser = (fedUserRawT *)afb_data_ro_pointer(params[0]);
    oidcSessionSetUser(session, fedUser);

    // user is new let's register it within fedid DB (do not free fedSocial
    // after call)
    rc = afb_create_data_raw(&params[1], fedSocialObjType, fedSocial, 0, NULL,
                             NULL);
    if (rc < 0)
        return replyOOM(wreq);

    afb_data_addref(params[0]);
    fedIdClientSubCall(wreq, "user-create", 2, params, userRegisterCB, NULL);
}

/************************************************************************
 * Implement the verb 'usr-federate'
 *
 * The verb 'usr-federate' expects a single argument: a user description
 * either as a fedUserRawT (see sec-gate-fedid-binding') or a JSON object
 * like '{pseudo, email, name, avatar, company, stamp, attrs}'
 *
 * It then calls fedid/user-exist in order to check if the given
 * user (pseudo and/or login) exists. If it exists, it is recorded in the
 * session to be federated and the url of the federation page is returned.
 *
 * Otherwise, an error is returned.
 */
static void userFederateCB(void *ctx,
                           int status,
                           unsigned argc,
                           const afb_data_t argv[],
                           afb_req_t wreq)
{
    afb_data_t data = ctx;
    fedUserRawT *fedUser = afb_data_ro_pointer(data);
    afb_data_t reply;
    json_object *responseJ;
    oidcSessionT *session;
    int rc;

    // subcall failed
    if (status < 0)
        return afb_req_reply(wreq, status, 0, NULL);

    // user isn't recorded
    if (status == 0) {
        EXT_INFO("user not recorded, pseudo=%s, email=%s", fedUser->pseudo,
                 fedUser->email);
        return replyInvalid(wreq);
    }

    // copy current user social and registration data for further federation
    // request
    session = oidcSessionOfReq(wreq);
    oidcSessionSetUser(session, fedUser);
    oidcSessionSetFederating(session);

    // Send the url of the federation
    rc = rp_jsonc_pack(&responseJ, "{ss}", "target",
                       oidcCoreGlobals(wreq2oidc(wreq))->fedlinkUrl);
    if (rc >= 0)
        rc = makeJSONData(&reply, responseJ);
    if (rc < 0)
        return replyOOM(wreq);

    afb_req_reply(wreq, 0, 1, &reply);
}

// backup social data for further federation social linking
static void userFederate(afb_req_t wreq, unsigned argc, afb_data_t const argv[])
{
    afb_data_t data;

    // get first argument and check the request
    if (argc != 1 || afb_req_param_convert(wreq, 0, fedUserObjType, &data) < 0)
        return replyInvalid(wreq);

    // check if pseudo/email already present within user federation db
    afb_data_addref(data);
    fedIdClientSubCall(wreq, "user-exist", 1, &data, userFederateCB, data);
}

/************************************************************************
 * Implement the verb 'session-reset'
 *
 * The verb 'session-reset' expects no argument.
 */

static void sessionReset(afb_req_t wreq, unsigned argc, afb_data_t const argv[])
{
    oidcSessionT *session = oidcSessionOfReq(wreq);
    json_object *responseJ;
    afb_data_t reply;
    int rc;

    oidcSessionReset(session);

    const oidGlobalsT *globals = oidcCoreGlobals(wreq2oidc(wreq));
    rc = rp_jsonc_pack(&responseJ, "{ss ss* ss*}", "home",
                       globals->homeUrl != NULL ? globals->homeUrl : "/",
                       "login", globals->loginUrl, "error", globals->errorUrl);
    if (rc >= 0)
        rc = makeJSONData(&reply, responseJ);
    if (rc < 0)
        return replyOOM(wreq);

    afb_req_reply(wreq, 0, 1, &reply);
}

/************************************************************************
 * Implement the verb 'session-get'
 *
 * The verb 'session-get' expects no argument.
 */

// Return all information we have on current session (profile, loa, idp, ...)
static void sessionGet(afb_req_t wreq, unsigned argc, afb_data_t const argv[])
{
    afb_data_t reply[3];
    oidcSessionT *session;
    oidcStateT *state;
    const oidcProfileT *profile;
    const fedUserRawT *fedUser;
    const fedSocialRawT *fedSocial;
    json_object *profileJ;
    int rc;

    // retrieve current wreq LOA from session (to be fixed by Jose)
    session = oidcSessionOfReq(wreq);
    state = oidcSessionGetActualState(session);
    if (state == NULL)
        return replyBadState(wreq);
    fedUser = oidcSessionGetUser(session);
    if (fedUser == NULL)
        fedUser = oidcStateGetUser(state);
    if (fedUser == NULL)
        return replyBadState(wreq);
    profile = oidcStateGetProfile(state);
    fedSocial = oidcStateGetSocial(state);
    if (profile == NULL || fedSocial == NULL)
        return replyBadState(wreq);

    rc = rp_jsonc_pack(&profileJ, "{ss ss si}", "uid", profile->uid, "scope",
                       profile->scope, "loa", profile->loa);
    if (rc >= 0)
        rc = makeJSONData(&reply[2], profileJ);
    if (rc >= 0) {
        rc = afb_create_data_raw(&reply[0], fedUserObjType, fedUser, 0, NULL,
                                 NULL);
        if (rc >= 0) {
            rc = afb_create_data_raw(&reply[1], fedSocialObjType, fedSocial, 0,
                                     NULL,
                                     NULL);  // keep feduser
            if (rc >= 0)
                return afb_req_reply(wreq, 0, 3, reply);
            afb_data_unref(reply[0]);
        }
        afb_data_unref(reply[2]);
    }
    return replyOOM(wreq);
}
/************************************************************************
 * Implement the verb 'session-event'
 *
 * The verb 'session-event' doesn't expect any argument.
 *
 * It  creates a session event if needed and subscribe to it
 */
static void subscribeEvent(afb_req_t wreq,
                           unsigned argc,
                           afb_data_t const argv[])
{
    int rc = oidcSessionEventSubscribe(wreq);
    EXT_DEBUG("[oidc-idsvc] client subscribe: %d", rc);
    if (rc < 0)
        return replyInternalError(wreq);

    afb_req_reply(wreq, 0, 0, NULL);
}

/************************************************************************
 * Implement the verb 'idp-query-conf'
 *
 * The verb 'idp-query-conf' doesn't expect any argument.
 *
 * It checks the current state and if a targeted page exists, it returns the
 * list of idps for reaching that page. Otherwise, it returns the full list
 * of known idps.
 *
 * On success, the verbs replies a JSON object {"idps":[ ... ], "alias": ...}
 * where idps is a list of idp descriptions, one per idp. alias is present
 * only if a target page exists. It then describes that page.
 */

// return the list of autorities matching requested LOA
static void idpQueryConf(afb_req_t wreq, unsigned argc, afb_data_t const argv[])
{
    replyIdpList(wreq, NULL, -1, 0);
}

/************************************************************************
 * Implement the verb 'url-query-conf'
 *
 * The verb 'url-query-conf' doesn't expect any argument.
 *
 * It returns the global urls of the sec-gate: home, login, federate, register,
 * error
 */
static void urlQuery(afb_req_t wreq, unsigned argc, afb_data_t const argv[])
{
    int rc;
    afb_data_t reply;
    json_object *responseJ;

    // retrieve OIDC global context from API handle
    const oidcCoreHdlT *oidc = wreq2oidc(wreq);
    const oidGlobalsT *globals = oidcCoreGlobals(oidc);

    // build the reply
    rc = rp_jsonc_pack(&responseJ, "{ss ss ss ss ss}", "home", globals->homeUrl,
                       "login", globals->loginUrl, "federate",
                       globals->fedlinkUrl, "register", globals->registerUrl,
                       "error", globals->errorUrl);
    if (rc >= 0)
        rc = makeJSONData(&reply, responseJ);
    if (rc < 0)
        return replyOOM(wreq);

    // send the reply
    afb_req_reply(wreq, 0, 1, &reply);
}

/************************************************************************
 * DECLARATION OF THE API
 */
// Static verbs
static afb_verb_t idsvcVerbs[] = {
    // clang-format off
    {
     .verb = "ping",
     .callback = idsvcPing,
     .info = "ping test"
    }, {
     .verb = "url-query-conf",
     .callback = urlQuery,
     .info = "wreq wellknown url list/tag"
    }, {
     .verb = "idp-query-conf",
     .callback = idpQueryConf,
     .info = "wreq idp list/scope for a given LOA level"
    }, {
     .verb = "idp-query-user",
     .callback = idpQueryUser,
     .info = "return pseudo/email idps list before linking user multiple IDPs"
    }, {
     .verb = "session-get",
     .callback = sessionGet,
     .info = "retrieve current client session [profile, user, social]"
    }, {
     .verb = "session-event",
     .callback = subscribeEvent,
     .info = "subscribe to sgate private client session events"
    }, {
     .verb = "session-reset",
     .callback = sessionReset,
     .info = "reset current session [set loa=0]"
    }, {
     .verb = "usr-register",
     .callback = userRegister,
     .info = "register federated user profile into local fedid store"
    }, {
     .verb = "usr-check",
     .callback = userCheckAttr,
     .info = "check user attribute within local store"
    }, {
     .verb = "usr-federate",
     .callback = userFederate,
     .info = "request federating current user with an other existing IDP"
    },
    {NULL} // terminator
    // clang-format on
};

#define IDSVC_INFO "internal oidc idp api"

int idsvcDeclareApi(struct afb_api_v4 **api,
                    const char *apiname,
                    const oidcCoreHdlT *oidc,
                    struct afb_apiset *declare_set,
                    struct afb_apiset *call_set)
{
    int rc;
    struct afb_apiset *public_set;
    char apiwsname[EXT_URL_MAX_LEN];

    // register fedid type
    rc = fedUserObjTypesRegister();
    if (rc) {
        EXT_ERROR("[oidc-idsvc] unable to register fedid types");
        return -1;
    }
    // get the public API set
    public_set = afb_apiset_subset_find(declare_set, "public");
    if (public_set == NULL)
        public_set = declare_set;

    // create the API
    rc = afb_api_v4_create(api, public_set, call_set, apiname, Afb_String_Const,
                           IDSVC_INFO, Afb_String_Const,
                           0,                      // noconcurrency unset
                           NULL, NULL,             // pre-initcb + ctx
                           NULL, Afb_String_Const  // no binding.so path
    );
    if (rc == 0)
        rc = afb_api_v4_set_verbs_hookable(*api, idsvcVerbs);
    if (rc) {
        EXT_CRITICAL("[oidc-idsvc] creation of api %s failed", apiname);
        return -1;
    }
    afb_api_v4_set_userdata(*api, (void *)oidc);

    // export (if possible) the api internally
    snprintf(apiwsname, sizeof(apiwsname), "unix:@%s", apiname);
    rc = afb_api_ws_add_server(apiwsname, public_set, call_set);
    if (rc < 0)
        EXT_WARNING("[oidc-idsvc] publishing api %s failed", apiwsname);

    return 0;
}
