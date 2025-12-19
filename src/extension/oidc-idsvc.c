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

#include <libafb/afb-apis.h>
#include <libafb/afb-core.h>
#include <libafb/afb-http.h>
#include <libafb/afb-v4.h>

#include <fedid-types-glue.h>

#include "oidc-alias.h"
#include "oidc-apis.h"
#include "oidc-core.h"
#include "oidc-fedid.h"
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
    return afb_create_data_raw(data, AFB_PREDEFINED_TYPE_STRINGZ,
                        string, string == NULL ? 0 : 1 + strlen(string),
                        destroy ? free : NULL, destroy ? (void*)string : NULL);
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
 * If a negative status is returned, it indecates an error.
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
    afb_req_subcall(wreq, API_OIDC_USR_SVC, "user-check", argc, argv,
                    afb_req_subcall_on_behalf, userCheckAttrCB, NULL);
}

/************************************************************************
 */

static json_object *idpQueryList(afb_req_t wreq, const char **idps)
{
    json_object *responseJ, *idpsJ, *aliasJ;
    int err;

    // retrieve OIDC global context from API handle
    oidcCoreHdlT *oidc = afb_api_get_userdata(afb_req_get_api(wreq));

    // retrieve oidc config from current alias cookie
    const oidcAliasT *alias;
    oidcSessionT *session = oidcSessionOfReq(wreq);
    alias = oidcSessionGetAlias(session);

    // build IDP list with corresponding scope for requested LOA
    idpsJ = oidcCoreGetProfilsForLOA(oidc, 0, idps, 1);
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
    const fedidLinkT *fedlink;
    json_object *queryJ;
    afb_data_t query, reply;

    // get current social data for further account linking
    oidcSessionT *session = oidcSessionOfReq(wreq);
    fedlink = oidcSessionGetFedIdLink(session);

    // if not a slave IDP then use email/pseudo to get IDP list
    if (fedlink) {
        rp_jsonc_pack(&queryJ, "{ss ss}", "email", fedlink->email, "pseudo",
                      fedlink->pseudo);
        afb_create_data_raw(&query, AFB_PREDEFINED_TYPE_JSON_C, queryJ, 0,
                            (void *)json_object_put, queryJ);
        afb_req_subcall(wreq, API_OIDC_USR_SVC, "social-idps", 1, &query,
                        afb_req_subcall_on_behalf, idpQueryUserCB, NULL);
        oidcSessionDropFedIdLink(session);
    }
    else {
        // if no idps list provided build one from config
        const char *idps[MAX_OIDC_IDPS + 1];
        const oidcProfileT *profile = oidcSessionGetIdpProfile(session);
        int count = oidcCoreGetFilteredIdpList(
            profile->idp->oidc, idps, MAX_OIDC_IDPS + 1, profile->idp->uid);
        if (count > MAX_OIDC_IDPS) {
            EXT_ERROR(
                "[idp-federate-list] too many idps in config "
                "MAX_OIDC_IDPS=%d (remaining ignored)",
                MAX_OIDC_IDPS);
            count = MAX_OIDC_IDPS;
        }
        idps[count] = NULL;

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
    const oidcProfileT *profile;
    const oidcAliasT *alias;
    json_object *aliasJ;
    oidcSessionT *session = oidcSessionOfReq(wreq);

    // return creation status to HTML5
    if (status < 0)
        goto OnErrorExit;

    // return destination alias
    profile = oidcSessionGetIdpProfile(session);
    oidcSessionSetLOA(session, profile->loa);
    alias = oidcSessionGetAlias(session);
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
    oidcSessionT *session = oidcSessionOfReq(wreq);
    profile = oidcSessionGetIdpProfile(session);
    if (!profile)
        goto OnErrorExit2;

    // retrieve fedsocial from session
    fedSocial = oidcSessionGetFedSocial(session);
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
    afb_data_t reply[1];
    const oidcProfileT *profile;
    oidcAliasT *alias;
    json_object *responseJ;
    oidcSessionT *session;
    int err;

    // subcall failed
    if (status < 0) {
        afb_req_reply(wreq, status, 0, NULL);
        return;
    }
    // user isn't recorded
    if (status == 0) {
        EXT_INFO("user not recorded, pseudo=%s, email=%s", fedUser->pseudo,
                 fedUser->email);
        afb_req_reply(wreq, AFB_USER_ERRNO(0), 0, NULL);
        return;
    }
    // get used IDP profile to access oidc wellknown urls
    session = oidcSessionOfReq(wreq);
    profile = oidcSessionGetIdpProfile(session);
    if (!profile) {
        EXT_INFO("no recorded IDP");
        afb_req_reply(wreq, AFB_USER_ERRNO(1), 0, NULL);
        return;
    }
    // copy current user social and registration data for further federation
    // request
    oidcSessionSetFedIdLink(session, fedUser->pseudo, fedUser->email);

    // force federation mode within fedidCheckCB
    oidcSessionSetFedIdLinkRequest(session, FEDID_LINK_REQUESTED);
    err = rp_jsonc_pack(&responseJ, "{ss}", "target",
                        oidcCoreGlobals(profile->idp->oidc)->fedlinkUrl);
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
    oidcSessionT *session = oidcSessionOfReq(wreq);
    const oidcProfileT *profile;
    afb_data_t reply;

    profile = oidcSessionGetIdpProfile(session);
    if (!profile)
        goto OnErrorExit;

    fedidsessionReset(session, profile);

    const oidGlobalsT *globals = oidcCoreGlobals(profile->idp->oidc);
    rp_jsonc_pack(&responseJ, "{ss ss* ss*}", "home", globals->homeUrl ?: "/",
                  "login", globals->loginUrl, "error", globals->errorUrl);
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
    const fedUserRawT *fedUser;
    const fedSocialRawT *fedSocial;
    json_object *profileJ;

    // retrieve current wreq LOA from session (to be fixed by Jose)
    oidcSessionT *session = oidcSessionOfReq(wreq);
    profile = oidcSessionGetIdpProfile(session);
    if (!profile)
        goto OnErrorExit;

    rp_jsonc_pack(&profileJ, "{ss ss si}", "uid", profile->uid, "scope",
                  profile->scope, "loa", profile->loa);

    fedUser = oidcSessionGetUser(session);
    fedSocial = oidcSessionGetFedSocial(session);
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

    err = oidcSessionEventSubscribe(wreq);
    if (err < 0)
        goto OnErrorExit;

    oidcSessionT *session = oidcSessionOfReq(wreq);
    EXT_DEBUG("[session-evt-sub] client subscribed session uuid=%s",
              oidcSessionUUID(session));

    asprintf(&response, "session-uuid=%s", oidcSessionUUID(session));
    afb_create_data_raw(&reply, AFB_PREDEFINED_TYPE_STRINGZ, response,
                        strlen(response) + 1, free, NULL);
    afb_req_reply(wreq, 0, 1, &reply);

    return;

OnErrorExit:
    afb_create_data_raw(&reply, AFB_PREDEFINED_TYPE_STRINGZ, errorMsg,
                        strlen(errorMsg) + 1, NULL, NULL);
    afb_req_reply(wreq, -1, 1, &reply);
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
    const oidcAliasT *alias;

    // retrieve OIDC global context from API handle
    oidcCoreHdlT *oidc = afb_api_get_userdata(afb_req_get_api(wreq));

    // retrieve current wreq LOA from session (to be fixed by Jose)
    oidcSessionT *session = oidcSessionOfReq(wreq);
    alias = oidcSessionGetAlias(session);

    // build IDP list with corresponding scope for requested LOA
    if (alias) {
        idpsJ = oidcCoreGetProfilsForLOA(oidc, alias->loa, NULL, 0);
        rp_jsonc_pack(&aliasJ, "{ss ss* ss si}", "uid", alias->uid, "info",
                      alias->info, "url", alias->url, "loa", alias->loa);
    }
    else {
        idpsJ = oidcCoreGetProfilsForLOA(oidc, 0, NULL, 0);
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

    const oidGlobalsT *globals = oidcCoreGlobals(oidc);
    err = rp_jsonc_pack(&responseJ, "{ss ss ss ss ss}", "home",
                        globals->homeUrl, "login", globals->loginUrl,
                        "federate", globals->fedlinkUrl, "register",
                        globals->registerUrl, "error", globals->errorUrl);
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
    // clang-format off
    /* VERB'S NAME         FUNCTION TO CALL         SHORT DESCRIPTION */
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
    },
    {
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
    {NULL}                      // terminator
    // clang-format on
};

#define IDSVC_INFO "internal oidc idp api"

int idsvcDeclareApi(afb_api_v4 **api,
                    const char *apiname,
                    const oidcCoreHdlT *oidc,
                    afb_apiset *declare_set,
                    afb_apiset *call_set)
{
    int rc;
    afb_apiset *public_set;
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
