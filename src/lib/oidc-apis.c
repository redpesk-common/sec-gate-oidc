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

#include "oidc-apis.h"

#include <rp-utils/rp-jsonc.h>

#include <libafb/afb-core.h>
#include <libafb/apis/afb-api-ws.h>

#include "oidc-session.h"

// process a filtered request
static void apisCheckReq(void *closure, struct afb_req_common *req)
{
    oidcApisT *api = (oidcApisT *)closure;
    oidcSessionT *session = oidcSessionOfAfbSession(req->session);

    // is authorized?
    if (session != NULL && oidcSessionIsValid(session) &&
        oidcSessionGetActualLOA(session) >= api->loa) {
        // yes, record session activity
        oidcSessionAutoValidate(session);
        // forward request to the backend "protected" api
        afb_req_common_process(afb_req_common_addref(req), api->apiset);
    }
    else {
        // no, forbiden
        afb_req_common_reply_hookable(req, AFB_ERRNO_FORBIDDEN, 0, NULL);
    }
}

static struct afb_api_itf api_frontend_itf = {.process = apisCheckReq};

// import API client from uri and map corresponding roles into apis hashtable
int apisRegister(const oidcCoreHdlT *oidc,
                 oidcApisT *api,
                 struct afb_apiset *declare_set,
                 struct afb_apiset *call_set)
{
    int err, index;
    struct afb_api_item api_item;
    struct afb_apiset *public_set;

    // if API is not runnning within the binder register client API
    if (api->uri[0] != '@') {
        // get the public API set
        public_set = afb_apiset_subset_find(declare_set, "public");
        if (public_set != NULL && declare_set != public_set) {
            if (api->loa == 0)
                declare_set = public_set;
            else {
                // expose a public filtered api
                api_item.itf = &api_frontend_itf;
                api_item.group = NULL;
                api_item.closure = api;
                // use the same api name for the public part
                err = afb_apiset_add(public_set, api->uid, api_item);
                if (err)
                    goto OnErrorExit;
                // record the declare set
                api->apiset = declare_set;
            }
        }
        // add the client api
        err =
            afb_api_ws_add_client(api->uri, declare_set, call_set, !api->lazy);
        if (err)
            goto OnErrorExit;
    }
    // Extract API from URI
    for (index = (int)strlen(api->uri) - 1; index > 0; index--) {
        if (api->uri[index] == '@' || api->uri[index] == '/')
            break;
    }

    // If needed create an alias
    if (index) {
        if (strcasecmp(&api->uri[index + 1], api->uid)) {
            err = afb_apiset_add_alias(declare_set, &api->uri[index + 1],
                                       api->uid);
            if (err)
                goto OnErrorExit;
        }
    }

    return 0;

OnErrorExit:
    EXT_ERROR("[oidc-apis] failed to create API %s, uri=%s ", api->uid,
              api->uri);
    return -1;
}

// parse one API configuration
static int apisParseOne(const oidcCoreHdlT *oidc,
                        json_object *apiJ,
                        oidcApisT *api)
{
    int rc, idx, count;
    const char **roles;
    json_object *requireJ = NULL;

    api->oidc = oidc;

    // scan object values
    rc = rp_jsonc_unpack(apiJ, "{ss,s?s,s?s,s?i,s?i,s?o}", "uid", &api->uid,
                         "info", &api->info, "uri", &api->uri, "loa", &api->loa,
                         "lazy", &api->lazy, "require", &requireJ);
    if (rc) {
        EXT_CRITICAL("[oidc-apis] bad API conf: %s",
                     json_object_to_json_string(apiJ));
        return -1;
    }
    // provide some defaults value based on uid
    if (!api->uri) {
        rc = asprintf((char **)&api->uri, "unix:@%s", api->uid);
        if (rc < 0)
            goto oom;
    }

    // inspect require values, building roles array
    if (requireJ) {
        switch (json_object_get_type(requireJ)) {
        case json_type_array:
            count = (int)json_object_array_length(requireJ);
            roles = calloc(count + 1, sizeof(char *));
            if (roles == NULL)
                goto oom;

            for (idx = 0; idx < count; idx++) {
                json_object *roleJ = json_object_array_get_idx(requireJ, idx);
                roles[idx] = json_object_get_string(roleJ);
            }
            break;

        case json_type_string:
            roles = calloc(2, sizeof(char *));
            if (roles == NULL)
                goto oom;
            roles[0] = json_object_get_string(requireJ);
            break;

        default:
            EXT_CRITICAL("[oidc-apis] bad 'require' value %s",
                         json_object_to_json_string(requireJ));
            return -1;
        }
        api->roles = roles;
    }
    return 0;

oom:
    EXT_CRITICAL("[oidc-apis] out of memory");
    return -1;
}

// parse API configuration object
oidcApisT *apisParseConfig(const oidcCoreHdlT *oidc, json_object *apisJ)
{
    oidcApisT *apis = NULL;
    int rc = 0, count, idx;

    switch (json_object_get_type(apisJ)) {
    case json_type_array:
        count = (int)json_object_array_length(apisJ);
        apis = calloc(count + 1, sizeof(oidcApisT));
        if (apis != NULL) {
            for (idx = 0; rc == 0 && idx < count; idx++) {
                json_object *apiJ = json_object_array_get_idx(apisJ, idx);
                rc = apisParseOne(oidc, apiJ, &apis[idx]);
            }
        }
        break;

    case json_type_object:
        apis = calloc(2, sizeof(oidcApisT));
        if (apis != NULL)
            rc = apisParseOne(oidc, apisJ, &apis[0]);
        break;

    default:
        rc = -1;
        break;
    }
    if (apis == NULL) {
        if (rc < 0)
            EXT_CRITICAL("[oidc-apis] bad APIs conf: %s",
                         json_object_to_json_string(apisJ));
        else
            EXT_CRITICAL("[oidc-apis] out of memory");
    }
    else if (rc < 0) {
        free(apis);  // TODO: also free the roles
        apis = NULL;
    }
    return apis;
}
