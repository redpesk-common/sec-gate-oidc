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

#include <assert.h>
#include <stdio.h>

#include <rp-utils/rp-jsonc.h>

#include <libafb/afb-core.h>
#include <libafb/afb-v4.h>
#include <libafb/apis/afb-api-ws.h>

#include "oidc-alias.h"
#include "oidc-apis.h"
#include "oidc-core.h"
#include "oidc-defaults.h"
#include "oidc-session.h"

static void on_protected_api_request(void *closure, struct afb_req_common *req)
{
    oidcApisT *api = (oidcApisT *)closure;
    int session_loa = oidcSessionGetLOA(req->session);

    if (session_loa < api->loa) {
        // insufficient LOA
        afb_req_common_reply_hookable(req, AFB_ERRNO_FORBIDDEN, 0, NULL);
    }
    else {
        // forward request to the backend "protected" api
        afb_req_common_process(afb_req_common_addref(req), api->apiset);
    }
}

static struct afb_api_itf api_frontend_itf = {.process =
                                                  on_protected_api_request};

// import API client from uri and map corresponding roles into apis hashtable
int apisRegisterOne(oidcCoreHdlT *oidc,
                    oidcApisT *api,
                    afb_apiset *declare_set,
                    afb_apiset *call_set)
{
    int err, index;
    struct afb_api_item api_item;
    afb_apiset *public_set =
        afb_apiset_subset_find(declare_set, "public") ?: declare_set;

    // if API is not runnning within the binder register client API
    if (api->uri[0] != '@') {
        // get the public set
        public_set =
            afb_apiset_subset_find(declare_set, "public") ?: declare_set;
        if (api->loa == 0 || declare_set == public_set) {
            // the api is obviously public
            err = afb_api_ws_add_client(api->uri, public_set, call_set,
                                        !api->lazy);
        }
        else {
            // add a (private) client to the protected api
            api->apiset = declare_set;
            err = afb_api_ws_add_client(api->uri, declare_set, call_set,
                                        !api->lazy);
            if (err)
                goto OnErrorExit;
            // expose a public filtered api
            api_item.itf = &api_frontend_itf;
            api_item.group = NULL;
            api_item.closure = api;
            // reuse the same api name for the public part
            err = afb_apiset_add(public_set, api->uid, api_item);
        }
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
            err = afb_api_v4_add_alias_hookable(oidc->apiv4,
                                                &api->uri[index + 1], api->uid);
            if (err)
                goto OnErrorExit;
        }
    }

    return 0;

OnErrorExit:
    EXT_ERROR(
        "[oidc-api-not-found] ext=%s fail to connect to api=%s uri=%s "
        "(apisRegisterOne)",
        oidc->uid, api->uid, api->uri);
    return 1;
}

static int apisParseOne(oidcCoreHdlT *oidc, json_object *apiJ, oidcApisT *api)
{
    json_object *requirerJ = NULL;

    int err =
        rp_jsonc_unpack(apiJ, "{ss,s?s,s?s,s?i,s?i,s?o}", "uid", &api->uid,
                        "info", &api->info, "uri", &api->uri, "loa", &api->loa,
                        "lazy", &api->lazy, "require", &requirerJ);
    if (err) {
        EXT_CRITICAL(
            "[idp-api-error] idpmake=%s parsing fail profile expect: "
            "uid,uri,loa,role (apisParseOne)",
            oidc->uid);
        goto OnErrorExit;
    }
    // provide some defaults value based on uid
    if (!api->uri)
        asprintf((char **)&api->uri, "unix:@%s", api->uid);

    if (requirerJ) {
        const char **roles;
        switch (json_object_get_type(requirerJ)) {
            int count;

        case json_type_array:
            count = (int)json_object_array_length(requirerJ);
            roles = calloc(count + 1, sizeof(char *));

            for (int idx = 0; idx < count; idx++) {
                json_object *roleJ = json_object_array_get_idx(requirerJ, idx);
                roles[idx] = json_object_get_string(roleJ);
            }
            break;

        case json_type_string:
            roles = calloc(2, sizeof(char *));
            roles[0] = json_object_get_string(requirerJ);
            break;

        default:
            EXT_CRITICAL(
                "[idp-apis-error] idp=%s role should be json_array|json_string "
                "(apisParseOne)",
                oidc->uid);
            goto OnErrorExit;
        }
        api->roles = roles;
        api->oidc = oidc;
    }
    return 0;

OnErrorExit:
    return 1;
}

oidcApisT *apisParseConfig(oidcCoreHdlT *oidc, json_object *apisJ)
{
    oidcApisT *apis;
    int err;

    switch (json_object_get_type(apisJ)) {
        int count;

    case json_type_array:
        count = (int)json_object_array_length(apisJ);
        apis = calloc(count + 1, sizeof(oidcApisT));

        for (int idx = 0; idx < count; idx++) {
            json_object *apiJ = json_object_array_get_idx(apisJ, idx);
            err = apisParseOne(oidc, apiJ, &apis[idx]);
            if (err)
                goto OnErrorExit;
        }
        break;

    case json_type_object:
        apis = calloc(2, sizeof(oidcApisT));
        err = apisParseOne(oidc, apisJ, &apis[0]);
        if (err)
            goto OnErrorExit;
        break;

    default:
        EXT_CRITICAL(
            "[idp-apis-error] idp=%s apis should be json_array|json_object "
            "(apisParseConfig)",
            oidc->uid);
        goto OnErrorExit;
    }
    return apis;

OnErrorExit:
    return NULL;
}
