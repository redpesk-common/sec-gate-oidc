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

#include <locale.h>
#include <microhttpd.h>
#include <string.h>
#include <time.h>

#include <rp-utils/rp-escape.h>
#include <rp-utils/rp-jsonc.h>

#include <libafb/afb-core.h>
#include <libafb/afb-http.h>
#include <libafb/afb-v4.h>

#include "oidc-alias.h"
#include "oidc-core.h"
#include "oidc-login.h"
#include "oidc-session.h"

// dummy unique value for session key

// check if one of requested role exist within social cookie
// return 0 if that is the case
// return 1 if none matches
static int aliasCheckAttrs(oidcSessionT *session, oidcAliasT *alias)
{
    oidcStateT *state;
    const char **roles = alias->roles;

    if (roles == NULL)
        return 1;

    state = oidcSessionGetActualState(session);
    if (state == NULL)
        return 0;

    while (*roles) {
        if (oidcStateHasAttribute(state, *roles))
            return 1;
        roles++;
    }
    return 0;
}

// create aliasFrom cookie and redirect to common login page
static int aliasRedirectLogin(struct afb_hreq *hreq,
                              oidcAliasT *alias,
                              oidcSessionT *session)
{
    oidcSessionReset(session);
    oidcSessionSetTargetPage(session, alias);
    return oidcCoreRedirectLogin(alias->oidc, hreq);
}

/**
 * check that the client has the required LOA
 */
static int aliasCheckReq(struct afb_hreq *hreq, void *ctx)
{
    oidcAliasT *alias = (oidcAliasT *)ctx;
    oidcSessionT *session;

    // get session of the request
    session = oidcSessionOfHttpReq(hreq);
    if (session == NULL) {
        EXT_NOTICE("[oidc-alias] can't bind to session");
        afb_hreq_reply_error(hreq, EXT_HTTP_CONFLICT);
        return 1;
    }
    // Check required LOA
    if (!oidcSessionIsValid(session) ||
        oidcSessionGetActualLOA(session) < alias->loa) {
        EXT_INFO("[oidc-alias] Redirecting valid %s, loa %d for %d",
                 oidcSessionIsValid(session) ? "yes" : "no",
                 oidcSessionGetActualLOA(session), alias->loa);

        // push event to notify the access denied
        oidcSessionEventPush(session, "{ss ss ss si si}", "status",
                             "loa-mismatch", "uid", alias->uid, "url",
                             alias->url, "loa-target", alias->loa,
                             "loa-session", oidcSessionGetActualLOA(session));

        return aliasRedirectLogin(hreq, alias, session);
    }
    // if tCache not expired use jump authent check
    if (oidcSessionShouldCheck(session)) {
        // check roles
        if (!aliasCheckAttrs(session, alias))
            return aliasRedirectLogin(hreq, alias, session);
        // store a timestamp to cache authentication validation
        oidcSessionSetNextCheck(session, alias->tCache);
    }
    oidcSessionAutoValidate(session);
    return 0;  // move forward and continue parsing lower priority aliases
}

/**
 * Register one alias, described by 'alias', to the HTTP server 'hsrv'
 */
int aliasRegisterOne(const oidcAliasT *alias, struct afb_hsrv *hsrv)
{
    const char *rootdir;
    int rc;

    // if alias full path does not start with '/' then prefix it with
    // http_root_dir
    if (alias->path[0] == '/')
        rootdir = "";
    else
        rootdir = afb_common_rootdir_get_path();

    // insert LOA checking if required
    if (alias->loa > 0) {
        rc = afb_hsrv_add_handler(hsrv, alias->url, aliasCheckReq,
                                  (void *)alias, alias->priority);
        if (rc == 0) {
            EXT_ERROR("[oidc-alias] failed to add alias %s handler %s",
                      alias->uid, alias->url);
            return -1;
        }
    }
    // add with lower priority the redirection
    rc = afb_hsrv_add_alias_path(hsrv, alias->url, rootdir, alias->path,
                                 alias->priority - 1, 0 /*not relax */);
    if (rc == 0) {
        EXT_ERROR("[oidc-alias] failed to add alias %s from %s to %s/%s",
                  alias->uid, alias->url, rootdir, alias->path);
        return -1;
    }

    EXT_DEBUG("[oidc-alias] register uid=%s loa=%d url='%s' fullpath='%s/%s'",
              alias->uid, alias->loa, alias->url, rootdir, alias->path);
    return 0;
}

/**
 * extract from aliasJ the struct oidcAliasT
 * alias recording the alias
 *
 * @param oidc the main structure
 * @param aliasJ the json object configuration
 * @param alias the struct to fill
 *
 * @return 0 on success or else not zero for error
 */
static int parseOneAlias(const oidcCoreHdlT *oidc,
                         json_object *aliasJ,
                         oidcAliasT *alias)
{
    const char **roles;
    int rc, count;
    json_object *requireJ = NULL;

    // set tCache default
    alias->oidc = oidc;
    alias->tCache = oidcCoreGlobals(oidc)->tCache;

    rc = rp_jsonc_unpack(aliasJ, "{ss,s?s,s?s,s?s,s?i,s?i,s?o}", "uid",
                         &alias->uid, "info", &alias->info, "url", &alias->url,
                         "path", &alias->path, "prio", &alias->priority, "loa",
                         &alias->loa, "require", &requireJ);
    if (rc) {
        EXT_CRITICAL("[oidc-alias] bad alias conf: %s",
                     json_object_to_json_string(aliasJ));
        return -1;
    }
    // provide some defaults value based on uid
    if (!alias->url) {
        rc = asprintf((char **)&alias->url, "/%s", alias->uid);
        if (rc < 0)
            goto oom;
    }
    if (!alias->path) {
        rc = asprintf((char **)&alias->path, "$ROOTDIR/%s", alias->uid);
        if (rc < 0)
            goto oom;
    }

    // handle required roles
    if (requireJ) {
        switch (json_object_get_type(requireJ)) {
        case json_type_array:
            count = (int)json_object_array_length(requireJ);
            roles = calloc(count + 1, sizeof(char *));
            if (roles == NULL)
                goto oom;

            for (int idx = 0; idx < count; idx++) {
                json_object *roleJ = json_object_array_get_idx(requireJ, idx);
                roles[idx] = json_object_get_string(roleJ);
            }
            break;

        case json_type_object:
            roles = calloc(2, sizeof(char *));
            if (roles == NULL)
                goto oom;

            roles[0] = json_object_get_string(requireJ);
            break;

        default:
            EXT_CRITICAL("[oidc-alias] bad require conf: %s",
                         json_object_to_json_string(requireJ));
            return -1;
        }
        alias->roles = roles;
    }
    return 0;

oom:
    EXT_CRITICAL("[oidc-alias] out of memory");
    return -1;
}

/**
 * extract from aliasesJ the array of structs oidcAliasT
 * recording aliases
 *
 * @param oidc the main structure
 * @param aliasesJ the json object configuration
 *
 * @return NULL on error or the array of aliases
 */
oidcAliasT *aliasParseConfig(const oidcCoreHdlT *oidc, json_object *aliasesJ)
{
    oidcAliasT *aliases = NULL;
    int rc = 0, count, idx;

    switch (json_object_get_type(aliasesJ)) {
    case json_type_array:
        /* extract array of aliases */
        count = (int)json_object_array_length(aliasesJ);
        aliases = calloc(count + 1, sizeof(oidcAliasT));
        if (aliases != NULL) {
            for (idx = 0; rc >= 0 && idx < count; idx++) {
                json_object *aliasJ = json_object_array_get_idx(aliasesJ, idx);
                rc = parseOneAlias(oidc, aliasJ, &aliases[idx]);
            }
        }
        break;

    case json_type_object:
        /* extract single alias */
        aliases = calloc(2, sizeof(oidcAliasT));
        if (aliases != NULL)
            rc = parseOneAlias(oidc, aliasesJ, &aliases[0]);
        break;

    default:
        rc = -1;
        break;
    }
    if (aliases == NULL) {
        if (rc == 0)
            EXT_CRITICAL("[oidc-alias] out of memory");
        else
            EXT_CRITICAL("[oidc-alias] bad aliases conf: %s",
                         json_object_to_json_string(aliasesJ));
    }
    else if (rc < 0) {
        free(aliases);
        aliases = NULL;
    }
    return aliases;
}
