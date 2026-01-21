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
 *
 *  References:
 *      https://onelogin.com
 *      https://www.phantauth.net/
 *      https://benmcollins.github.io/libjwt/group__jwt__header.html#ga308c00b85ab5ebfa76b1d2485a494104
 */

#define _GNU_SOURCE

#include <assert.h>
#include <locale.h>
#include <string.h>
#include <uthash.h>

#include <rp-utils/rp-base64.h>
#include <rp-utils/rp-enum-map.h>
#include <rp-utils/rp-escape.h>
#include <rp-utils/rp-jsonc.h>

#include <libafb/afb-core.h>
#include <libafb/afb-http.h>
#include <libafb/afb-v4.h>

#include "curl-glue.h"
#include "idp-oidc.h"
#include "oidc-core.h"
#include "oidc-fedid.h"
#include "oidc-idp.h"
#include "oidc-session.h"

#define IDP_CLIENT_SECRET_DEFAULT IDP_CLIENT_SECRET_POST
// #define IDP_RESPOND_TYPE_DEFAULT IDP_RESPOND_TYPE_CODE
#define IDP_RESPOND_TYPE_DEFAULT IDP_RESPOND_TYPE_CODE

typedef struct
{
    const char *fedid;
    const char *pseudo;
    const char *avatar;
    const char *name;
    const char *company;
    const char *email;
    const char *attrs;
    const char *idpsid;
    char *auth64;
    json_object *jwksJ;
} oidcSchemaT;

// import idp authentication enum/label
extern const rp_enum_map_t idpAuthMethods[];
extern const rp_enum_map_t idpRespondTypes[];

// idp session id hash table map sid with uuid
typedef struct
{
    const char *uuid;
    const char *sid;
    UT_hash_handle hh;
} sidMapT;
static sidMapT *sidHead = NULL;

// make code easier to read
enum { TKN_HEADER = 0, TKN_BODY = 1, TKN_SIGN = 2, TKN_SIZE = 3 } tokenPart;
#define ENCODED_URL 1

static const oidcProfileT dfltProfiles[] = {
    {.loa = 1, .scope = "openid,profile"},
    {NULL}  // terminator
};

static const oidcSchemaT dfltSchema = {
    .fedid = "sub",
    .pseudo = "preferred_username",
    .name = "name",
    .email = "email",
    .avatar = "picture",
    .company = "company",
    .idpsid = "sid",
    .attrs = NULL,
};

static const oidcWellknownT dfltWellknown = {
    .authMethod = IDP_CLIENT_SECRET_DEFAULT,
    .respondType = IDP_RESPOND_TYPE_UNKNOWN,
    .errorLabel = "error_description",
};

static const httpKeyValT dfltHeaders[] = {
    {.tag = "Content-type", .value = "application/x-www-form-urlencoded"},
    {.tag = "Accept", .value = "application/json"},
    {NULL}  // terminator
};

static httpOptsT dfltOpts = {
    .agent = HTTP_DFLT_AGENT,
    .follow = 1,
    .timeout = 10,  // default authentication timeout
    // .verbose=1
};

static const oidcStaticsT dfltstatics = {
    .aliasLogin = "/sgate/oidc/login",
    .aliasLogo = "/sgate/oidc/logo-64px.png",
    .aliasLogout = NULL,
    .sTimeout = 600};

// string key value if exist
static const char *get_object_string(json_object *objJ, const char *key)
{
    json_object *valJ;
    if (!json_object_object_get_ex(objJ, key, &valJ) || valJ == NULL)
        return NULL;
    return json_object_get_string(valJ);
}

// duplicate key value if not null
static char *get_object_string_dup(json_object *objJ, const char *key)
{
    const char *str = get_object_string(objJ, key);
    return str == NULL ? NULL : strdup(str);
}

// signature to be check with GNUTLS to be added by JOSE)
// reference https://jwt.io/ https://datatracker.ietf.org/doc/html/rfc7517
static json_object *oidcJwtCheck(const oidcSchemaT *schema, char *token[])
{
    int err;
    const char *keyId, *keyAlg;
    const char *kty, *kid, *use;
    const unsigned char *nkey, *esign;
    json_object *headerJ, *jwkJ = NULL;

    headerJ = json_tokener_parse(token[TKN_HEADER]);
    if (!headerJ)
        goto OnErrorExit;

    err = rp_jsonc_unpack(headerJ, "{ss ss}", "kid", &keyId, "alg", &keyAlg);
    if (err)
        goto OnErrorExit;

    // for for kid withing jwks
    for (int idx = 0; idx < json_object_array_length(schema->jwksJ); idx++) {
        json_object *slotJ;
        slotJ = json_object_array_get_idx(schema->jwksJ, idx);
        err = rp_jsonc_unpack(slotJ, "{ss ss ss ss ss !}", "kty", &kty, "kid",
                              &kid, "use", &use, "n", &nkey, "e", &esign);
        if (err)
            goto OnErrorExit;
        if (!strcasecmp(kid, keyId)) {
            jwkJ = slotJ;
            break;
        }
    }
    if (!jwkJ)
        goto OnErrorExit;

    // JOSE to implement signature check use="sign" nkey="idp key" esign="jwt
    // signature"

OnErrorExit:
    EXT_CRITICAL(
        "[token-sign-invalid] fail to check tokenId signature (oidcJwtCheck)");
    return NULL;
}

static int oidcUserFederateId(oidcStateT *state, json_object *profileJ)
{
    const oidcIdpT *idp = oidcStateGetIdp(state);
    oidcSchemaT *schema = (oidcSchemaT *)idp->userData;
    fedSocialRawT *fedSocial = oidcStateGetSocial(state);
    fedUserRawT *fedUser = oidcStateGetUser(state);
    json_object *attrsJ;

    // no profile just ignore
    if (!profileJ)
        return -1;

    // build social fedkey from idp->uid+oidc->id
    fedSocial->fedkey = get_object_string_dup(profileJ, schema->fedid);

    // check groups as security attributs
    if (schema->attrs) {
        json_object_object_get_ex(profileJ, schema->attrs, &attrsJ);
        EXT_DEBUG("fedid= %s ***\n", json_object_get_string(profileJ));
        if (json_object_is_type(attrsJ, json_type_array)) {
            size_t count = json_object_array_length(attrsJ);
            fedSocial->attrs = calloc(count + 1, sizeof(char *));
            for (int idx = 0; idx < count; idx++) {
                json_object *attrJ = json_object_array_get_idx(attrsJ, idx);
                fedSocial->attrs[idx] = strdup(json_object_get_string(attrJ));
            }
        }
    }

    fedUser->pseudo = get_object_string(profileJ, schema->pseudo);
    fedUser->email = get_object_string(profileJ, schema->email);
    fedUser->name = get_object_string(profileJ, schema->name);
    fedUser->avatar = get_object_string(profileJ, schema->avatar);
    fedUser->company = get_object_string(profileJ, schema->company);

    fedidCheck(state);
    return 0;
}

// call when IDP respond to user profile wreq
// reference:
// https://docs.oidc.com/en/rest/reference/users#get-the-authenticated-user
static httpRqtActionT oidcUserGetByTokenCB(const httpRqtT *httpRqt)
{
    oidcStateT *state = (oidcStateT *)httpRqt->userData;
    int err;

    // something when wrong
    if (httpRqt->status != 200) {
        EXT_ERROR("[idp-oidc] HTTP request failed %d: %.*s", httpRqt->status,
                (int)httpRqt->body.length, httpRqt->body.buffer);
        goto OnErrorExit;
    }

    // unwrap user profile
    json_object *profileJ = json_tokener_parse(httpRqt->body.buffer);
    if (!profileJ) {
        EXT_ERROR("[idp-oidc] bad HTTP reply %.*s",
                (int)httpRqt->body.length, httpRqt->body.buffer);
        goto OnErrorExit;
    }

    err = oidcUserFederateId(state, profileJ);
    if (err)
        goto OnErrorExit;

    return HTTP_HANDLE_FREE;

OnErrorExit:
    oidcStateUnauthorized(state);
    return HTTP_HANDLE_FREE;
}

// from acces token wreq user profile
// reference
// https://docs.oidc.com/en/developers/apps/authorizing-oauth-apps#web-application-flow
static int oidcUserGetByToken(oidcStateT *state)
{
    const oidcIdpT *idp = oidcStateGetIdp(state);

    httpKeyValT authToken[] = {
        {.tag = "Authorization", .value = oidcStateGetAuthorization(state)},
        {.tag = "grant_type", .value = "authorization_code"},
        {NULL}  // terminator
    };

    // asynchronous wreq to IDP user profile
    // https://docs.oidc.com/en/rest/reference/orgs#list-organizations-for-the-authenticated-user
    EXT_DEBUG("[oidc-profile-get] curl -H 'Authorization: %s' %s\n",
              oidcStateGetAuthorization(state), idp->wellknown->userinfo);
    int err = httpSendGet(oidcCoreHTTPPool(idp->oidc), idp->wellknown->userinfo,
                          &dfltOpts, authToken, oidcUserGetByTokenCB, state);
    if (err)
        goto OnErrorExit;
    return 0;

OnErrorExit:
    return -1;
}

// parse jwt token
// reference
// https://developer.yahoo.com/oauth2/guide/openid_connect/decode_id_token.html?guccounter=1
static json_object *oidcUserGetByJwt(const oidcSchemaT *schema, char *tokenId)
{
    int tknIdx = 0, start = 0, index, rc;
    char *token[TKN_SIZE];
    size_t length[TKN_SIZE];
    json_object *bodyJ;

    // split jwt token "header64"."body64"."sign64"
    for (index = 0; tokenId[index] != '\0'; index++) {
        if (tokenId[index] == '.') {
            if (tknIdx == 3)
                goto OnErrorExit;
            tokenId[index] = '\0';
            length[tknIdx] = (size_t)(index - start);
            token[tknIdx] = &tokenId[start];
            tknIdx++;
            start = index + 1;
        }
    }
    token[tknIdx] = &tokenId[start];
    length[tknIdx] = (size_t)(index - start);

    // uncode64 and open json object
    rc = rp_base64_decode(token[TKN_BODY], length[TKN_BODY],
                          (uint8_t **)&token[TKN_BODY], &length[TKN_BODY],
                          ENCODED_URL);
    if (rc != rp_base64_ok)
        goto OnErrorExit;

    // if no signature directly open token body as a json object
    if (!schema->jwksJ) {
        bodyJ = json_tokener_parse(token[TKN_BODY]);
    }
    else {
        rc = rp_base64_decode(token[TKN_HEADER], length[TKN_HEADER],
                              (uint8_t **)&token[TKN_HEADER],
                              &length[TKN_HEADER], ENCODED_URL);
        // signature is not encoded
        if (rc != rp_base64_ok || !token[TKN_SIGN])
            goto OnErrorExit;
        bodyJ = oidcJwtCheck(schema, token);
    }
    return bodyJ;

OnErrorExit:
    EXT_CRITICAL("[token-id-invalid] fail to parse tokenId (oidcUserGetByJwt)");
    return NULL;
}

// call when oidc return a valid access_token
static httpRqtActionT oidcAccessTokenCB(const httpRqtT *httpRqt)
{
    char *tokenVal, *tokenType, *tokenId = NULL;
    oidcStateT *state = (oidcStateT *)httpRqt->userData;
    const oidcIdpT *idp = oidcStateGetIdp(state);
    const oidcSchemaT *schema = (oidcSchemaT *)idp->userData;
    json_object *responseJ = NULL;
    int err;

    // free old post data

    if (httpRqt->status != 200)
        goto OnErrorExit;

    // we should have a valid token or something when wrong
    responseJ = json_tokener_parse(httpRqt->body.buffer);
    if (!responseJ)
        goto OnErrorExit;

    err = rp_jsonc_unpack(responseJ, "{ss ss s?s}", "access_token", &tokenVal,
                          "token_type", &tokenType, "id_token", &tokenId);
    if (err)
        goto OnErrorExit;
    err = oidcStateSetAuthorization(state, tokenType, tokenVal);
    if (err)
        goto OnErrorExit;

    // if we get a token ID check it otherwise try to query user profile end
    // point
    if (tokenId) {
        json_object *fedIdJ = oidcUserGetByJwt(schema, tokenId);
        err = oidcUserFederateId(state, fedIdJ);
        if (err)
            goto OnErrorExit;

        // if logout registered then keep track of SID
        if (idp->statics->aliasLogout) {
            sidMapT *sidMap = calloc(1, sizeof(sidMapT));
            sidMap->sid = get_object_string_dup(fedIdJ, schema->idpsid);
            sidMap->uuid = oidcStateGetSessionUUID(state);
            HASH_ADD_STR(sidHead, uuid, sidMap);
            if (!sidMap)
                goto OnErrorExit;
        }
    }
    else {
        // when no token id an extra request to user profile info endpoint
        // require
        err = oidcUserGetByToken(state);
        if (err)
            goto OnErrorExit;
    }

    // callback is responsible to free wreq & context
    json_object_put(responseJ);
    return HTTP_HANDLE_FREE;

OnErrorExit:
    EXT_CRITICAL(
        "[fail-access-token] Fail to process response from oidc status=%d "
        "body='%s' (oidcAccessTokenCB)",
        httpRqt->status, httpRqt->body.buffer);
    oidcStateUnauthorized(state);
    json_object_put(responseJ);
    return HTTP_HANDLE_FREE;
}

static int oidcOnCodeCB(struct afb_hreq *hreq,
                        const oidcIdpT *idp,
                        oidcSessionT *session,
                        oidcStateT *state)
{
    int err, status;
    char content[EXT_URL_MAX_LEN];
    char redirectUrl[EXT_HEADER_MAX_LEN];
    oidcSchemaT *schema = (oidcSchemaT *)idp->userData;

    // check if wreq as a code
    const char *code = afb_hreq_get_argument(hreq, "code");
    if (code == NULL) {
        EXT_WARNING("[idp-oidc] code is missing");
        goto OnErrorExit;
    }

    // add afb-binder endpoint to login redirect alias
    status = afb_hreq_make_here_url(hreq, idp->statics->aliasLogin, redirectUrl,
                                    sizeof(redirectUrl));
    if (status < 0) {
        EXT_WARNING("[idp-oidc] can't compute redirect url");
        goto OnErrorExit;
    }

    httpKeyValT headers[5];
    const char *params[12];
    int ipar = 0, ihead = 0;
    params[ipar++] = "code";
    params[ipar++] = code;
    params[ipar++] = "redirect_uri";
    params[ipar++] = redirectUrl;
    headers[ihead++] =
        (httpKeyValT){"Content-type", "application/x-www-form-urlencoded"};
    headers[ihead++] = (httpKeyValT){"Accept", "application/json"};
    switch (idp->wellknown->authMethod) {
    case IDP_CLIENT_SECRET_BASIC:
        params[ipar++] = "grant_type";
        params[ipar++] = "authorization_code";
        headers[ihead++] = (httpKeyValT){"Authorization", schema->auth64};
        break;
    case IDP_CLIENT_SECRET_POST:
        params[ipar++] = "client_id";
        params[ipar++] = idp->credentials->clientId;
        params[ipar++] = "client_secret";
        params[ipar++] = idp->credentials->secret;
        break;
    default:
        EXT_DEBUG("[idp-oidc] idp=%s unsupported authentication method=%d",
                  idp->uid, idp->wellknown->authMethod);
        goto OnErrorExit;
    }
    params[ipar] = NULL;
    headers[ihead] = (httpKeyValT){NULL, NULL};

    // send asynchronous post wreq with params in query //
    // https://gist.github.com/technoweenie/419219
    size_t sz = rp_escape_url_to(NULL, NULL, params, content, sizeof content);
    if (sz >= sizeof content) {
        EXT_WARNING("[idp-oidc] content is too small < %u", (unsigned)sz);
        goto OnErrorExit;
    }

    switch (idp->wellknown->authMethod) {
    case IDP_CLIENT_SECRET_BASIC:
        EXT_DEBUG(
            "[oidc-access-token] curl -H 'Authorization: %s' -X post -d '%s' "
            "%s\n",
            schema->auth64, content, idp->wellknown->tokenid);
        break;
    case IDP_CLIENT_SECRET_POST:
        EXT_DEBUG("[oidc-access-token] curl -X post -d '%s' %s\n", content, idp->wellknown->tokenid);
        break;
    default:
        break;
    }
    err =
        httpSendPost(oidcCoreHTTPPool(idp->oidc), idp->wellknown->tokenid,
                     &dfltOpts, headers, content, sz, oidcAccessTokenCB, state);
    if (err) {
        EXT_WARNING("[idp-oidc] HTTP post returned error %d", err);
        goto OnErrorExit;
    }

    return 0;

OnErrorExit:
    oidcStateUnauthorized(state);
    oidcStateUnRef(state);
    return 1;
}

// this check idp code and either wreq profile or redirect to idp login page
static int oidcLoginCB(struct afb_hreq *hreq, void *ctx)
{
    oidcIdpT *idp = (oidcIdpT *)ctx;
    oidcSessionT *session = oidcSessionOfHttpReq(hreq);
    return idpOnLoginPage(hreq, idp, oidcOnCodeCB, idp->wellknown->authorize,
                          idp->statics->aliasLogin, idp->credentials->clientId,
                          idp->wellknown->respondLabel,
                          oidcSessionUUID(session));
}

// this check idp code and either wreq profile or redirect to idp login page
// reference https://openid.net/specs/openid-connect-backchannel-1_0.html
static int oidcLogoutCB(struct afb_hreq *hreq, void *ctx)
{
    const oidcIdpT *idp = (oidcIdpT *)ctx;
    const oidcSchemaT *schema = (oidcSchemaT *)idp->userData;
    const oidcProfileT *idpProfile;
    const char *sid;
    oidcSessionT *session;
    sidMapT *sidMap;
    int err;

    // retrieve nonce from tokenid to access targetted session
    const char *tokenId = afb_hreq_get_argument(hreq, "logout_token");
    json_object *fedIdJ = oidcUserGetByJwt(schema, (char *)tokenId);
    if (!fedIdJ)
        goto OnErrorExit;

    // tokenid nonce should match with the session uuid to reset
    err = rp_jsonc_unpack(fedIdJ, "{ss}", "sid", &sid);
    if (err)
        goto OnErrorExit;

    // search for sid into hashtable
    HASH_FIND_STR(sidHead, sid, sidMap);
    if (!sidMap)
        goto OnErrorExit;

    // search session uuid and close it when exist
    session = oidcSessionOfUUID(sid);
    if (!session)
        goto OnErrorExit;
    idpProfile = oidcSessionGetTargetProfile(oidcSessionOfHttpReq(hreq));
    fedidsessionReset(session, idpProfile);

    // remove sid from sidmap table
    HASH_DEL(sidHead, sidMap);
    free(sidMap);

    return 1;  // we're done (0 would search for an html page)

OnErrorExit:
    afb_hreq_reply_error(hreq, EXT_HTTP_UNAUTHORIZED);
    return 1;
}

static int oidcRegisterAlias(const oidcIdpT *idp, struct afb_hsrv *hsrv)
{
    int err;
    EXT_DEBUG("[oidc-register-alias] uid=%s login='%s'", idp->uid,
              idp->statics->aliasLogin);

    err = afb_hsrv_add_handler(hsrv, idp->statics->aliasLogin, oidcLoginCB,
                               (void *)idp, EXT_HIGHEST_PRIO);
    if (!err)
        goto OnErrorExit;

    if (idp->statics->aliasLogout) {
        err = afb_hsrv_add_handler(hsrv, idp->statics->aliasLogout,
                                   oidcLogoutCB, (void *)idp, EXT_HIGHEST_PRIO);
        if (!err)
            goto OnErrorExit;
    }
    return 0;

OnErrorExit:
    EXT_ERROR(
        "[oidc-register-alias] idp=%s fail to register static aliases "
        "(oidcRegisterAlias)",
        idp->uid);
    return 1;
}

// request IDP wellknown endpoint and retrieve config
static httpRqtActionT oidcDiscoJwksCB(const httpRqtT *httpRqt)
{
    oidcSchemaT *schema = (oidcSchemaT *)httpRqt->userData;
    int err;

    if (httpRqt->status != 200)
        goto OnErrorExit;

    // we should have a valid json object
    json_object *responseJ = json_tokener_parse(httpRqt->body.buffer);
    if (!responseJ)
        goto OnErrorExit;

    err = rp_jsonc_unpack(responseJ, "{so}", "keys", &schema->jwksJ);
    if (err || !json_object_is_type(schema->jwksJ, json_type_array))
        goto OnErrorExit;

    return HTTP_HANDLE_FREE;

OnErrorExit:
    EXT_CRITICAL(
        "[fail-wellknown-discovery] Fail to process response from oidc "
        "status=%d body='%s' (oidcDiscoveryCB)",
        httpRqt->status, httpRqt->body.buffer);
    return HTTP_HANDLE_FREE;
}

// request IDP wellknown endpoint and retrieve config
static httpRqtActionT oidcDiscoveryCB(const httpRqtT *httpRqt)
{
    oidcIdpT *idp = (oidcIdpT *)httpRqt->userData;
    oidcSchemaT *schema = (oidcSchemaT *)idp->userData;
    oidcWellknownT *wellknown = (oidcWellknownT *)idp->wellknown;
    json_object *authMethodJ = NULL, *respondTypeJ = NULL;

    if (httpRqt->status != 200)
        goto OnErrorExit;

    // we should have a valid json object
    json_object *responseJ = json_tokener_parse(httpRqt->body.buffer);
    if (!responseJ)
        goto OnErrorExit;

    rp_jsonc_unpack(responseJ, "{s?s s?s s?s s?s s?o s?o}", "token_endpoint",
                    &wellknown->tokenid, "authorization_endpoint",
                    &wellknown->authorize, "userinfo_endpoint",
                    &wellknown->userinfo, "jwks_uri", &wellknown->jwks,
                    "token_endpoint_auth_methods_supported", &authMethodJ,
                    "response_types_supported", &respondTypeJ, "jwks_uri",
                    &wellknown->jwks);

    if (!wellknown->tokenid || !wellknown->authorize || !wellknown->userinfo)
        goto OnErrorExit;

    // search for IDP supported authentication method
    if (wellknown->authLabel) {
        wellknown->authMethod =
            rp_enum_map_value_def(idpAuthMethods, wellknown->authLabel, 0);
    }
    else {
        if (authMethodJ) {
            for (int idx = 0; idx < json_object_array_length(authMethodJ);
                 idx++) {
                const char *method = json_object_get_string(
                    json_object_array_get_idx(authMethodJ, idx));
                wellknown->authMethod =
                    rp_enum_map_value_def(idpAuthMethods, method, 0);
                if (wellknown->authMethod) {
                    wellknown->authLabel = method;
                    break;
                }
            }
        }
    }
    if (!wellknown->authMethod)
        wellknown->authMethod = IDP_CLIENT_SECRET_DEFAULT;
    if (!wellknown->authLabel)
        wellknown->authLabel = rp_enum_map_label_def(
            idpAuthMethods, IDP_RESPOND_TYPE_DEFAULT, NULL);
    if (!wellknown->authLabel)
        goto OnErrorExit;

    // if response type not defined use from from idp remote wellknown
    if (wellknown->respondLabel) {
        wellknown->respondType =
            rp_enum_map_value_def(idpRespondTypes, wellknown->respondLabel, 0);
        if (!wellknown->respondType)
            goto OnErrorExit;
    }
    else {
        if (respondTypeJ) {
            for (int idx = 0; idx < json_object_array_length(respondTypeJ);
                 idx++) {
                const char *redpond = json_object_get_string(
                    json_object_array_get_idx(respondTypeJ, idx));
                wellknown->respondType =
                    rp_enum_map_value_def(idpRespondTypes, redpond, 0);
                if (wellknown->respondType) {
                    wellknown->respondLabel = redpond;
                    break;
                }
            }
        }
    }

    // nothing defined let's try default
    if (!wellknown->respondType)
        wellknown->respondType = IDP_RESPOND_TYPE_DEFAULT;
    if (!wellknown->respondLabel)
        wellknown->respondLabel = rp_enum_map_label_def(
            idpRespondTypes, IDP_RESPOND_TYPE_DEFAULT, NULL);
    if (!wellknown->respondLabel)
        goto OnErrorExit;

    // if jwks is define request URI to get jwt keys
    if (idp->wellknown->jwks && schema->jwksJ &&
        json_object_get_boolean(schema->jwksJ)) {
        int err = httpSendGet(oidcCoreHTTPPool(idp->oidc), idp->wellknown->jwks,
                              NULL, NULL, oidcDiscoJwksCB, schema);
        if (err)
            goto OnErrorExit;
    }
    // callback is responsible to free wreq & context
    return HTTP_HANDLE_FREE;

OnErrorExit:
    EXT_CRITICAL(
        "[fail-wellknown-discovery] Fail to process response from oidc "
        "status=%d body='%s' (oidcDiscoveryCB)",
        httpRqt->status, httpRqt->body.buffer);
    return HTTP_HANDLE_FREE;
}

// oidc is openid compliant. Provide default and delegate parsing to default
// ParseOidcConfigCB
static int oidcRegisterConfig(oidcIdpT *idp, json_object *configJ)
{
    oidcDefaultsT defaults = {
        .credentials = NULL,
        .wellknown = &dfltWellknown,
        .headers = dfltHeaders,
        .statics = &dfltstatics,
        .profiles = dfltProfiles,
    };

    int err = idpParseOidcConfig(idp, configJ, &defaults, NULL);
    if (err)
        goto OnErrorExit;

    // copy default ldap options as idp private user data
    oidcSchemaT *schema = malloc(sizeof(oidcSchemaT));
    memcpy(schema, &dfltSchema, sizeof(oidcSchemaT));
    idp->userData = (void *)schema;

    // check is we have custom options
    json_object *schemaJ = json_object_object_get(configJ, "schema");
    if (schemaJ) {
        const char *info;
        err = rp_jsonc_unpack(
            schemaJ, "{s?s s?o s?s s?s s?s s?s s?s s?s s?s s?s!}", "info",
            &info, "signed", &schema->jwksJ, "idpsid", &schema->idpsid, "fedid",
            &schema->fedid, "avatar", &schema->avatar, "pseudo",
            &schema->pseudo, "name", &schema->name, "email", &schema->email,
            "company", &schema->company, "attrs", &schema->attrs);
        if (err) {
            EXT_ERROR(
                "[iodc-config-schema] json error 'schema' support json keys: "
                "signed,fedid,avatar,pseudo,email,name");
            goto OnErrorExit;
        }
    }
    // prebuilt basic authentication token
    char *authstr, *auth64;
    size_t sz64;
    int len = asprintf(&authstr, "%s:%s", idp->credentials->clientId,
                       idp->credentials->secret);
    rp_base64_encode((uint8_t *)authstr, (size_t)len, &auth64, &sz64, 0, 1, 0);
    asprintf((char **)&schema->auth64, "Basic %s", auth64);
    idp->userData = schema;
    free(authstr);
    free(auth64);

    // if discovery url is present request it now
    if (idp->wellknown->discovery) {
        EXT_NOTICE("[oidc-wellknown-get] oidc wellknown url=%s",
                   idp->wellknown->discovery);
        int err =
            httpSendGet(oidcCoreHTTPPool(idp->oidc), idp->wellknown->discovery,
                        &dfltOpts, NULL, oidcDiscoveryCB, idp);
        if (err && !idp->wellknown->lazy) {
            EXT_CRITICAL(
                "[fail-wellknown-discovery] invalid url='%s' (oidcDiscoveryCB)",
                idp->wellknown->discovery);
            goto OnErrorExit;
        }
    }

    return 0;

OnErrorExit:
    EXT_CRITICAL("[fail-config-oidc] invalid config idp='%s' (oidcDiscoveryCB)",
                 idp->uid);
    return 1;
}

//----------------------------------------------------------------
// Description
//----------------------------------------------------------------
const idpPluginT oidcPluginDesc = {.uid = "oidc",
                                   .info = "openid connect idp",
                                   .registerConfig = oidcRegisterConfig,
                                   .registerAlias = oidcRegisterAlias};
