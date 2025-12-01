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

#include <rp-utils/rp-jsonc.h>

#include <libafb/afb-core.h>
#include <libafb/afb-http.h>
#include <libafb/afb-v4.h>

#include "curl-glue.h"
#include "idp-oidc.h"
#include "oidc-alias.h"
#include "oidc-core.h"
#include "oidc-fedid.h"
#include "oidc-idp.h"
#include "oidc-session.h"
#include "oidc-utils.h"

// import idp authentication enum/label
extern const nsKeyEnumT idpAuthMethods[];
extern const nsKeyEnumT idpRespondTypes[];

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

// duplicate key value if not null
static char *json_object_dup_key_value(json_object *objJ, const char *key)
{
    char *value;
    value = (char *)json_object_get_string(json_object_object_get(objJ, key));
    if (value)
        value = strdup(value);
    return value;
}

// signature to be check with GNUTLS to be added by JOSE)
// reference https://jwt.io/ https://datatracker.ietf.org/doc/html/rfc7517
static json_object *oidcJwtCheck(oidcSchemaT *schema, char *token[])
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

static int oidcUserFederateId(idpRqtCtxT *rqtCtx, json_object *profileJ)
{
    oidcIdpT *idp = rqtCtx->idp;
    oidcSchemaT *schema = (oidcSchemaT *)idp->userData;
    fedSocialRawT *fedSocial;
    fedUserRawT *fedUser;
    json_object *attrsJ;
    int err;

    // no profile just ignore
    if (!profileJ)
        return -1;

    // build social fedkey from idp->uid+oidc->id
    fedSocial = calloc(1, sizeof(fedSocialRawT));
    fedSocial->fedkey = json_object_dup_key_value(profileJ, schema->fedid);
    fedSocial->idpsid = json_object_dup_key_value(profileJ, schema->idpsid);
    fedSocial->idp = strdup(idp->uid);
    rqtCtx->fedSocial = fedSocial;

    // check groups as security attributs
    if (schema->attrs) {
        json_object_object_get_ex(profileJ, schema->attrs, &attrsJ);
        fprintf(stderr, "fedid= %s ***\n", json_object_get_string(profileJ));
        if (json_object_is_type(attrsJ, json_type_array)) {
            size_t count = json_object_array_length(attrsJ);
            fedSocial->attrs = calloc(count + 1, sizeof(char *));
            for (int idx = 0; idx < count; idx++) {
                json_object *attrJ = json_object_array_get_idx(attrsJ, idx);
                rqtCtx->fedSocial->attrs[idx] =
                    strdup(json_object_get_string(attrJ));
            }
        }
    }

    fedUser = calloc(1, sizeof(fedUserRawT));
    fedUser->pseudo = json_object_dup_key_value(profileJ, schema->pseudo);
    fedUser->avatar = json_object_dup_key_value(profileJ, schema->avatar);
    fedUser->name = json_object_dup_key_value(profileJ, schema->name);
    fedUser->company = json_object_dup_key_value(profileJ, schema->company);
    fedUser->email = json_object_dup_key_value(profileJ, schema->email);
    rqtCtx->fedUser = fedUser;

    err = fedidCheck(rqtCtx);
    if (err)
        goto OnErrorExit;

    return 0;

OnErrorExit:
    free(fedSocial);
    free(fedUser);
    return -1;
}

// call when IDP respond to user profile wreq
// reference:
// https://docs.oidc.com/en/rest/reference/users#get-the-authenticated-user
static httpRqtActionT oidcUserGetByTokenCB(httpRqtT *httpRqt)
{
    idpRqtCtxT *rqtCtx = (idpRqtCtxT *)httpRqt->userData;
    int err;

    // something when wrong
    if (httpRqt->status != 200)
        goto OnErrorExit;

    // unwrap user profile
    json_object *profileJ = json_tokener_parse(httpRqt->body);
    if (!profileJ)
        goto OnErrorExit;

    err = oidcUserFederateId(rqtCtx, profileJ);
    if (err)
        goto OnErrorExit;

    return HTTP_HANDLE_FREE;

OnErrorExit:
    EXT_CRITICAL(
        "[oidc-fail-user-profile] Fail to get user profile from oidc "
        "status=%ld body='%s'",
        httpRqt->status, httpRqt->body);
    afb_hreq_reply_error(rqtCtx->hreq, EXT_HTTP_UNAUTHORIZED);
    idpRqtCtxFree(rqtCtx);
    return HTTP_HANDLE_FREE;
}

// from acces token wreq user profile
// reference
// https://docs.oidc.com/en/developers/apps/authorizing-oauth-apps#web-application-flow
static int oidcUserGetByToken(idpRqtCtxT *rqtCtx)
{
    oidcIdpT *idp = rqtCtx->idp;

    httpKeyValT authToken[] = {
        {.tag = "Authorization", .value = rqtCtx->token},
        {.tag = "grant_type", .value = "authorization_code"},
        {NULL}  // terminator
    };

    // asynchronous wreq to IDP user profile
    // https://docs.oidc.com/en/rest/reference/orgs#list-organizations-for-the-authenticated-user
    EXT_DEBUG("[oidc-profile-get] curl -H 'Authorization: %s' %s\n",
              rqtCtx->token, idp->wellknown->userinfo);
    // int err = httpSendGet (idp->oidc->httpPool, idp->wellknown->userinfo,
    // &dfltOpts, authToken, oidcUserGetByTokenCB, rqtCtx);
    int err = httpSendGet(NULL, idp->wellknown->userinfo, &dfltOpts, authToken,
                          oidcUserGetByTokenCB, rqtCtx);
    if (err)
        goto OnErrorExit;
    return 0;

OnErrorExit:
    return -1;
}

// parse jwt token
// reference
// https://developer.yahoo.com/oauth2/guide/openid_connect/decode_id_token.html?guccounter=1
static json_object *oidcUserGetByJwt(oidcSchemaT *schema, char *tokenId)
{
    int tknIdx = 0, start = 0, index;
    char *token[TKN_SIZE];
    int length[TKN_SIZE];
    json_object *bodyJ;

    // split jwt token "header64"."body64"."sign64"
    for (index = 0; tokenId[index] != '\0'; index++) {
        if (tokenId[index] == '.') {
            if (tknIdx == 3)
                goto OnErrorExit;
            tokenId[index] = '\0';
            length[tknIdx] = index - start;
            token[tknIdx] = &tokenId[start];
            tknIdx++;
            start = index + 1;
        }
    }
    token[tknIdx] = &tokenId[start];
    length[tknIdx] = index - start;

    // uncode64 and open json object
    token[TKN_BODY] =
        httpDecode64(token[TKN_BODY], length[TKN_BODY], ENCODED_URL);
    if (!token[TKN_BODY])
        goto OnErrorExit;

    // if no signature directly open token body as a json object
    if (!schema->jwksJ) {
        bodyJ = json_tokener_parse(token[TKN_BODY]);
    }
    else {
        token[TKN_HEADER] =
            httpDecode64(token[TKN_HEADER], length[TKN_HEADER], ENCODED_URL);
        // signature is not encoded
        if (!token[TKN_HEADER] || !token[TKN_SIGN])
            goto OnErrorExit;
        bodyJ = oidcJwtCheck(schema, token);
    }
    return bodyJ;

OnErrorExit:
    EXT_CRITICAL("[token-id-invalid] fail to parse tokenId (oidcUserGetByJwt)");
    return NULL;
}

// call when oidc return a valid access_token
static httpRqtActionT oidcAccessTokenCB(httpRqtT *httpRqt)
{
    char *tokenVal, *tokenType, *tokenId = NULL;
    assert(httpRqt->magic == MAGIC_HTTP_RQT);
    idpRqtCtxT *rqtCtx = (idpRqtCtxT *)httpRqt->userData;
    oidcSchemaT *schema = (oidcSchemaT *)rqtCtx->idp->userData;
    json_object *responseJ = NULL;
    int err;

    // free old post data
    free(rqtCtx->userData);

    if (httpRqt->status != 200)
        goto OnErrorExit;

    // we should have a valid token or something when wrong
    responseJ = json_tokener_parse(httpRqt->body);
    if (!responseJ)
        goto OnErrorExit;

    err = rp_jsonc_unpack(responseJ, "{ss ss s?s}", "access_token", &tokenVal,
                          "token_type", &tokenType, "id_token", &tokenId);
    if (err)
        goto OnErrorExit;
    asprintf(&rqtCtx->token, "%s %s", tokenType, tokenVal);

    // if we get a token ID check it otherwise try to query user profile end
    // point
    if (tokenId) {
        json_object *fedIdJ = oidcUserGetByJwt(schema, tokenId);
        err = oidcUserFederateId(rqtCtx, fedIdJ);
        if (err)
            goto OnErrorExit;

        // if logout registered then keep track of SID
        if (rqtCtx->idp->statics->aliasLogout) {
            sidMapT *sidMap = calloc(1, sizeof(sidMapT));
            sidMap->sid = rqtCtx->fedSocial->idpsid;
            sidMap->uuid = rqtCtx->uuid;
            HASH_ADD_STR(sidHead, uuid, sidMap);
            if (!sidMap)
                goto OnErrorExit;
        }
    }
    else {
        // when no token id an extra request to user profile info endpoint
        // require
        err = oidcUserGetByToken(rqtCtx);
        if (err)
            goto OnErrorExit;
    }

    // callback is responsible to free wreq & context
    json_object_put(responseJ);
    return HTTP_HANDLE_FREE;

OnErrorExit:
    if (responseJ)
        json_object_put(responseJ);
    EXT_CRITICAL(
        "[fail-access-token] Fail to process response from oidc status=%ld "
        "body='%s' (oidcAccessTokenCB)",
        httpRqt->status, httpRqt->body);
    afb_hreq_reply_error(rqtCtx->hreq, EXT_HTTP_UNAUTHORIZED);
    return HTTP_HANDLE_FREE;
}

static int oidcAccessToken(afb_hreq *hreq,
                           oidcIdpT *idp,
                           const char *redirectUrl,
                           const char *code)
{
    assert(idp->magic == MAGIC_OIDC_IDP);
    oidcCoreHdlT *oidc = idp->oidc;
    int err, dataLen;
    oidcSchemaT *schema = (oidcSchemaT *)idp->userData;

    idpRqtCtxT *rqtCtx = calloc(1, sizeof(idpRqtCtxT));
    rqtCtx->hreq = hreq;
    rqtCtx->idp = idp;
    rqtCtx->uuid = afb_session_uuid(hreq->comreq.session);
    rqtCtx->profile = oidcSessionGetIdpProfile(hreq->comreq.session);
    if (rqtCtx->profile == NULL)
        goto OnErrorExit;

    switch (idp->wellknown->authMethod) {
    case IDP_CLIENT_SECRET_BASIC: {
        dataLen = asprintf((char **)&rqtCtx->userData,
                           "code=%s&redirect_uri=%s&grant_type=%s", code,
                           redirectUrl, "authorization_code");

        httpKeyValT headers[] = {
            {.tag = "Content-type",
             .value = "application/x-www-form-urlencoded"},
            {.tag = "Accept", .value = "application/json"},
            {.tag = "Authorization", .value = schema->auth64},
            {NULL}  // terminator
        };

        EXT_DEBUG(
            "[oidc-access-token] curl -H 'Authorization: %s' -X post -d '%s' "
            "%s\n",
            schema->auth64, (char *)rqtCtx->userData, idp->wellknown->tokenid);
        // err = httpSendPost (oidc->httpPool, idp->wellknown->tokenid,
        // &dfltOpts, headers, rqtCtx->userData, dataLen , oidcAccessTokenCB,
        // rqtCtx);
        err =
            httpSendPost(NULL, idp->wellknown->tokenid, &dfltOpts, headers,
                         rqtCtx->userData, dataLen, oidcAccessTokenCB, rqtCtx);
        break;
    }

        // reference
        // https://developers.onelogin.com/openid-connect/api/client-credentials-grant
        // https://iot-bzh-dev.onelogin.com/ (email not username)
    case IDP_CLIENT_SECRET_POST:
        dataLen =
            asprintf((char **)&rqtCtx->userData,
                     "code=%s&redirect_uri=%s&grant_type=%s&client_id=%s&"
                     "client_secret=%s",
                     code, redirectUrl, "client_credentials",
                     idp->credentials->clientId, idp->credentials->secret);

        httpKeyValT headers[] = {
            {.tag = "Content-type",
             .value = "application/x-www-form-urlencoded"},
            {.tag = "Accept", .value = "application/json"},
            {NULL}  // terminator
        };

        EXT_DEBUG("[oidc-access-token] curl -X post -d '%s' %s\n",
                  (char *)rqtCtx->userData, idp->wellknown->tokenid);
        // err = httpSendPost (oidc->httpPool, idp->wellknown->tokenid,
        // &dfltOpts, headers, rqtCtx->userData, dataLen , oidcAccessTokenCB,
        // rqtCtx);
        err =
            httpSendPost(NULL, idp->wellknown->tokenid, &dfltOpts, headers,
                         rqtCtx->userData, dataLen, oidcAccessTokenCB, rqtCtx);
        break;

    default:
        EXT_DEBUG(
            "[oidc-auth-unknown] idp=%s unsupported authentication method=%d",
            idp->uid, idp->wellknown->authMethod);
        goto OnErrorExit;
    }
    if (err)
        goto OnErrorExit;

    return 0;

OnErrorExit:
    if (rqtCtx->userData)
        free(rqtCtx->userData);
    free(rqtCtx);
    afb_hreq_reply_error(hreq, EXT_HTTP_UNAUTHORIZED);
    return 1;
}

// this check idp code and either wreq profile or redirect to idp login page
static int oidcLoginCB(afb_hreq *hreq, void *ctx)
{
    oidcIdpT *idp = (oidcIdpT *)ctx;
    assert(idp->magic == MAGIC_OIDC_IDP);
    char redirectUrl[EXT_HEADER_MAX_LEN];
    const oidcProfileT *profile = NULL;
    const oidcAliasT *alias = NULL;
    int err, status, aliasLoa;

    // check if wreq as a code
    const char *code = afb_hreq_get_argument(hreq, "code");
    const char *session = afb_session_uuid(hreq->comreq.session);
    alias = oidcSessionGetAlias(hreq->comreq.session);
    if (alias)
        aliasLoa = alias->loa;
    else
        aliasLoa = 0;

    // add afb-binder endpoint to login redirect alias
    status = afb_hreq_make_here_url(hreq, idp->statics->aliasLogin, redirectUrl,
                                    sizeof(redirectUrl));
    if (status < 0)
        goto OnErrorExit;

    // if no code then set state and redirect to IDP
    if (!code) {
        char url[EXT_URL_MAX_LEN];
        const char *scope = afb_hreq_get_argument(hreq, "scope");

        // search for a scope fiting wreqing loa
        for (int idx = 0; idp->profiles[idx].uid; idx++) {
            if (idp->profiles[idx].loa >= aliasLoa) {
                // if no scope take the 1st profile with valid LOA
                if (scope && (strcmp(scope, idp->profiles[idx].scope)))
                    continue;
                profile = &idp->profiles[idx];
                break;
            }
        }

        // if loa working and no profile fit exit without trying authentication
        if (!profile)
            goto OnErrorExit;

        // store working profile to retreive attached loa and role filter if
        // login succeeded
        oidcSessionSetIdpProfile(hreq->comreq.session, profile);

        httpKeyValT query[] = {
            {.tag = "client_id", .value = idp->credentials->clientId},
            {.tag = "response_type", .value = idp->wellknown->respondLabel},
            {.tag = "state", .value = session},
            {.tag = "nonce", .value = session},
            {.tag = "scope", .value = profile->scope},
            {.tag = "redirect_uri", .value = redirectUrl},
            {.tag = "language", .value = setlocale(LC_CTYPE, "")},
            {NULL}  // terminator
        };

        // build wreq and send it
        err = httpBuildQuery(idp->uid, url, sizeof(url), NULL /* prefix */,
                             idp->wellknown->authorize, query);
        if (err)
            goto OnErrorExit;

        EXT_DEBUG("[oidc-redirect-url] %s (oidcRegisterAlias)", url);
        afb_hreq_redirect_to(hreq, url, HREQ_QUERY_EXCL, HREQ_REDIR_TMPY);
    }
    else {
        // use state to retreive original wreq session uuid and restore original
        // session before wreqing token
        const char *oidcState = afb_hreq_get_argument(hreq, "state");
        if (strcmp(oidcState, session)) {
            EXT_DEBUG(
                "[oidc-auth-code] missmatch session/state state=%s session=%s "
                "(oidcRegisterAlias)",
                oidcState, session);
            goto OnErrorExit;
        }

        EXT_DEBUG("[oidc-auth-code] state=%s code=%s (oidcRegisterAlias)",
                  oidcState, code);
        // wreq authentication token from tempry code
        err = oidcAccessToken(hreq, idp, redirectUrl, code);
        if (err)
            goto OnErrorExit;
    }
    return 1;  // we're done (0 would search for an html page)

OnErrorExit:
    afb_hreq_reply_error(hreq, EXT_HTTP_UNAUTHORIZED);
    return 1;
}

// this check idp code and either wreq profile or redirect to idp login page
// reference https://openid.net/specs/openid-connect-backchannel-1_0.html
static int oidcLogoutCB(afb_hreq *hreq, void *ctx)
{
    oidcIdpT *idp = (oidcIdpT *)ctx;
    oidcSchemaT *schema = (oidcSchemaT *)idp->userData;
    const oidcProfileT *idpProfile;
    const char *sessionUid;
    struct afb_session *session;
    sidMapT *sidMap;
    int err;

    // retreive nonce from tokenid to access targetted session
    const char *tokenId = afb_hreq_get_argument(hreq, "logout_token");
    json_object *fedIdJ = oidcUserGetByJwt(schema, (char *)tokenId);
    if (!fedIdJ)
        goto OnErrorExit;

    // tokenid nonce should match with the session uuid to reset
    err = rp_jsonc_unpack(fedIdJ, "{ss}", "sid", &sessionUid);
    if (err)
        goto OnErrorExit;

    // search for sid into hashtable
    HASH_FIND_STR(sidHead, sessionUid, sidMap);
    if (!sidMap)
        goto OnErrorExit;

    // search session uuid and close it when exist
    session = afb_session_search(sessionUid);
    if (!session)
        goto OnErrorExit;
    idpProfile = oidcSessionGetIdpProfile(hreq->comreq.session);
    fedidsessionReset(session, idpProfile);

    // remove sid from sidmap table
    HASH_DEL(sidHead, sidMap);
    free(sidMap);

    return 1;  // we're done (0 would search for an html page)

OnErrorExit:
    afb_hreq_reply_error(hreq, EXT_HTTP_UNAUTHORIZED);
    return 1;
}

int oidcRegisterAlias(oidcIdpT *idp, afb_hsrv *hsrv)
{
    int err;
    EXT_DEBUG("[oidc-register-alias] uid=%s login='%s'", idp->uid,
              idp->statics->aliasLogin);

    err = afb_hsrv_add_handler(hsrv, idp->statics->aliasLogin, oidcLoginCB, idp,
                               EXT_HIGHEST_PRIO);
    if (!err)
        goto OnErrorExit;

    if (idp->statics->aliasLogout) {
        err = afb_hsrv_add_handler(hsrv, idp->statics->aliasLogout,
                                   oidcLogoutCB, idp, EXT_HIGHEST_PRIO);
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

// request IDP wellknown endpoint and retreive config
static httpRqtActionT oidcDiscoJwksCB(httpRqtT *httpRqt)
{
    assert(httpRqt->magic == MAGIC_HTTP_RQT);
    oidcSchemaT *schema = (oidcSchemaT *)httpRqt->userData;
    int err;

    if (httpRqt->status != 200)
        goto OnErrorExit;

    // we should have a valid json object
    json_object *responseJ = json_tokener_parse(httpRqt->body);
    if (!responseJ)
        goto OnErrorExit;

    err = rp_jsonc_unpack(responseJ, "{so}", "keys", &schema->jwksJ);
    if (err || !json_object_is_type(schema->jwksJ, json_type_array))
        goto OnErrorExit;

    return HTTP_HANDLE_FREE;

OnErrorExit:
    EXT_CRITICAL(
        "[fail-wellknown-discovery] Fail to process response from oidc "
        "status=%ld body='%s' (oidcDiscoveryCB)",
        httpRqt->status, httpRqt->body);
    return HTTP_HANDLE_FREE;
}

// request IDP wellknown endpoint and retreive config
static httpRqtActionT oidcDiscoveryCB(httpRqtT *httpRqt)
{
    assert(httpRqt->magic == MAGIC_HTTP_RQT);
    oidcIdpT *idp = (oidcIdpT *)httpRqt->userData;
    oidcSchemaT *schema = (oidcSchemaT *)idp->userData;
    oidcWellknownT *wellknown = (oidcWellknownT *)idp->wellknown;
    json_object *authMethodJ = NULL, *respondTypeJ = NULL;

    if (httpRqt->status != 200)
        goto OnErrorExit;

    // we should have a valid json object
    json_object *responseJ = json_tokener_parse(httpRqt->body);
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
            utilLabel2Value(idpAuthMethods, wellknown->authLabel);
    }
    else {
        if (authMethodJ) {
            for (int idx = 0; idx < json_object_array_length(authMethodJ);
                 idx++) {
                const char *method = json_object_get_string(
                    json_object_array_get_idx(authMethodJ, idx));
                wellknown->authMethod = utilLabel2Value(idpAuthMethods, method);
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
        wellknown->authLabel =
            utillValue2Label(idpAuthMethods, IDP_RESPOND_TYPE_DEFAULT);
    if (!wellknown->authLabel)
        goto OnErrorExit;

    // if response type not defined use from from idp remote wellknown
    if (wellknown->respondLabel) {
        wellknown->respondType =
            utilLabel2Value(idpRespondTypes, wellknown->respondLabel);
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
                    utilLabel2Value(idpRespondTypes, redpond);
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
        wellknown->respondLabel =
            utillValue2Label(idpRespondTypes, IDP_RESPOND_TYPE_DEFAULT);
    if (!wellknown->respondLabel)
        goto OnErrorExit;

    // if jwks is define request URI to get jwt keys
    if (idp->wellknown->jwks && schema->jwksJ &&
        json_object_get_boolean(schema->jwksJ)) {
        // int err = httpSendGet (idp->oidc->httpPool, idp->wellknown->jwks,
        // NULL, NULL, oidcDiscoJwksCB, schema);
        int err = httpSendGet(NULL, idp->wellknown->jwks, NULL, NULL,
                              oidcDiscoJwksCB, schema);
        if (err)
            goto OnErrorExit;
    }
    // callback is responsible to free wreq & context
    return HTTP_HANDLE_FREE;

OnErrorExit:
    EXT_CRITICAL(
        "[fail-wellknown-discovery] Fail to process response from oidc "
        "status=%ld body='%s' (oidcDiscoveryCB)",
        httpRqt->status, httpRqt->body);
    return HTTP_HANDLE_FREE;
}

// oidc is openid compliant. Provide default and delegate parsing to default
// ParseOidcConfigCB
int oidcRegisterConfig(oidcIdpT *idp, json_object *configJ)
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
    char *authstr;
    int len = asprintf(&authstr, "%s:%s", idp->credentials->clientId,
                       idp->credentials->secret);
    char *auth64 = httpEncode64(authstr, len);
    asprintf((char **)&schema->auth64, "Basic %s", auth64);
    idp->userData = schema;
    free(authstr);
    free(auth64);

    // if discovery url is present request it now
    if (idp->wellknown->discovery) {
        EXT_NOTICE("[oidc-wellknown-get] oidc wellknown url=%s",
                   idp->wellknown->discovery);
        int err = httpSendGet(idp->oidc->httpPool, idp->wellknown->discovery,
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
