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

#include "oidc-core.h"
#include "oidc-idp.h"
#include "oidc-fedid.h"
#include "idps-builtin.h"
#include <libafb/http/afb-hsrv.h>

#include <string.h>
#include <dlfcn.h>

MAGIC_OIDC_SESSION(oidcIdpProfilCookie);

typedef struct idpRegistryS {
   struct idpRegistryS *next;
   const char *uid;
   idpPluginT *plugin;
} idpRegistryT;

// registry holds a linked list of core+pugins idps
idpPluginT idpBuiltin[];
static idpRegistryT *registryHead= NULL;

// return the idp list to display corresponding login page.
json_object *idpLoaProfilsGet (oidcCoreHdlT *oidc, int loa) {
	json_object *idpsJ= NULL;

	for (int idx=0; oidc->idps[idx].uid; idx++) {
		oidcIdpT *idp= &oidc->idps[idx];
		json_object *profilsJ=NULL;

		// search for requested LOA within idp existing profils
		for (int jdx=0; idp->profils[jdx].uid; jdx++) {
			// if loa mach return corresponding scope
			if (idp->profils[jdx].loa >= loa) {
				json_object *profilJ;
				if (!profilsJ) profilsJ= json_object_new_array();
				wrap_json_pack (&profilJ, "{si ss ss* ss}"
					, "loa", idp->profils[jdx].loa
					, "uid", idp->profils[jdx].uid
					, "info", idp->profils[jdx].info
					, "scope",idp->profils[jdx].scope
				);
				json_object_array_add (profilsJ,profilJ);
			}
		}

		// only return IDP with a corresponding loa/scope
		if (profilsJ) {
			json_object *idpJ;
			if (!idpsJ) idpsJ= json_object_new_array();
			wrap_json_pack (&idpJ, "{ss ss* ss* ss* ss* ss* so}"
				,"uid",  idp->uid
				,"info", idp->info
				,"logo", idp->statics->aliasLogo
				,"client-id", idp->credentials->clientId
				,"token-url", idp->wellknown->loginTokenUrl
				,"login-url", idp->statics->aliasLogin
				,"profils", profilsJ
			);

			json_object_array_add (idpsJ,idpJ);
		}
	}
	return idpsJ;
}


// add a new plugin idp to the registry
static int idpPluginRegisterCB (const char *pluginUid, idpPluginT *pluginCbs) {
    idpRegistryT *registryIdx, *registryEntry;

    // create holding hat for idp/decoder CB
    registryEntry= (idpRegistryT*) calloc (1, sizeof(idpRegistryT));
    if (pluginUid) registryEntry->uid = pluginUid;
	else registryEntry->uid = "built-in";
    registryEntry->plugin = pluginCbs;

    // if not 1st idp insert at the end of the chain
    if (!registryHead) {
        registryHead = registryEntry;
    } else {
        for (registryIdx= registryHead; registryIdx->next; registryIdx=registryIdx->next);
        registryIdx->next = registryEntry;
    }

    return 0;
}

static const oidcCredentialsT *idpParseCredentials (oidcIdpT *idp, json_object *credentialsJ, const oidcCredentialsT *defaults) {

    oidcCredentialsT *credentials = calloc(1, sizeof(oidcCredentialsT));
    if (defaults) memcpy(credentials, defaults, sizeof(oidcCredentialsT));

	if (credentialsJ) {
		int err= wrap_json_unpack (credentialsJ, "{ss,ss}"
				, "clientid", &credentials->clientId
				, "secret", &credentials->secret
				);
		if (err) {
		EXT_CRITICAL ("idp=%s parsing fail 'credentials' should define 'clientid','secret' (idpParseCredentials)", idp->uid);
			goto OnErrorExit;
		}
	}
	return credentials;

OnErrorExit:
  free(credentials);
  return NULL;
}

static int idpParseOneHeader (oidcIdpT *idp, json_object *headerJ, httpKeyValT *header) {
		int err= wrap_json_unpack (headerJ, "{ss,ss}"
			, "tag",  &header->tag
			, "value", &header->value
			);
		if (err) {
			EXT_CRITICAL ("[idp-header-error] idp=%s parsing fail profil expect: tag,value (idpParseOneHeader)", idp->uid);
			goto OnErrorExit;
		}
    return 0;

OnErrorExit:
  return 1;
}

static const httpKeyValT *idpParseHeaders (oidcIdpT *idp, json_object *headersJ, const httpKeyValT *defaults) {
  if (!headersJ) return defaults;

  httpKeyValT *headers;
  int err;

	switch (json_object_get_type (headersJ)) {
				int count;

				case json_type_array:
					count= (int)json_object_array_length(headersJ);
					headers= calloc (count+1, sizeof(httpKeyValT));

					for (int idx=0; idx < count; idx ++) {
						json_object *headerJ= json_object_array_get_idx(headersJ, idx);
						err= idpParseOneHeader (idp, headerJ, &headers[idx]);
						if (err) goto OnErrorExit;
					}
					break;

				case json_type_object:
					headers = calloc (2, sizeof(httpKeyValT));
					err= idpParseOneHeader (idp, headersJ, &headers[0]);
					if (err) goto OnErrorExit;
					break;

				default:
					EXT_CRITICAL("[idp-headers-error] idp=%s should be json_array|json_object (idpParseHeaders)", idp->uid);
					goto OnErrorExit;
			}
			return headers;

OnErrorExit:
  return NULL;
}

static int idpParseOneProfil (oidcIdpT *idp, json_object *profileJ, oidcProfilsT *profil) {
		int err= wrap_json_unpack (profileJ, "{ss,s?s,si,ss,s?s}"
			, "uid", &profil->uid
			, "info", &profil->info
			, "loa", &profil->loa
			, "scope", &profil->scope
			, "label", &profil->label
			);
		if (err) {
			EXT_CRITICAL ("[idp-profile-error] idp=%s parsing fail profil expect: loa,scope (idpParseOneProfil)", idp->uid);
			goto OnErrorExit;
		}
    return 0;

OnErrorExit:
  return 1;
}

static const oidcProfilsT *idpParseProfils (oidcIdpT *idp, json_object *profilsJ, const oidcProfilsT *defaults) {
	oidcProfilsT *profils;
	int err;

    // no config use defaults
    if (!profilsJ) return defaults;

	switch (json_object_get_type (profilsJ)) {
		int count;

		case json_type_array:
			count= (int)json_object_array_length(profilsJ);
			profils= calloc (count+1, sizeof(oidcProfilsT));

			for (int idx=0; idx < count; idx ++) {
				json_object *profilJ= json_object_array_get_idx(profilsJ, idx);
				err= idpParseOneProfil (idp, profilJ, &profils[idx]);
				if (err) goto OnErrorExit;
			}
			break;

		case json_type_object:
			profils = calloc (2, sizeof(oidcProfilsT));
			err= idpParseOneProfil (idp, profilsJ, &profils[0]);
			if (err) goto OnErrorExit;
			break;

		default:
			EXT_CRITICAL("[idp-profil-error] idp=%s should be json_array|json_object", idp->uid);
			goto OnErrorExit;
		}
    return(profils);

OnErrorExit:
  free(profils);
  return NULL;
}

static const oidcStaticsT *idpParsestatic (oidcIdpT *idp, json_object *staticJ, const oidcStaticsT *defaults) {

    // no config use defaults
    if (!staticJ) return defaults;

	oidcStaticsT *statics=calloc(1, sizeof(oidcStaticsT));
	if (defaults) memcpy(statics, defaults, sizeof(oidcStaticsT));

	int err= wrap_json_unpack (staticJ, "{s?s,s?s,s?i}"
		, "login", &statics->aliasLogin
		, "logo",  &statics->aliasLogo
		, "timeout", &statics->timeout
		);
	if (err) {
		EXT_CRITICAL ("[idp-static-error] idp=%s parsing fail statics expect: login,logo,plugin,timeout (idpParsestatic)", idp->uid);
		goto OnErrorExit;
	}

	// if session timeout null use default (600s)
	if (statics->timeout <0) statics->timeout= EXT_SESSION_TIMEOUT;

    return(statics);

OnErrorExit:
  free(statics);
  return NULL;
}

static const oidcWellknownT *idpParseWellknown (oidcIdpT *idp, json_object *wellknownJ, const oidcWellknownT *defaults) {
    if (!wellknownJ) return defaults;

		oidcWellknownT *wellknown=calloc(1, sizeof(oidcWellknownT));
		if (defaults) memcpy(wellknown, defaults, sizeof(oidcWellknownT));

   	int err= wrap_json_unpack (wellknownJ, "{s?s,s?s,s?s}"
			, "loginTokenUrl", &wellknown->loginTokenUrl
			, "accessTokenUrl", &wellknown->accessTokenUrl
			, "identityApiUrl", &wellknown->identityApiUrl
			);
		if (err) {
			EXT_CRITICAL ("github parsing fail wellknown expect: loginTokenUrl,accessTokenUrl,identityApiUrl (idpParseWellknown)");
			goto OnErrorExit;
		}

    return (wellknown);

OnErrorExit:
  free(wellknown);
  return NULL;
}


int idpParseOidcConfig (oidcIdpT *idp, json_object *configJ, oidcDefaultsT *defaults, void*ctx) {

    if (!configJ) {
      EXT_CRITICAL ("ext=%s github config must define client->id & client->secret (githubConfigCB)", idp->uid);
      goto OnErrorExit;
    }

    // unpack main IDP config
    json_object* credentialsJ=NULL, *staticJ=NULL, *wellknownJ=NULL, *headersJ=NULL, *profilsJ;
    int err= wrap_json_unpack (configJ, "{ss s?s s?o s?o s?o s?o}"
      , "uid", &idp->uid
      , "info", &idp->info
      , "credentials", &credentialsJ
      , "statics", &staticJ
      , "profils", &profilsJ
      , "wellknown", &wellknownJ
      , "headers", &headersJ
      );
    if (err) {
      EXT_CRITICAL ("idp=%s parsing fail should define 'credentials','static','alias' (githubConfigCB)", idp->uid);
      goto OnErrorExit;
    }

    // parse config sections
    idp->magic= MAGIC_OIDC_IDP;
    idp->ctx= ctx;
    idp->credentials= idpParseCredentials (idp, credentialsJ, defaults->credentials);
    idp->statics= idpParsestatic (idp, staticJ, defaults->statics);
    idp->profils= idpParseProfils (idp, profilsJ, defaults->profils);
    idp->wellknown= idpParseWellknown (idp, wellknownJ, defaults->wellknown);
    idp->headers = idpParseHeaders(idp, headersJ, defaults->headers);

    // any error is fatal, even if section check continue after 1st error
    if (!idp->wellknown || !idp->statics || !idp->credentials || !idp->headers) goto OnErrorExit;

    idp->ctx= ctx; // optional idp context specific handle
    return 0;

OnErrorExit:
	return 1;
}

// search for a plugin idps/decoders CB list
static const idpPluginT *idpFindPlugin (const char *uid) {
    idpPluginT *idp=NULL;
    int index;

    // search within plugin list
    for (idpRegistryT *registryIdx= registryHead; registryIdx; registryIdx=registryIdx->next) {
        idpPluginT *idps=registryIdx->plugin;
        for (index=0; idps[index].uid; index++) {
          if (!strcasecmp (idps[index].uid, uid)) {
            idp= &idps[index];
            break;
          }
        }
    }
    if (!idp) goto OnErrorExit;

    return idp;

OnErrorExit:
    return NULL;
}

// build IDP generic callback handle
idpGenericCbT idpGenericCB = {
  .magic= MAGIC_OIDC_CBS,
  .parseCredentials= idpParseCredentials,
  .parsestatic= idpParsestatic,
  .parseWellknown= idpParseWellknown,
  .parseHeaders= idpParseHeaders,
  .parseConfig= idpParseOidcConfig,
  .fedidCheck= fedidCheck,
  .pluginRegister= idpPluginRegisterCB,
};

static int idpParseOne (oidcCoreHdlT *oidc, json_object *idpJ, oidcIdpT *idp) {
	int err;

	// search idp with registry
	const char *uid= json_object_get_string (json_object_object_get (idpJ,"uid"));
		if (!uid) {
		EXT_ERROR("[idp-parsing-error] invalid json requires: uid");
		goto OnErrorExit;
	}

	// if not builtin load plugin before processing any further the config
	json_object *pluginJ = json_object_object_get (idpJ,"plugin");
	if (pluginJ) {
		const char *ldpath = json_object_get_string (json_object_object_get (pluginJ,"ldpath"));
		if (!ldpath) {
			EXT_CRITICAL("[idp-parsing-ldpath] idp=%s invalid json 'ldpath' missing", uid);
			goto OnErrorExit;
		} else {
			void *handle=NULL;
			char* filepath;
			char* tokpath= strdup(ldpath);
		    // split string into multiple configpath
            for (filepath=strtok(tokpath, ":"); filepath; filepath=strtok(NULL, ":")) {
				handle= dlopen (filepath, RTLD_NOW|RTLD_LOCAL);
				if (handle) break;
            }
			free(tokpath);
			if (!handle) {
				EXT_ERROR("[idp-plugin-load] idp=%s plugin=%s error=%s", uid, ldpath, dlerror());
				goto OnErrorExit; 
			}

			oidcPluginInitCbT registerPluginCB= (oidcPluginInitCbT) dlsym(handle, "oidcPluginInit");  
			if (!registerPluginCB) {
				EXT_ERROR("[idp-plugin-symb] idp=%s plugin=%s initcb='oidcPluginInit' (symbol not found)", uid, filepath);
				goto OnErrorExit; 
			}

			err= registerPluginCB (oidc, &idpGenericCB);
			if (err) {
				EXT_ERROR("[idp-plugin-init] idp=%s plugin=%s initcb='oidcPluginInit' (call fail)", uid, filepath);
				goto OnErrorExit; 
			}
		}
	}

	idp->magic = MAGIC_OIDC_IDP;
	idp->oidc= oidc;
	idp->plugin= idpFindPlugin (uid);
	if (!idp->plugin) {
		EXT_ERROR("[idp-plugin-missing] fail to find idp=%s", uid);
		goto OnErrorExit;
	}

    // when call idp custom config callback
    if (idp->plugin->configCB) err= idp->plugin->configCB (idp, idpJ);
    else err= idpParseOidcConfig (idp, idpJ, NULL, NULL);
    if (err) goto OnErrorExit;

	return 0;

OnErrorExit:
	return 1;
}

oidcIdpT const *idpParseConfig (oidcCoreHdlT *oidc, json_object *idpsJ) {
	oidcIdpT *idps;
  	int err, count;

	switch (json_object_get_type (idpsJ)) {

		case json_type_array:
			count= (int)json_object_array_length(idpsJ);
			idps = calloc (count+1, sizeof(oidcIdpT));

			for (int idx=0; idx < count; idx ++) {
				json_object *idpJ= json_object_array_get_idx(idpsJ, idx);
				err= idpParseOne (oidc, idpJ, &idps[idx]);
				if (err) {
					EXT_ERROR("[idp-parsing-error] ext=%s", oidc->uid);
					goto OnErrorExit;
				}
			}
			break;

		case json_type_object:
			idps = calloc (2, sizeof(oidcIdpT));
			err= idpParseOne (oidc, idpsJ, &idps[0]);
			if (err) {
				EXT_ERROR("[idp-parsing-error] ext=%s check config", oidc->uid);
				goto OnErrorExit;
			}
			break;

		default:
			EXT_ERROR("[idp-parsing-error] ext=%s idp config should be json/array|object", oidc->uid);
			goto OnErrorExit;
	}
	return idps;

OnErrorExit:
	return NULL;
}

// register IDP login and authentication callback endpoint
int idpRegisterOne (oidcCoreHdlT *oidc, oidcIdpT *idp, struct afb_apiset *declare_set, struct afb_apiset *call_set) {
    int err;

    EXT_DEBUG ("[idp-register] uid=%s login='%s'", idp->uid, idp->statics->aliasLogin);

    // call idp init callback
    if (idp->plugin->registerCB) {
		err= idp->plugin->registerCB(idp, declare_set, call_set);
		if (err) {
		EXT_ERROR("[idp-initcb-fail] idp=%s not avaliable within registered idp plugins", idp->uid);
		goto OnErrorExit;
		}
	}

  return 0;

OnErrorExit:
  EXT_ERROR("[idp-register-error] ext=%s idp=%s config should be json/array|object", oidc->uid, idp->uid);
  return 1;
}

int idpRegisterLogin (oidcCoreHdlT *oidc, oidcIdpT *idp, afb_hsrv *hsrv) {
    int err;
    EXT_DEBUG ("[idp-register-alias] uid=%s login='%s'", idp->uid, idp->statics->aliasLogin);

    err= afb_hsrv_add_handler(hsrv, idp->statics->aliasLogin, idp->plugin->loginCB, idp, EXT_HIGHEST_PRIO);
    if (!err) goto OnErrorExit;
  return 0;

OnErrorExit:
  EXT_ERROR("[idp-register-alias] ext=%s idp=%s config should be json/array|object", oidc->uid, idp->uid);
  return 1;    
}

// Builtin in output formater. Note that first one is used when cmd does not define a format
idpPluginT idpBuiltin[] = {
  {.uid="github" , .info="github public oauth2 idp", .configCB=githubConfigCB, .loginCB=githubLoginCB},
  {.uid= NULL} // must be null terminated
};

// register callback and use it to register core idps
int idpPLuginRegistryInit (void) {

  // Builtin idp don't have UID
  int status= idpPluginRegisterCB (NULL, idpBuiltin);
  return status;
}

