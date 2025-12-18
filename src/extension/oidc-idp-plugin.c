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

#include <assert.h>
#include <dlfcn.h>
#include <string.h>

#include <rp-utils/rp-enum-map.h>
#include <rp-utils/rp-jsonc.h>

#include <libafb/afb-core.h>
#include <libafb/afb-http.h>
#include <libafb/afb-v4.h>

#include "oidc-core.h"
#include "oidc-fedid.h"
#include "oidc-idp-plugin.h"
#include "oidc-idp.h"

#define OIDC_PLUGIN_INIT "oidcPluginInit"

typedef struct idpRegistryS
{
    struct idpRegistryS *next;
    const char *type;
    const idpPluginT *plugin;
} idpRegistryT;

// registry holds a linked list of core+pugins idps
static idpRegistryT *registryHead = NULL;

// search for a plugin idps/decoders CB list
const idpPluginT *idpPluginFind(const char *type)
{
    idpRegistryT *registryIdx = registryHead;
    while (registryIdx != NULL) {
        if (strcasecmp(type, registryIdx->type) == 0)
            return registryIdx->plugin;
        registryIdx = registryIdx->next;
    }
    return NULL;
}

// add a new plugin idp to the registry
int idpPluginRegister(const idpPluginT *plugin)
{
    idpRegistryT *registryIdx, *registryEntry;

    // create holding hat for idp/decoder CB
    registryEntry = (idpRegistryT *)calloc(1, sizeof(idpRegistryT));
    registryEntry->type = plugin->uid;
    registryEntry->plugin = plugin;

    // if not 1st idp insert at the end of the chain
    if (!registryHead) {
        registryHead = registryEntry;
    }
    else {
        for (registryIdx = registryHead; registryIdx->next;
             registryIdx = registryIdx->next)
            ;
        registryIdx->next = registryEntry;
    }

    return 0;
}

// parse one plugin configuration
int idpPluginParseOne(oidcCoreHdlT *oidc, json_object *pluginJ)
{
    int rc;
    json_object *obj;
    char *copy, *head, *next;
    void *handle;
    oidcPluginInitCbT registerPluginCB;

    // get the load path copy
    if (!json_object_object_get_ex(pluginJ, "ldpath", &obj) ||
        !json_object_is_type(obj, json_type_string)) {
        EXT_ERROR("[oidc-idp] idp plugin config requires a 'ldpath'");
        return -1;
    }
    copy = strdup(json_object_get_string(obj));
    if (copy == NULL) {
        EXT_ERROR("[oidc-idp] out of memory");
        return -1;
    }
    // iterate over paths of the copy
    next = NULL;
    head = strtok_r(copy, ":", &next);
    while (head != NULL) {
        handle = dlopen(head, RTLD_NOW | RTLD_LOCAL);
        if (handle != NULL) {
            registerPluginCB = dlsym(handle, OIDC_PLUGIN_INIT);
            if (registerPluginCB == NULL)
                EXT_WARNING("[oidc-idp] no symbol " OIDC_PLUGIN_INIT
                            " in %s, skipping",
                            head);
            else {
                rc = registerPluginCB(oidc);
                if (rc == 0) {
                    EXT_INFO("[oidc-idp] using plugin %s", head);
                    free(copy);
                    return 0;
                }
                EXT_WARNING("[oidc-idp] fail to initialize plugin %s, skipping",
                            head);
            }
            dlclose(handle);
        }
        head = strtok_r(NULL, ":", &next);
    }
    EXT_ERROR("[oidc-idp] no available plugin from %s",
              json_object_get_string(obj));
    copy = strdup(json_object_get_string(obj));
    free(copy);
    return -1;
}

// Parse the configuration object for idp plugins
int idpPluginsParseConfig(oidcCoreHdlT *oidc, json_object *pluginsJ)
{
    int err, count, idx;

    switch (json_object_get_type(pluginsJ)) {
    case json_type_array:
        count = (int)json_object_array_length(pluginsJ);
        for (idx = 0; idx < count; idx++) {
            err = idpPluginParseOne(oidc,
                                    json_object_array_get_idx(pluginsJ, idx));
            if (err)
                return -1;
        }
        break;

    case json_type_object:
        err = idpPluginParseOne(oidc, pluginsJ);
        if (err)
            return -1;
        break;

    default:
        EXT_ERROR("[oidc-idp] Bad idp-plugins config object");
        return -1;
    }
    return 0;
}
