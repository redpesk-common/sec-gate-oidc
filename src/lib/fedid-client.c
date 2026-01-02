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

#include "fedid-client.h"

#include <stdlib.h>

#include <fedid-types-glue.h>

// local or remote federated identity service api name
#define API_OIDC_USR_SVC "fedid"

/*
 * Wrapper for subccalling API fedid
 */
void fedIdClientSubCall(
                afb_req_t req,
                const char *verbname,
                unsigned nparams,
                afb_data_t const params[],
                afb_subcall_callback_t callback,
                void *closure)
{
    afb_req_subcall(req, API_OIDC_USR_SVC, verbname, nparams, params,
                    afb_req_subcall_on_behalf, callback, closure);
}

void fedIdClientCall(
                afb_api_t api,
                const char *verbname,
                unsigned nparams,
                afb_data_t const params[],
                afb_call_callback_t callback,
                void *closure)
{
    afb_api_v4_call_hookable(api, API_OIDC_USR_SVC, verbname, nparams, params,
                             callback, closure);
}

int fedIdClientCallSync(
                afb_api_t api,
                const char *verbname,
                unsigned nparams,
                afb_data_t const params[],
        int *status,
        unsigned *nresults,
        afb_data_t results[])
{
    return afb_api_v4_call_sync_hookable(api, API_OIDC_USR_SVC, verbname, nparams, params,
                             status, nresults, results);
}

/****************************************************************
 * SECTION for wrapping calls to "social-check"
 */

/* hold request while sending request to fedid binding */
struct social_check_data
{
    /* the fedsocial to be checked */
    fedSocialRawT *fedSoc;
    /* the callback receiving the result */
    void (*callback)(void*,int,fedSocialRawT*,fedUserRawT*);
    /* closure for the callback */
    void *closure;
};

/* calls the callback */
static void social_check_reply(
                        struct social_check_data *scd,
                        int status,
                        fedUserRawT *fedUsr)
{
    // call it
    scd->callback(scd->closure, status, scd->fedSoc, fedUsr);

    // release resources
    fedSocialUnRef(scd->fedSoc);
    fedUserUnRef(fedUsr);
    free(scd);
}

/* verb call callback */
static void social_check_cb(
                        void *closure,
                        int status,
                        unsigned argc,
                        afb_data_x4_t const argv[],
                        struct afb_api_v4 *api)
{
    struct social_check_data *scd = closure;
    fedUserRawT *fedUsr = NULL;

    /* get the federated user if existing */
    if (status == 1) {
        afb_data_x4_t data;
        int rc = afb_data_convert(argv[0], fedUserObjType, &data);
        if (rc < 0)
            // handle error
            status = AFB_ERRNO_INTERNAL_ERROR;
        else {
            /* extract the structure */
            fedUsr = (fedUserRawT *)afb_data_ro_pointer(data);
            fedUsr = fedUserAddRef(fedUsr);
            afb_data_unref(data);
        }
    }
    /* send the reply */
    social_check_reply(scd, status, fedUsr);
}

// fedSoc should remain valid after subcall for fedsocial cookie
void fedIdClientSocialCheck(
        afb_api_t api,
        fedSocialRawT *fedSoc,
        void (*callback)(void*,int,fedSocialRawT*,fedUserRawT*),
        void *closure)
{
    int rc;
    afb_data_x4_t data;
    struct social_check_data *scd;

    /* prepare the call */
    scd = malloc(sizeof *scd);
    if (scd == NULL)
        callback(closure, AFB_ERRNO_OUT_OF_MEMORY, fedSoc, NULL);
    else {
        scd->fedSoc = fedSocialAddRef(fedSoc);
        scd->callback = callback;
        scd->closure = closure;

        /* wrap the fedSoc in a data */
        rc = afb_data_create_raw(&data, fedSocialObjType, fedSoc, 0, NULL, NULL);
        if (rc < 0)
            social_check_reply(scd, AFB_ERRNO_OUT_OF_MEMORY, NULL);
        else
            /* call fedid binding */
            fedIdClientCall(api, "social-check", 1, &data, social_check_cb, scd);
    }
}

