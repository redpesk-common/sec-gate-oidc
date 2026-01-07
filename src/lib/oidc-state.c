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

#include "oidc-state.h"

#include <stdlib.h>
#include <assert.h>

#include "oidc-idp-plugin.h"

void idpRqtCtxFree(idpRqtCtxT *rqtCtx)
{
    assert(rqtCtx->ucount >= 0);
    rqtCtx->ucount--;

    if (rqtCtx->ucount < 0) {
        if (rqtCtx->token)
            free(rqtCtx->token);
        free(rqtCtx);
    }
}

// session timeout, reset LOA
void fedidsessionReset(oidcSessionT *session, const oidcProfileT *idpProfile)
{
    int err;
    int count = -1;

    // reset session and alias LOA (this will force authentication)
    oidcSessionSetActualLOA(session, 0);
    oidcSessionSetNextCheck(session, 0);
    EXT_DEBUG("[fedid-session-reset] logout/timeout session uuid=%s ?",
              oidcSessionUUID(session));

    if (idpProfile) {
        if (idpProfile->idp->plugin && idpProfile->idp->plugin->resetSession) {
            void *ctx = oidcSessionGetOpaqueData(session);
            if (ctx != NULL) {
                idpProfile->idp->plugin->resetSession(idpProfile, ctx);
                oidcSessionSetOpaqueData(session, NULL);
            }
        }

        const oidGlobalsT *globals = oidcCoreGlobals(idpProfile->idp->oidc);
        count = oidcSessionEventPush(
            session, "{ss ss ss* ss*}", "status", "loa-reset", "home",
            globals->homeUrl ?: "/", "login", globals->loginUrl, "error",
            globals->errorUrl);
        if (!count)
            EXT_DEBUG("[fedid-session-reset] no client subscribed uuid=%s ?",
                      oidcSessionUUID(session));
    }
}

