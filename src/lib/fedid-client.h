/*
 * Copyright (C) 2015-2021 IoT.bzh Company
 * Author dev-team@iot.bzh
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

#pragma once

#include <fedid-types.h>
#include <libafb/afb-v4.h>

void fedIdClientSubCall(
                afb_req_t req,
                const char *verbname,
                unsigned nparams,
                afb_data_t const params[],
                afb_subcall_callback_t callback,
                void *closure);

void fedIdClientCall(
                afb_api_t api,
                const char *verbname,
                unsigned nparams,
                afb_data_t const params[],
                afb_call_callback_t callback,
                void *closure);

int fedIdClientCallSync(
                afb_api_t api,
                const char *verbname,
                unsigned nparams,
                afb_data_t const params[],
		int *status,
		unsigned *nresults,
		afb_data_t results[]);


void fedIdClientSocialCheck(
                afb_api_t api,
		fedSocialRawT *fedSoc,
		void (*callback)(void*,int,fedSocialRawT*,fedUserRawT*),
		void *closure);

void fedIdClientSocialCheck(
        afb_api_t api,
        fedSocialRawT *fedSoc,
        void (*callback)(void*,int,fedSocialRawT*,fedUserRawT*),
        void *closure);
