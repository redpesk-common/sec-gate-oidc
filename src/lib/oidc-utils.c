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

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "oidc-utils.h"

// replace any %key% with its coresponding json value (warning: json is case
// sensitive)
char *utilsExpandJson(const char *src, json_object *keysJ)
{
    int srcIdx, destIdx = 0, labelIdx, expanded = 0;
    char dst[OIDC_MAX_ARG_LEN], label[OIDC_MAX_ARG_LABEL];
    char *response;
    json_object *labelJ;
    char separator = -1;

    if (!keysJ || !src)
        goto OnErrorExit;

    for (srcIdx = 0; src[srcIdx]; srcIdx++) {
        // replace "%%" by '%'
        if (src[srcIdx] == '%') {
            separator = src[srcIdx];
            if (src[srcIdx + 1] == separator) {
                dst[destIdx++] = src[srcIdx];
                srcIdx++;
                continue;
            }
        }

        if (src[srcIdx] != separator) {
            dst[destIdx++] = src[srcIdx];
        }
        else {
            expanded = 1;
            labelIdx = 0;
            // extract expansion label for source argument
            for (srcIdx = srcIdx + 1; src[srcIdx]; srcIdx++) {
                if (src[srcIdx] != separator) {
                    label[labelIdx++] = src[srcIdx];
                    if (labelIdx == OIDC_MAX_ARG_LABEL)
                        goto OnErrorExit;
                }
                else
                    break;
            }

            // close label string and remove trailling '%' from destination
            label[labelIdx] = '\0';

            // search for expansion label within keysJ
            labelJ = json_object_object_get(keysJ, label);
            if (!labelJ) {
                if (separator == '%')
                    goto OnErrorExit;
            }
            else {
                // add label value to destination argument
                const char *labelVal = json_object_get_string(labelJ);
                for (labelIdx = 0; labelVal[labelIdx]; labelIdx++) {
                    dst[destIdx++] = labelVal[labelIdx];
                }
            }
        }
    }
    dst[destIdx++] = '\0';

    // when expanded make a copy of dst into params
    if (!expanded) {
        response = strdup(src);
    }
    else {
        // fprintf (stderr, "utilsExpandJson: '%s' => '%s'\n", src, dst);
        response = strdup(dst);
    }

    return response;

OnErrorExit:
    return NULL;
}
