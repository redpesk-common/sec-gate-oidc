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
    json_object *labelJ;
    char *result;
    const char *head, *first, *last, *val;
    size_t len, out, sz;

    if (src == NULL)
        return NULL;

    result = NULL;
    head = src;
    out = 0;
    len = 0;
    for (;;) {
        /* search the pattern */
        first = strchr(head, '%');
        if (first == NULL) {
            /* no more pattern */
            if (len != 0) {
                /* end of expansion */
                sz = strlen(head);
                memcpy(&result[out], head, sz + 1);
                return result;
            }
            /* compute size, allocates and restart */
            len = out + 1 + strlen(head);
            result = malloc(len);
            if (result == NULL)
                return NULL;
            out = 0;
            head = src;
        }
        else {
            /* a start of pattern exists */
            sz = first - head;
            if (sz > 0) {
                /* inserted text until pattern*/
                if (len != 0)
                    memcpy(&result[out], head, sz);
                out += sz;
            }
            /* start of a pattern */
            last = strchr(first + 1, '%');
            sz = last == NULL ? 0 : last - first;
            if (sz <= 1) {
                /* not a real pattern */
                if (len != 0)
                    result[out] = '%';
                out++;
                head = first + sz + 1;
            }
            else {
                /* got in % the key of a substitution */
                char key[sz]; /* in stack alloc of key */
                memcpy(key, first + 1, sz - 1);
                key[sz - 1] = 0;
                if (json_object_object_get_ex(keysJ, key, &labelJ)) {
                    val = json_object_get_string(labelJ);
                    sz = strlen(val);
                    if (len != 0)
                        memcpy(&result[out],val, sz);
                    out += sz;
                }
                head = last + 1;
            }
        }
    }
}

