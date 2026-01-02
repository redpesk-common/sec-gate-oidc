###########################################################################
# Copyright (C) 2015-2026 IoT.bzh Company
#
# $RP_BEGIN_LICENSE$
# Commercial License Usage
#  Licensees holding valid commercial IoT.bzh licenses may use this file in
#  accordance with the commercial license agreement provided with the
#  Software or, alternatively, in accordance with the terms contained in
#  a written agreement between you and The IoT.bzh Company. For licensing terms
#  and conditions see https://www.iot.bzh/terms-conditions. For further
#  information use the contact form at https://www.iot.bzh/contact.
#
# GNU General Public License Usage
#  Alternatively, this file may be used under the terms of the GNU General
#  Public license version 3. This license is as published by the Free Software
#  Foundation and appearing in the file LICENSE.GPLv3 included in the packaging
#  of this file. Please review the following information to ensure the GNU
#  General Public License requirements will be met
#  https://www.gnu.org/licenses/gpl-3.0.html.
# $RP_END_LICENSE$
###########################################################################


# Define project Targets
add_library(sec-gate-oidc SHARED
	oidc-builtin-idps.c
	oidc-extension-main.c
	oidc-idsvc.c
	builtin-idps/idp-github.c
	builtin-idps/idp-ldap.c
	builtin-idps/idp-oidc.c
)

add_dependencies(sec-gate-oidc curl-glue-afb sgoidc)
target_link_libraries(sec-gate-oidc curl-glue-afb sgoidc)

target_include_directories(sec-gate-oidc BEFORE PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# Binder exposes a unique public entry point
set_target_properties(sec-gate-oidc
	PROPERTIES
		PREFIX "libafb-"
		SUFFIX "-ext.so"
)
install(TARGETS sec-gate-oidc DESTINATION ${APPDIR}/lib)

