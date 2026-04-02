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

pkg_check_modules(DEPS REQUIRED IMPORTED_TARGET
	json-c
	libafb>=5.3.8
	fedid-types>=2.0.0
	librp-utils-core
	librp-utils-json-c
)

# Define project Targets
add_library(sgoidc SHARED
	fedid-client.c
	oidc-alias.c
	oidc-apis.c
	oidc-core.c
	oidc-idp.c
	oidc-idp-plugin.c
	oidc-login.c
	oidc-session.c
	oidc-state.c
	oidc-utils.c
)

target_include_directories(sgoidc BEFORE PUBLIC
   ${CMAKE_CURRENT_SOURCE_DIR}
   ${DEPS_INCLUDE_DIRS}
)

add_dependencies(sgoidc curl-glue-afb)
target_link_libraries(sgoidc curl-glue-afb PkgConfig::DEPS)

install(TARGETS sgoidc DESTINATION ${CMAKE_INSTALL_LIBDIR})

set(HEADERS
	fedid-client.h
	oidc-alias.h
	oidc-apis.h
	oidc-common.h
	oidc-core.h
	oidc-defaults.h
	oidc-idp.h
	oidc-login.h
	oidc-idp-plugin.h
	oidc-session.h
	oidc-utils.h
)

install(FILES ${HEADERS} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/sec-gate)

