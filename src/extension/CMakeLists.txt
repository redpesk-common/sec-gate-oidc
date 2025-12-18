###########################################################################
# Copyright 201 IoT.bzh
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
###########################################################################

add_subdirectory(lib)
add_subdirectory(builtin-idps)

# Define project Targets
add_library(sec-gate-oidc SHARED
	oidc-alias.c
	oidc-apis.c
	oidc-builtin-idps.c
	oidc-core.c
	oidc-extension-main.c
	oidc-fedid.c
	oidc-idp.c
	oidc-idp-plugin.c
	oidc-idsvc.c
)

add_dependencies(sec-gate-oidc curl-glue-afb builtin-idps sgoidc)
target_link_libraries(sec-gate-oidc curl-glue-afb builtin-idps sgoidc)

target_include_directories(sec-gate-oidc BEFORE PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/lib ${CMAKE_CURRENT_SOURCE_DIR})

# Binder exposes a unique public entry point
set_target_properties(sec-gate-oidc
	PROPERTIES
		PREFIX "libafb-"
		SUFFIX "-ext.so"
)
install(TARGETS sec-gate-oidc DESTINATION ${APPDIR}/lib)

install(FILES
		oidc-alias.h
		oidc-apis.h
		oidc-core.h
		oidc-defaults.h
		oidc-fedid.h
		oidc-idp.h
		oidc-idsvc.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

