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

# Define project Targets
add_library(sgoidc SHARED
	oidc-session.c
	oidc-utils.c
)

target_include_directories(sgoidc BEFORE PUBLIC
   ${CMAKE_CURRENT_SOURCE_DIR}
   ${CMAKE_CURRENT_SOURCE_DIR}/..  # TODO remove that
)

add_dependencies(sgoidc curl-glue-afb)
target_link_libraries(sgoidc curl-glue-afb)

install(TARGETS sgoidc DESTINATION ${CMAKE_INSTALL_LIBDIR})

install(FILES
		oidc-session.h
		oidc-utils.h
        DESTINATION
		${CMAKE_INSTALL_INCLUDEDIR}
)

