###########################################################################
# Copyright 2015-2025 IoT.bzh Company
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


cmake_minimum_required(VERSION 3.16)

project(
	sec-gate-oidc
	VERSION 1.1.0
	DESCRIPTION "Provide authentication through OpenID"
	HOMEPAGE_URL "https://github.com/iotbzh/sec-gate-oidc"
	LANGUAGES C
)

include(FindPkgConfig)
include(GNUInstallDirs)

set(AFM_APP_DIR ${CMAKE_INSTALL_PREFIX}/redpesk CACHE PATH "Applications directory")

set(APPDIR ${AFM_APP_DIR}/sec-gate-oidc CACHE PATH "sec-gate-oidc directory")

pkg_check_modules(mod0 REQUIRED
	json-c
	libafb>=5.3.8
	libcurl>=7.55.0
	fedid-types>=2.0.0
	afb-binding>=4.0.2
	librp-utils-core
	librp-utils-json-c
)
include_directories(${mod0_INCLUDE_DIRS})
add_compile_options(${mod0_CFLAGS} -fPIC)
add_link_options(${mod0_LDFLAGS})
link_libraries(${mod0_LIBRARIES})

configure_file(sec-gate-oidc.pc.in sec-gate-oidc.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/sec-gate-oidc.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

add_subdirectory(src)
add_subdirectory(data)
