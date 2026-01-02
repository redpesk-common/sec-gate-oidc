# Define project Targets
find_library(PAM_DEVEL pam REQUIRED)

add_library(idp-sgate-pam-auth MODULE oidc-pam.c)

add_dependencies(idp-sgate-pam-auth sgoidc)
target_include_directories(idp-sgate-pam-auth BEFORE PRIVATE .)
target_link_libraries(idp-sgate-pam-auth pam sgoidc)

install(TARGETS idp-sgate-pam-auth
	DESTINATION ${APPDIR}/lib/plugins)

