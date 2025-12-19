# Define project Targets
add_library(idp-sgate-pcscd-auth MODULE oidc-pcsc.c)

add_dependencies(idp-sgate-pcscd-auth curl-glue-afb sec-gate-oidc sgoidc)
target_include_directories(idp-sgate-pcscd-auth BEFORE PRIVATE .)
target_link_libraries(idp-sgate-pcscd-auth pcscd-glue sec-gate-oidc sgoidc)

install(TARGETS idp-sgate-pcscd-auth
	DESTINATION ${APPDIR}/lib/plugins)

