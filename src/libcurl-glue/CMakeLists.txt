
# Define project Targets
add_library(curl-glue-afb STATIC curl-client.c http-gluafb.c)

# compilation include path
target_include_directories(curl-glue-afb INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
