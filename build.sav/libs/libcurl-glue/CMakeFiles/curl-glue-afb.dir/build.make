# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.19

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Disable VCS-based implicit rules.
% : %,v


# Disable VCS-based implicit rules.
% : RCS/%


# Disable VCS-based implicit rules.
% : RCS/%,v


# Disable VCS-based implicit rules.
% : SCCS/s.%


# Disable VCS-based implicit rules.
% : s.%


.SUFFIXES: .hpux_make_needs_suffix_list


# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/fulup/Workspace/AFB-binder/sec-gate-oidc

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/fulup/Workspace/AFB-binder/sec-gate-oidc/build

# Include any dependencies generated for this target.
include libs/libcurl-glue/CMakeFiles/curl-glue-afb.dir/depend.make

# Include the progress variables for this target.
include libs/libcurl-glue/CMakeFiles/curl-glue-afb.dir/progress.make

# Include the compile flags for this target's objects.
include libs/libcurl-glue/CMakeFiles/curl-glue-afb.dir/flags.make

libs/libcurl-glue/CMakeFiles/curl-glue-afb.dir/curl-client.c.o: libs/libcurl-glue/CMakeFiles/curl-glue-afb.dir/flags.make
libs/libcurl-glue/CMakeFiles/curl-glue-afb.dir/curl-client.c.o: ../libs/libcurl-glue/curl-client.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/fulup/Workspace/AFB-binder/sec-gate-oidc/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object libs/libcurl-glue/CMakeFiles/curl-glue-afb.dir/curl-client.c.o"
	cd /home/fulup/Workspace/AFB-binder/sec-gate-oidc/build/libs/libcurl-glue && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/curl-glue-afb.dir/curl-client.c.o -c /home/fulup/Workspace/AFB-binder/sec-gate-oidc/libs/libcurl-glue/curl-client.c

libs/libcurl-glue/CMakeFiles/curl-glue-afb.dir/curl-client.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/curl-glue-afb.dir/curl-client.c.i"
	cd /home/fulup/Workspace/AFB-binder/sec-gate-oidc/build/libs/libcurl-glue && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/fulup/Workspace/AFB-binder/sec-gate-oidc/libs/libcurl-glue/curl-client.c > CMakeFiles/curl-glue-afb.dir/curl-client.c.i

libs/libcurl-glue/CMakeFiles/curl-glue-afb.dir/curl-client.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/curl-glue-afb.dir/curl-client.c.s"
	cd /home/fulup/Workspace/AFB-binder/sec-gate-oidc/build/libs/libcurl-glue && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/fulup/Workspace/AFB-binder/sec-gate-oidc/libs/libcurl-glue/curl-client.c -o CMakeFiles/curl-glue-afb.dir/curl-client.c.s

libs/libcurl-glue/CMakeFiles/curl-glue-afb.dir/http-gluafb.c.o: libs/libcurl-glue/CMakeFiles/curl-glue-afb.dir/flags.make
libs/libcurl-glue/CMakeFiles/curl-glue-afb.dir/http-gluafb.c.o: ../libs/libcurl-glue/http-gluafb.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/fulup/Workspace/AFB-binder/sec-gate-oidc/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object libs/libcurl-glue/CMakeFiles/curl-glue-afb.dir/http-gluafb.c.o"
	cd /home/fulup/Workspace/AFB-binder/sec-gate-oidc/build/libs/libcurl-glue && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/curl-glue-afb.dir/http-gluafb.c.o -c /home/fulup/Workspace/AFB-binder/sec-gate-oidc/libs/libcurl-glue/http-gluafb.c

libs/libcurl-glue/CMakeFiles/curl-glue-afb.dir/http-gluafb.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/curl-glue-afb.dir/http-gluafb.c.i"
	cd /home/fulup/Workspace/AFB-binder/sec-gate-oidc/build/libs/libcurl-glue && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/fulup/Workspace/AFB-binder/sec-gate-oidc/libs/libcurl-glue/http-gluafb.c > CMakeFiles/curl-glue-afb.dir/http-gluafb.c.i

libs/libcurl-glue/CMakeFiles/curl-glue-afb.dir/http-gluafb.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/curl-glue-afb.dir/http-gluafb.c.s"
	cd /home/fulup/Workspace/AFB-binder/sec-gate-oidc/build/libs/libcurl-glue && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/fulup/Workspace/AFB-binder/sec-gate-oidc/libs/libcurl-glue/http-gluafb.c -o CMakeFiles/curl-glue-afb.dir/http-gluafb.c.s

# Object files for target curl-glue-afb
curl__glue__afb_OBJECTS = \
"CMakeFiles/curl-glue-afb.dir/curl-client.c.o" \
"CMakeFiles/curl-glue-afb.dir/http-gluafb.c.o"

# External object files for target curl-glue-afb
curl__glue__afb_EXTERNAL_OBJECTS =

libs/libcurl-glue/libcurl-glue-afb.a: libs/libcurl-glue/CMakeFiles/curl-glue-afb.dir/curl-client.c.o
libs/libcurl-glue/libcurl-glue-afb.a: libs/libcurl-glue/CMakeFiles/curl-glue-afb.dir/http-gluafb.c.o
libs/libcurl-glue/libcurl-glue-afb.a: libs/libcurl-glue/CMakeFiles/curl-glue-afb.dir/build.make
libs/libcurl-glue/libcurl-glue-afb.a: libs/libcurl-glue/CMakeFiles/curl-glue-afb.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/fulup/Workspace/AFB-binder/sec-gate-oidc/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking C static library libcurl-glue-afb.a"
	cd /home/fulup/Workspace/AFB-binder/sec-gate-oidc/build/libs/libcurl-glue && $(CMAKE_COMMAND) -P CMakeFiles/curl-glue-afb.dir/cmake_clean_target.cmake
	cd /home/fulup/Workspace/AFB-binder/sec-gate-oidc/build/libs/libcurl-glue && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/curl-glue-afb.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
libs/libcurl-glue/CMakeFiles/curl-glue-afb.dir/build: libs/libcurl-glue/libcurl-glue-afb.a

.PHONY : libs/libcurl-glue/CMakeFiles/curl-glue-afb.dir/build

libs/libcurl-glue/CMakeFiles/curl-glue-afb.dir/clean:
	cd /home/fulup/Workspace/AFB-binder/sec-gate-oidc/build/libs/libcurl-glue && $(CMAKE_COMMAND) -P CMakeFiles/curl-glue-afb.dir/cmake_clean.cmake
.PHONY : libs/libcurl-glue/CMakeFiles/curl-glue-afb.dir/clean

libs/libcurl-glue/CMakeFiles/curl-glue-afb.dir/depend:
	cd /home/fulup/Workspace/AFB-binder/sec-gate-oidc/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/fulup/Workspace/AFB-binder/sec-gate-oidc /home/fulup/Workspace/AFB-binder/sec-gate-oidc/libs/libcurl-glue /home/fulup/Workspace/AFB-binder/sec-gate-oidc/build /home/fulup/Workspace/AFB-binder/sec-gate-oidc/build/libs/libcurl-glue /home/fulup/Workspace/AFB-binder/sec-gate-oidc/build/libs/libcurl-glue/CMakeFiles/curl-glue-afb.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : libs/libcurl-glue/CMakeFiles/curl-glue-afb.dir/depend

