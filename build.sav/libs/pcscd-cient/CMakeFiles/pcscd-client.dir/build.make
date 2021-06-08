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
include libs/pcscd-cient/CMakeFiles/pcscd-client.dir/depend.make

# Include the progress variables for this target.
include libs/pcscd-cient/CMakeFiles/pcscd-client.dir/progress.make

# Include the compile flags for this target's objects.
include libs/pcscd-cient/CMakeFiles/pcscd-client.dir/flags.make

libs/pcscd-cient/CMakeFiles/pcscd-client.dir/client-pcsc.c.o: libs/pcscd-cient/CMakeFiles/pcscd-client.dir/flags.make
libs/pcscd-cient/CMakeFiles/pcscd-client.dir/client-pcsc.c.o: ../libs/pcscd-cient/client-pcsc.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/fulup/Workspace/AFB-binder/sec-gate-oidc/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object libs/pcscd-cient/CMakeFiles/pcscd-client.dir/client-pcsc.c.o"
	cd /home/fulup/Workspace/AFB-binder/sec-gate-oidc/build/libs/pcscd-cient && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/pcscd-client.dir/client-pcsc.c.o -c /home/fulup/Workspace/AFB-binder/sec-gate-oidc/libs/pcscd-cient/client-pcsc.c

libs/pcscd-cient/CMakeFiles/pcscd-client.dir/client-pcsc.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/pcscd-client.dir/client-pcsc.c.i"
	cd /home/fulup/Workspace/AFB-binder/sec-gate-oidc/build/libs/pcscd-cient && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/fulup/Workspace/AFB-binder/sec-gate-oidc/libs/pcscd-cient/client-pcsc.c > CMakeFiles/pcscd-client.dir/client-pcsc.c.i

libs/pcscd-cient/CMakeFiles/pcscd-client.dir/client-pcsc.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/pcscd-client.dir/client-pcsc.c.s"
	cd /home/fulup/Workspace/AFB-binder/sec-gate-oidc/build/libs/pcscd-cient && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/fulup/Workspace/AFB-binder/sec-gate-oidc/libs/pcscd-cient/client-pcsc.c -o CMakeFiles/pcscd-client.dir/client-pcsc.c.s

# Object files for target pcscd-client
pcscd__client_OBJECTS = \
"CMakeFiles/pcscd-client.dir/client-pcsc.c.o"

# External object files for target pcscd-client
pcscd__client_EXTERNAL_OBJECTS =

libs/pcscd-cient/pcscd-client: libs/pcscd-cient/CMakeFiles/pcscd-client.dir/client-pcsc.c.o
libs/pcscd-cient/pcscd-client: libs/pcscd-cient/CMakeFiles/pcscd-client.dir/build.make
libs/pcscd-cient/pcscd-client: libs/pcscd-cient/libpcscd-glue.a
libs/pcscd-cient/pcscd-client: /usr/lib64/libpcsclite.so
libs/pcscd-cient/pcscd-client: libs/pcscd-cient/CMakeFiles/pcscd-client.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/fulup/Workspace/AFB-binder/sec-gate-oidc/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable pcscd-client"
	cd /home/fulup/Workspace/AFB-binder/sec-gate-oidc/build/libs/pcscd-cient && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/pcscd-client.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
libs/pcscd-cient/CMakeFiles/pcscd-client.dir/build: libs/pcscd-cient/pcscd-client

.PHONY : libs/pcscd-cient/CMakeFiles/pcscd-client.dir/build

libs/pcscd-cient/CMakeFiles/pcscd-client.dir/clean:
	cd /home/fulup/Workspace/AFB-binder/sec-gate-oidc/build/libs/pcscd-cient && $(CMAKE_COMMAND) -P CMakeFiles/pcscd-client.dir/cmake_clean.cmake
.PHONY : libs/pcscd-cient/CMakeFiles/pcscd-client.dir/clean

libs/pcscd-cient/CMakeFiles/pcscd-client.dir/depend:
	cd /home/fulup/Workspace/AFB-binder/sec-gate-oidc/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/fulup/Workspace/AFB-binder/sec-gate-oidc /home/fulup/Workspace/AFB-binder/sec-gate-oidc/libs/pcscd-cient /home/fulup/Workspace/AFB-binder/sec-gate-oidc/build /home/fulup/Workspace/AFB-binder/sec-gate-oidc/build/libs/pcscd-cient /home/fulup/Workspace/AFB-binder/sec-gate-oidc/build/libs/pcscd-cient/CMakeFiles/pcscd-client.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : libs/pcscd-cient/CMakeFiles/pcscd-client.dir/depend

