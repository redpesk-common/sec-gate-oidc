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

# Utility rule file for afb-sgate-oidc_build_done.

# Include the progress variables for this target.
include CMakeFiles/afb-sgate-oidc_build_done.dir/progress.make

CMakeFiles/afb-sgate-oidc_build_done:
	/usr/bin/cmake -E cmake_echo_color --cyan ++\ Debug:\ afb-binder\ --name=afb-oidc\ --config=../conf.d/project/etc/oidc-config.json\ --rootdir=../conf.d/project/htdocs\ --verbose\ #\ http://localhost:1234/devtools/index.html

afb-sgate-oidc_build_done: CMakeFiles/afb-sgate-oidc_build_done
afb-sgate-oidc_build_done: CMakeFiles/afb-sgate-oidc_build_done.dir/build.make

.PHONY : afb-sgate-oidc_build_done

# Rule to build all files generated by this target.
CMakeFiles/afb-sgate-oidc_build_done.dir/build: afb-sgate-oidc_build_done

.PHONY : CMakeFiles/afb-sgate-oidc_build_done.dir/build

CMakeFiles/afb-sgate-oidc_build_done.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/afb-sgate-oidc_build_done.dir/cmake_clean.cmake
.PHONY : CMakeFiles/afb-sgate-oidc_build_done.dir/clean

CMakeFiles/afb-sgate-oidc_build_done.dir/depend:
	cd /home/fulup/Workspace/AFB-binder/sec-gate-oidc/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/fulup/Workspace/AFB-binder/sec-gate-oidc /home/fulup/Workspace/AFB-binder/sec-gate-oidc /home/fulup/Workspace/AFB-binder/sec-gate-oidc/build /home/fulup/Workspace/AFB-binder/sec-gate-oidc/build /home/fulup/Workspace/AFB-binder/sec-gate-oidc/build/CMakeFiles/afb-sgate-oidc_build_done.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/afb-sgate-oidc_build_done.dir/depend

