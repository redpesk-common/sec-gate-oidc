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

# Utility rule file for project_populate_htdocs.

# Include the progress variables for this target.
include CMakeFiles/project_populate_htdocs.dir/progress.make

CMakeFiles/project_populate_htdocs: package/htdocs/htdocs


package/htdocs/htdocs: conf.d/project/htdocs/htdocs
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/fulup/Workspace/AFB-binder/sec-gate-oidc/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Generating package/htdocs/htdocs"
	mkdir -p /home/fulup/Workspace/AFB-binder/sec-gate-oidc/build/package/htdocs
	touch /home/fulup/Workspace/AFB-binder/sec-gate-oidc/build/package/htdocs
	cp -dr /home/fulup/Workspace/AFB-binder/sec-gate-oidc/build/conf.d/project/htdocs/htdocs/* /home/fulup/Workspace/AFB-binder/sec-gate-oidc/build/package/htdocs 2> /dev/null || cp -d /home/fulup/Workspace/AFB-binder/sec-gate-oidc/build/conf.d/project/htdocs/htdocs /home/fulup/Workspace/AFB-binder/sec-gate-oidc/build/package/htdocs

project_populate_htdocs: CMakeFiles/project_populate_htdocs
project_populate_htdocs: package/htdocs/htdocs
project_populate_htdocs: CMakeFiles/project_populate_htdocs.dir/build.make

.PHONY : project_populate_htdocs

# Rule to build all files generated by this target.
CMakeFiles/project_populate_htdocs.dir/build: project_populate_htdocs

.PHONY : CMakeFiles/project_populate_htdocs.dir/build

CMakeFiles/project_populate_htdocs.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/project_populate_htdocs.dir/cmake_clean.cmake
.PHONY : CMakeFiles/project_populate_htdocs.dir/clean

CMakeFiles/project_populate_htdocs.dir/depend:
	cd /home/fulup/Workspace/AFB-binder/sec-gate-oidc/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/fulup/Workspace/AFB-binder/sec-gate-oidc /home/fulup/Workspace/AFB-binder/sec-gate-oidc /home/fulup/Workspace/AFB-binder/sec-gate-oidc/build /home/fulup/Workspace/AFB-binder/sec-gate-oidc/build /home/fulup/Workspace/AFB-binder/sec-gate-oidc/build/CMakeFiles/project_populate_htdocs.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/project_populate_htdocs.dir/depend

