# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.17

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


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /home/ec2-user/.local/bin/cmake

# The command to remove a file.
RM = /home/ec2-user/.local/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/ec2-user/zkboo-r1cs

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/ec2-user/zkboo-r1cs

# Include any dependencies generated for this target.
include zkboo/CMakeFiles/Prover.dir/depend.make

# Include the progress variables for this target.
include zkboo/CMakeFiles/Prover.dir/progress.make

# Include the compile flags for this target's objects.
include zkboo/CMakeFiles/Prover.dir/flags.make

zkboo/CMakeFiles/Prover.dir/prover.cc.o: zkboo/CMakeFiles/Prover.dir/flags.make
zkboo/CMakeFiles/Prover.dir/prover.cc.o: zkboo/prover.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ec2-user/zkboo-r1cs/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object zkboo/CMakeFiles/Prover.dir/prover.cc.o"
	cd /home/ec2-user/zkboo-r1cs/zkboo && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/Prover.dir/prover.cc.o -c /home/ec2-user/zkboo-r1cs/zkboo/prover.cc

zkboo/CMakeFiles/Prover.dir/prover.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/Prover.dir/prover.cc.i"
	cd /home/ec2-user/zkboo-r1cs/zkboo && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/ec2-user/zkboo-r1cs/zkboo/prover.cc > CMakeFiles/Prover.dir/prover.cc.i

zkboo/CMakeFiles/Prover.dir/prover.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/Prover.dir/prover.cc.s"
	cd /home/ec2-user/zkboo-r1cs/zkboo && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/ec2-user/zkboo-r1cs/zkboo/prover.cc -o CMakeFiles/Prover.dir/prover.cc.s

zkboo/CMakeFiles/Prover.dir/view.cc.o: zkboo/CMakeFiles/Prover.dir/flags.make
zkboo/CMakeFiles/Prover.dir/view.cc.o: zkboo/view.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ec2-user/zkboo-r1cs/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object zkboo/CMakeFiles/Prover.dir/view.cc.o"
	cd /home/ec2-user/zkboo-r1cs/zkboo && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/Prover.dir/view.cc.o -c /home/ec2-user/zkboo-r1cs/zkboo/view.cc

zkboo/CMakeFiles/Prover.dir/view.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/Prover.dir/view.cc.i"
	cd /home/ec2-user/zkboo-r1cs/zkboo && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/ec2-user/zkboo-r1cs/zkboo/view.cc > CMakeFiles/Prover.dir/view.cc.i

zkboo/CMakeFiles/Prover.dir/view.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/Prover.dir/view.cc.s"
	cd /home/ec2-user/zkboo-r1cs/zkboo && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/ec2-user/zkboo-r1cs/zkboo/view.cc -o CMakeFiles/Prover.dir/view.cc.s

zkboo/CMakeFiles/Prover.dir/common.cc.o: zkboo/CMakeFiles/Prover.dir/flags.make
zkboo/CMakeFiles/Prover.dir/common.cc.o: zkboo/common.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ec2-user/zkboo-r1cs/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object zkboo/CMakeFiles/Prover.dir/common.cc.o"
	cd /home/ec2-user/zkboo-r1cs/zkboo && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/Prover.dir/common.cc.o -c /home/ec2-user/zkboo-r1cs/zkboo/common.cc

zkboo/CMakeFiles/Prover.dir/common.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/Prover.dir/common.cc.i"
	cd /home/ec2-user/zkboo-r1cs/zkboo && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/ec2-user/zkboo-r1cs/zkboo/common.cc > CMakeFiles/Prover.dir/common.cc.i

zkboo/CMakeFiles/Prover.dir/common.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/Prover.dir/common.cc.s"
	cd /home/ec2-user/zkboo-r1cs/zkboo && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/ec2-user/zkboo-r1cs/zkboo/common.cc -o CMakeFiles/Prover.dir/common.cc.s

zkboo/CMakeFiles/Prover.dir/verifier.cc.o: zkboo/CMakeFiles/Prover.dir/flags.make
zkboo/CMakeFiles/Prover.dir/verifier.cc.o: zkboo/verifier.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ec2-user/zkboo-r1cs/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object zkboo/CMakeFiles/Prover.dir/verifier.cc.o"
	cd /home/ec2-user/zkboo-r1cs/zkboo && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/Prover.dir/verifier.cc.o -c /home/ec2-user/zkboo-r1cs/zkboo/verifier.cc

zkboo/CMakeFiles/Prover.dir/verifier.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/Prover.dir/verifier.cc.i"
	cd /home/ec2-user/zkboo-r1cs/zkboo && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/ec2-user/zkboo-r1cs/zkboo/verifier.cc > CMakeFiles/Prover.dir/verifier.cc.i

zkboo/CMakeFiles/Prover.dir/verifier.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/Prover.dir/verifier.cc.s"
	cd /home/ec2-user/zkboo-r1cs/zkboo && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/ec2-user/zkboo-r1cs/zkboo/verifier.cc -o CMakeFiles/Prover.dir/verifier.cc.s

# Object files for target Prover
Prover_OBJECTS = \
"CMakeFiles/Prover.dir/prover.cc.o" \
"CMakeFiles/Prover.dir/view.cc.o" \
"CMakeFiles/Prover.dir/common.cc.o" \
"CMakeFiles/Prover.dir/verifier.cc.o"

# External object files for target Prover
Prover_EXTERNAL_OBJECTS =

zkboo/libProver.a: zkboo/CMakeFiles/Prover.dir/prover.cc.o
zkboo/libProver.a: zkboo/CMakeFiles/Prover.dir/view.cc.o
zkboo/libProver.a: zkboo/CMakeFiles/Prover.dir/common.cc.o
zkboo/libProver.a: zkboo/CMakeFiles/Prover.dir/verifier.cc.o
zkboo/libProver.a: zkboo/CMakeFiles/Prover.dir/build.make
zkboo/libProver.a: zkboo/CMakeFiles/Prover.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/ec2-user/zkboo-r1cs/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Linking CXX static library libProver.a"
	cd /home/ec2-user/zkboo-r1cs/zkboo && $(CMAKE_COMMAND) -P CMakeFiles/Prover.dir/cmake_clean_target.cmake
	cd /home/ec2-user/zkboo-r1cs/zkboo && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/Prover.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
zkboo/CMakeFiles/Prover.dir/build: zkboo/libProver.a

.PHONY : zkboo/CMakeFiles/Prover.dir/build

zkboo/CMakeFiles/Prover.dir/clean:
	cd /home/ec2-user/zkboo-r1cs/zkboo && $(CMAKE_COMMAND) -P CMakeFiles/Prover.dir/cmake_clean.cmake
.PHONY : zkboo/CMakeFiles/Prover.dir/clean

zkboo/CMakeFiles/Prover.dir/depend:
	cd /home/ec2-user/zkboo-r1cs && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/ec2-user/zkboo-r1cs /home/ec2-user/zkboo-r1cs/zkboo /home/ec2-user/zkboo-r1cs /home/ec2-user/zkboo-r1cs/zkboo /home/ec2-user/zkboo-r1cs/zkboo/CMakeFiles/Prover.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : zkboo/CMakeFiles/Prover.dir/depend

