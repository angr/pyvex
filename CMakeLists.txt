cmake_minimum_required(VERSION 3.15)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

project(pyvex LANGUAGES C CXX)

# Find Python and nanobind
find_package(Python COMPONENTS Interpreter Development REQUIRED)
find_package(nanobind CONFIG REQUIRED)

# Set the output directory for built libraries
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/pyvex/lib)

# Set the C standard to C99
set(CMAKE_C_STANDARD 99)

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/pyvex/include
    ${CMAKE_SOURCE_DIR}/pyvex_c
    ${CMAKE_SOURCE_DIR}/vex/pub
)

# Source files for the pyvex C library
set(PYVEX_SRC
    pyvex_c/pyvex.c
    pyvex_c/analysis.c
    pyvex_c/logging.c
    pyvex_c/postprocess.c
	pyvex_c/typeenv.cpp
    pyvex_c/const.cpp
    pyvex_c/enums.cpp
    pyvex_c/stmt.cpp
    pyvex_c/expr.cpp
    pyvex_c/block.cpp
	pyvex_c/module.cpp
	pyvex_c/arches.cpp
)

# Source files for the VEX C library
set(VEX_SRC
	vex/priv/ir_defs.c
	vex/priv/ir_match.c
	vex/priv/ir_opt.c
	vex/priv/ir_inject.c
	vex/priv/main_globals.c
	vex/priv/main_util.c
	vex/priv/s390_disasm.c
	vex/priv/host_x86_defs.c
	vex/priv/host_amd64_defs.c
	vex/priv/host_arm_defs.c
	vex/priv/host_arm64_defs.c
	vex/priv/host_ppc_defs.c
	vex/priv/host_riscv64_defs.c
	vex/priv/host_s390_defs.c
	vex/priv/host_mips_defs.c
	vex/priv/host_x86_isel.c
	vex/priv/host_amd64_isel.c
	vex/priv/host_arm_isel.c
	vex/priv/host_arm64_isel.c
	vex/priv/host_ppc_isel.c
	vex/priv/host_riscv64_isel.c
	vex/priv/host_s390_isel.c
	vex/priv/host_mips_isel.c
	vex/priv/host_generic_maddf.c
	vex/priv/host_generic_regs.c
	vex/priv/host_generic_simd64.c
	vex/priv/host_generic_simd128.c
	vex/priv/host_generic_simd256.c
	vex/priv/host_generic_reg_alloc2.c
	vex/priv/host_generic_reg_alloc3.c
	vex/priv/guest_generic_x87.c
	vex/priv/guest_generic_bb_to_IR.c
	vex/priv/guest_x86_helpers.c
	vex/priv/guest_amd64_helpers.c
	vex/priv/guest_arm_helpers.c
	vex/priv/guest_arm64_helpers.c
	vex/priv/guest_ppc_helpers.c
	vex/priv/guest_riscv64_helpers.c
	vex/priv/guest_s390_helpers.c
	vex/priv/guest_mips_helpers.c
	vex/priv/guest_x86_toIR.c
	vex/priv/guest_amd64_toIR.c
	vex/priv/guest_arm_toIR.c
	vex/priv/guest_arm64_toIR.c
	vex/priv/guest_ppc_toIR.c
	vex/priv/guest_riscv64_toIR.c
	vex/priv/guest_s390_toIR.c
	vex/priv/guest_mips_toIR.c
    vex/priv/multiarch_main_main.c
)

# Build the VEX static library
add_library(vex STATIC ${VEX_SRC})
set_target_properties(vex PROPERTIES LINKER_LANGUAGE C)
target_compile_definitions(vex PRIVATE PYVEX)
target_include_directories(vex PUBLIC ${CMAKE_SOURCE_DIR}/vex/pub)

# Build the nanobind module
nanobind_add_module(
	_pyvex
	STABLE_ABI
	NB_STATIC
	${PYVEX_SRC})
target_link_libraries(_pyvex PRIVATE vex)
target_include_directories(_pyvex PRIVATE pyvex_c)

# Install the nanobind module
install(TARGETS _pyvex DESTINATION ${CMAKE_SOURCE_DIR}/pyvex/lib)

# --- BEGIN: Generate pub/libvex_guest_offsets.h ---
add_executable(genoffsets vex/auxprogs/genoffsets.c)
set_target_properties(genoffsets PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/vex/auxprogs)

add_custom_command(
    OUTPUT ${CMAKE_SOURCE_DIR}/vex/pub/libvex_guest_offsets.h
    COMMAND $<TARGET_FILE:genoffsets> > ${CMAKE_SOURCE_DIR}/vex/pub/libvex_guest_offsets.h
    DEPENDS genoffsets
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Generating pub/libvex_guest_offsets.h"
)

add_custom_target(generate_offsets_header
    DEPENDS ${CMAKE_SOURCE_DIR}/vex/pub/libvex_guest_offsets.h
)
install(
    FILES ${CMAKE_SOURCE_DIR}/vex/pub/libvex_guest_offsets.h
    DESTINATION pyvex/include
)

add_dependencies(vex generate_offsets_header)
add_dependencies(_pyvex generate_offsets_header)
# --- END: Generate pub/libvex_guest_offsets.h ---

# --- BEGIN: Copy headers to pyvex/include ---
add_custom_command(
    OUTPUT ${CMAKE_SOURCE_DIR}/pyvex/include/pub
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_SOURCE_DIR}/vex/pub ${CMAKE_SOURCE_DIR}/pyvex/include/
    DEPENDS ${CMAKE_SOURCE_DIR}/vex/pub
    COMMENT "Copying vex/pub to pyvex/include/"
)
add_custom_command(
    OUTPUT ${CMAKE_SOURCE_DIR}/pyvex/include/pyvex.h
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_SOURCE_DIR}/pyvex_c/pyvex.h ${CMAKE_SOURCE_DIR}/pyvex/include/pyvex.h
    DEPENDS ${CMAKE_SOURCE_DIR}/pyvex_c/pyvex.h
    COMMENT "Copying pyvex_c/pyvex.h to pyvex/include/"
)
add_custom_target(copy_headers ALL
    DEPENDS ${CMAKE_SOURCE_DIR}/pyvex/include/pub ${CMAKE_SOURCE_DIR}/pyvex/include/pyvex.h
)
add_dependencies(_pyvex copy_headers)
# --- END: Copy headers to pyvex/include ---
