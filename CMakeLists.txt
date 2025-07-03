cmake_minimum_required(VERSION 3.15)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

project(pyvex LANGUAGES C)

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
target_compile_definitions(vex PRIVATE PYVEX)
target_include_directories(vex PUBLIC ${CMAKE_SOURCE_DIR}/vex/pub)

# Build the shared library
add_library(pyvex SHARED ${PYVEX_SRC})
set_target_properties(pyvex PROPERTIES OUTPUT_NAME "pyvex")

# Handle .def file for Windows builds
if (WIN32)
    set_target_properties(pyvex PROPERTIES LINK_FLAGS "/DEF:${CMAKE_SOURCE_DIR}/pyvex_c/pyvex.def")
endif()

target_include_directories(pyvex PRIVATE pyvex_c)

target_link_libraries(pyvex PRIVATE vex)

# Install the built library to the Python package
# It is installed twice to handle both editable and non-editable installs
install(TARGETS pyvex DESTINATION ${CMAKE_SOURCE_DIR}/pyvex/lib)
install(TARGETS pyvex DESTINATION pyvex/lib)

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
# --- END: Generate pub/libvex_guest_offsets.h ---

# --- BEGIN: Generate pyvex/vex_ffi.py ---
add_custom_command(
    OUTPUT ${CMAKE_SOURCE_DIR}/pyvex/vex_ffi.py
    COMMAND ${CMAKE_COMMAND} -E env
        ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/make_ffi.py ${CMAKE_SOURCE_DIR}/vex/pub
    DEPENDS ${CMAKE_SOURCE_DIR}/vex/pub/libvex_guest_offsets.h
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Generating pyvex/vex_ffi.py using make_ffi.py"
)

add_custom_target(generate_vex_ffi_py
    DEPENDS ${CMAKE_SOURCE_DIR}/pyvex/vex_ffi.py
)
install(
    FILES ${CMAKE_SOURCE_DIR}/pyvex/vex_ffi.py
    DESTINATION pyvex
)
add_dependencies(pyvex generate_vex_ffi_py)
# --- END: Generate pyvex/vex_ffi.py ---

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
add_dependencies(pyvex copy_headers)
add_dependencies(copy_headers generate_offsets_header)
# --- END: Copy headers to pyvex/include ---
