#pragma once

#include <nanobind/nanobind.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/unordered_map.h>
#include <nanobind/stl/vector.h>
#include <string>
#include <unordered_map>
#include <vector>
#include <memory>

extern "C" {
#include "pyvex.h"
}

namespace nb = nanobind;

// Architecture enum
enum class ArchType {
    X86,
    AMD64,
    ARM_LE,
    ARM_BE_LE,
    ARM_BE,
    ARM64_LE,
    ARM64_BE,
    PPC32,
    PPC64_BE,
    PPC64_LE,
    S390X,
    MIPS32_BE,
    MIPS32_LE,
    MIPS64_BE,
    MIPS64_LE,
    RISCV64_LE
};

// Register type (simplified version of Python Register class)
struct Register {
    std::string name;
    int offset;
    int size;
    
    Register(const std::string& name, int offset, int size)
        : name(name), offset(offset), size(size) {}
};

// PyvexArch class
class PyvexArch {
public:
    std::string name;
    int bits;
    std::string memory_endness;
    std::string instruction_endness;
    int byte_width;
    std::vector<Register> register_list;
    std::unordered_map<std::string, std::pair<int, int>> registers;
    std::string vex_arch;
    int ip_offset;

    PyvexArch(const std::string& name, int bits, const std::string& memory_endness, 
              const std::string& instruction_endness = "Iend_BE");

    std::string __repr__() const;
    
    std::string vex_name_small() const;
    
    std::string translate_register_name(int offset, int size = -1) const;
    
    int get_register_offset(const std::string& name) const;

private:
    void initialize_vex_arch();
    void initialize_ip_offset();
};

// Architecture instances as shared pointers
extern std::shared_ptr<PyvexArch> ARCH_X86;
extern std::shared_ptr<PyvexArch> ARCH_AMD64;
extern std::shared_ptr<PyvexArch> ARCH_ARM_LE;
extern std::shared_ptr<PyvexArch> ARCH_ARM_BE_LE;
extern std::shared_ptr<PyvexArch> ARCH_ARM_BE;
extern std::shared_ptr<PyvexArch> ARCH_ARM64_LE;
extern std::shared_ptr<PyvexArch> ARCH_ARM64_BE;
extern std::shared_ptr<PyvexArch> ARCH_PPC32;
extern std::shared_ptr<PyvexArch> ARCH_PPC64_BE;
extern std::shared_ptr<PyvexArch> ARCH_PPC64_LE;
extern std::shared_ptr<PyvexArch> ARCH_S390X;
extern std::shared_ptr<PyvexArch> ARCH_MIPS32_BE;
extern std::shared_ptr<PyvexArch> ARCH_MIPS32_LE;
extern std::shared_ptr<PyvexArch> ARCH_MIPS64_BE;
extern std::shared_ptr<PyvexArch> ARCH_MIPS64_LE;
extern std::shared_ptr<PyvexArch> ARCH_RISCV64_LE;

std::shared_ptr<PyvexArch> arch_from_archtype(ArchType arch_type);

// Function to bind arches to nanobind
void bind_arches(nb::module_& m);