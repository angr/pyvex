#include "arches.hpp"
#include <stdexcept>
#include <sstream>
#include <algorithm>

using namespace nb::literals;

// Helper function to get VEX arch string from name
std::string get_vex_arch_string(const std::string& name) {
    static const std::unordered_map<std::string, std::string> vex_arch_map = {
        {"X86", "VexArchX86"},
        {"AMD64", "VexArchAMD64"},
        {"ARM", "VexArchARM"},
        {"ARM64", "VexArchARM64"},
        {"PPC32", "VexArchPPC32"},
        {"PPC64", "VexArchPPC64"},
        {"S390X", "VexArchS390X"},
        {"MIPS32", "VexArchMIPS32"},
        {"MIPS64", "VexArchMIPS64"},
        {"RISCV64", "VexArchRISCV64"}
    };
    
    auto it = vex_arch_map.find(name);
    if (it != vex_arch_map.end()) {
        return it->second;
    }
    throw std::invalid_argument("Unknown architecture: " + name);
}

// Helper function to get IP register name from architecture
std::string get_ip_register_name(const std::string& name) {
    static const std::unordered_map<std::string, std::string> ip_reg_map = {
        {"X86", "eip"},
        {"AMD64", "rip"},
        {"ARM", "r15t"},
        {"ARM64", "pc"},
        {"PPC32", "cia"},
        {"PPC64", "cia"},
        {"S390X", "ia"},
        {"MIPS32", "pc"},
        {"MIPS64", "pc"},
        {"RISCV64", "pc"}
    };
    
    auto it = ip_reg_map.find(name);
    if (it != ip_reg_map.end()) {
        return it->second;
    }
    throw std::invalid_argument("Unknown architecture: " + name);
}

PyvexArch::PyvexArch(const std::string& name, int bits, const std::string& memory_endness, 
                         const std::string& instruction_endness)
    : name(name), bits(bits), memory_endness(memory_endness), 
      instruction_endness(instruction_endness), byte_width(8) {
    initialize_vex_arch();
    initialize_ip_offset();
}

void PyvexArch::initialize_vex_arch() {
    vex_arch = get_vex_arch_string(name);
}

void PyvexArch::initialize_ip_offset() {
    // This would need to be implemented with actual VEX guest_offsets lookup
    // For now, we'll set a placeholder value
    ip_offset = 0;
    
    // In the actual implementation, this would be:
    // std::string ip_reg_name = get_ip_register_name(name);
    // ip_offset = guest_offsets[(vex_name_small(), ip_reg_name)];
}

std::string PyvexArch::__repr__() const {
    return "<PyvexArch " + name + ">";
}

std::string PyvexArch::vex_name_small() const {
    // Remove "VexArch" prefix and convert to lowercase
    if (vex_arch.substr(0, 7) == "VexArch") {
        std::string result = vex_arch.substr(7);
        std::transform(result.begin(), result.end(), result.begin(), ::tolower);
        return result;
    }
    return vex_arch;
}

std::string PyvexArch::translate_register_name(int offset, int size) const {
    // This would need to be implemented with actual VEX guest_offsets lookup
    // For now, return the offset as string
    return std::to_string(offset);
    
    // In the actual implementation, this would be:
    // std::string vex_small = vex_name_small();
    // for (const auto& [key, value] : guest_offsets) {
    //     if (key.first == vex_small && value == offset) {
    //         return key.second;
    //     }
    // }
    // for (const auto& [key, value] : REGISTER_OFFSETS) {
    //     if (key.first == vex_small && value == offset) {
    //         return key.second;
    //     }
    // }
    // return std::to_string(offset);
}

int PyvexArch::get_register_offset(const std::string& name) const {
    // This would need to be implemented with actual VEX guest_offsets lookup
    // For now, throw an exception
    throw std::runtime_error("get_register_offset not implemented yet");
    
    // In the actual implementation, this would be:
    // std::string vex_small = vex_name_small();
    // std::pair<std::string, std::string> key = {vex_small, name};
    // if (guest_offsets.find(key) != guest_offsets.end()) {
    //     return guest_offsets[key];
    // }
    // if (REGISTER_OFFSETS.find(key) != REGISTER_OFFSETS.end()) {
    //     return REGISTER_OFFSETS[key];
    // }
    // throw std::runtime_error("Unknown register " + name + " for architecture " + this->name);
}

// Architecture instances
std::shared_ptr<PyvexArch> ARCH_X86 = std::make_shared<PyvexArch>("X86", 32, "Iend_LE");
std::shared_ptr<PyvexArch> ARCH_AMD64 = std::make_shared<PyvexArch>("AMD64", 64, "Iend_LE");
std::shared_ptr<PyvexArch> ARCH_ARM_LE = std::make_shared<PyvexArch>("ARM", 32, "Iend_LE", "Iend_LE");
std::shared_ptr<PyvexArch> ARCH_ARM_BE_LE = std::make_shared<PyvexArch>("ARM", 32, "Iend_BE", "Iend_LE");
std::shared_ptr<PyvexArch> ARCH_ARM_BE = std::make_shared<PyvexArch>("ARM", 32, "Iend_LE");
std::shared_ptr<PyvexArch> ARCH_ARM64_LE = std::make_shared<PyvexArch>("ARM64", 64, "Iend_LE", "Iend_LE");
std::shared_ptr<PyvexArch> ARCH_ARM64_BE = std::make_shared<PyvexArch>("ARM64", 64, "Iend_BE");
std::shared_ptr<PyvexArch> ARCH_PPC32 = std::make_shared<PyvexArch>("PPC32", 32, "Iend_BE");
std::shared_ptr<PyvexArch> ARCH_PPC64_BE = std::make_shared<PyvexArch>("PPC64", 64, "Iend_BE");
std::shared_ptr<PyvexArch> ARCH_PPC64_LE = std::make_shared<PyvexArch>("PPC64", 64, "Iend_LE");
std::shared_ptr<PyvexArch> ARCH_S390X = std::make_shared<PyvexArch>("S390X", 64, "Iend_BE");
std::shared_ptr<PyvexArch> ARCH_MIPS32_BE = std::make_shared<PyvexArch>("MIPS32", 32, "Iend_BE");
std::shared_ptr<PyvexArch> ARCH_MIPS32_LE = std::make_shared<PyvexArch>("MIPS32", 32, "Iend_LE");
std::shared_ptr<PyvexArch> ARCH_MIPS64_BE = std::make_shared<PyvexArch>("MIPS64", 64, "Iend_BE");
std::shared_ptr<PyvexArch> ARCH_MIPS64_LE = std::make_shared<PyvexArch>("MIPS64", 64, "Iend_LE");
std::shared_ptr<PyvexArch> ARCH_RISCV64_LE = std::make_shared<PyvexArch>("RISCV64", 64, "Iend_LE", "Iend_LE");

std::shared_ptr<PyvexArch> arch_from_archtype(ArchType arch_type) {
    switch (arch_type) {
        case ArchType::X86:
            return ARCH_X86;
        case ArchType::AMD64:
            return ARCH_AMD64;
        case ArchType::ARM_LE:
            return ARCH_ARM_LE;
        case ArchType::ARM_BE_LE:
            return ARCH_ARM_BE_LE;
        case ArchType::ARM_BE:
            return ARCH_ARM_BE;
        case ArchType::ARM64_LE:
            return ARCH_ARM64_LE;
        case ArchType::ARM64_BE:
            return ARCH_ARM64_BE;
        case ArchType::PPC32:
            return ARCH_PPC32;
        case ArchType::PPC64_BE:
            return ARCH_PPC64_BE;
        case ArchType::PPC64_LE:
            return ARCH_PPC64_LE;
        case ArchType::S390X:
            return ARCH_S390X;
        case ArchType::MIPS32_BE:
            return ARCH_MIPS32_BE;
        case ArchType::MIPS32_LE:
            return ARCH_MIPS32_LE;
        case ArchType::MIPS64_BE:
            return ARCH_MIPS64_BE;
        case ArchType::MIPS64_LE:
            return ARCH_MIPS64_LE;
        case ArchType::RISCV64_LE:
            return ARCH_RISCV64_LE;
        default:
            throw std::invalid_argument("Unknown architecture type");
    }
}

void bind_arches(nb::module_& m) {

    // Bind ArchType enum
    nb::enum_<ArchType>(m, "ArchType")
        .value("X86", ArchType::X86)
        .value("AMD64", ArchType::AMD64)
        .value("ARM_LE", ArchType::ARM_LE)
        .value("ARM_BE_LE", ArchType::ARM_BE_LE)
        .value("ARM_BE", ArchType::ARM_BE)
        .value("ARM64_LE", ArchType::ARM64_LE)
        .value("ARM64_BE", ArchType::ARM64_BE)
        .value("PPC32", ArchType::PPC32)
        .value("PPC64_BE", ArchType::PPC64_BE)
        .value("PPC64_LE", ArchType::PPC64_LE)
        .value("S390X", ArchType::S390X)
        .value("MIPS32_BE", ArchType::MIPS32_BE)
        .value("MIPS32_LE", ArchType::MIPS32_LE)
        .value("MIPS64_BE", ArchType::MIPS64_BE)
        .value("MIPS64_LE", ArchType::MIPS64_LE)
        .value("RISCV64_LE", ArchType::RISCV64_LE);

    // Bind Register struct
    nb::class_<Register>(m, "Register")
        .def(nb::init<const std::string&, int, int>())
        .def_rw("name", &Register::name)
        .def_rw("offset", &Register::offset)
        .def_rw("size", &Register::size);

    // Bind PyvexArch class
    nb::class_<PyvexArch>(m, "PyvexArch")
        .def(nb::init<const std::string&, int, const std::string&, const std::string&>(),
             "name"_a, "bits"_a, "memory_endness"_a, "instruction_endness"_a = "Iend_BE")
        .def_ro("name", &PyvexArch::name)
        .def_ro("bits", &PyvexArch::bits)
        .def_ro("memory_endness", &PyvexArch::memory_endness)
        .def_ro("instruction_endness", &PyvexArch::instruction_endness)
        .def_ro("byte_width", &PyvexArch::byte_width)
        .def_ro("register_list", &PyvexArch::register_list)
        .def_ro("registers", &PyvexArch::registers)
        .def_ro("vex_arch", &PyvexArch::vex_arch)
        .def_ro("ip_offset", &PyvexArch::ip_offset)
        .def("__repr__", &PyvexArch::__repr__)
        .def_prop_ro("vex_name_small", &PyvexArch::vex_name_small)
        .def("translate_register_name", &PyvexArch::translate_register_name,
             "offset"_a, "size"_a = -1)
        .def("get_register_offset", &PyvexArch::get_register_offset);

    m.attr("ARCH_X86") = ArchType::X86;
    m.attr("ARCH_AMD64") = ArchType::AMD64;
    m.attr("ARCH_ARM_LE") = ArchType::ARM_LE;
    m.attr("ARCH_ARM_BE_LE") = ArchType::ARM_BE_LE;
    m.attr("ARCH_ARM_BE") = ArchType::ARM_BE;
    m.attr("ARCH_ARM64_LE") = ArchType::ARM64_LE;
    m.attr("ARCH_ARM64_BE") = ArchType::ARM64_BE;
    m.attr("ARCH_PPC32") = ArchType::PPC32;
    m.attr("ARCH_PPC64_BE") = ArchType::PPC64_BE;
    m.attr("ARCH_PPC64_LE") = ArchType::PPC64_LE;
    m.attr("ARCH_S390X") = ArchType::S390X;
    m.attr("ARCH_MIPS32_BE") = ArchType::MIPS32_BE;
    m.attr("ARCH_MIPS32_LE") = ArchType::MIPS32_LE;
    m.attr("ARCH_MIPS64_BE") = ArchType::MIPS64_BE;
    m.attr("ARCH_MIPS64_LE") = ArchType::MIPS64_LE;
    m.attr("ARCH_RISCV64_LE") = ArchType::RISCV64_LE;
}