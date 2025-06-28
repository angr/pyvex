#include <nanobind/nanobind.h>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

extern "C" {
#include "pyvex.h"
}

namespace nb = nanobind;

// Base VEXObject class
class VEXObject {
public:
    virtual ~VEXObject() = default;
    
    virtual bool __eq__(const VEXObject& other) const {
        return typeid(*this) == typeid(other);
    }
    
    virtual size_t __hash__() const {
        return std::hash<std::string>{}(typeid(*this).name());
    }
};

// PyIRCallee class
class PyIRCallee : public VEXObject {
public:
    int regparms;
    std::string name;
    int mcx_mask;

    PyIRCallee(int regparms, const std::string& name, int mcx_mask)
        : regparms(regparms), name(name), mcx_mask(mcx_mask) {}

    std::string __str__() const {
        return name;
    }

    bool __eq__(const VEXObject& other) const override {
        if (const auto* other_callee = dynamic_cast<const PyIRCallee*>(&other)) {
            return regparms == other_callee->regparms &&
                   name == other_callee->name &&
                   mcx_mask == other_callee->mcx_mask;
        }
        return false;
    }

    size_t __hash__() const override {
        return std::hash<int>{}(regparms) ^ 
               std::hash<std::string>{}(name) ^ 
               std::hash<int>{}(mcx_mask);
    }

    static std::shared_ptr<PyIRCallee> _from_c(const IRCallee* c_callee) {
        if (!c_callee) return nullptr;
        return std::make_shared<PyIRCallee>(
            c_callee->regparms,
            std::string(c_callee->name),
            c_callee->mcx_mask
        );
    }

    static IRCallee* _to_c(const PyIRCallee& callee) {
        // This doesn't work in the original Python either
        throw std::runtime_error(
            "This doesn't work! Please invent a way to get the correct address for the named function from pyvex_c."
        );
    }
};

// PyIRRegArray class
class PyIRRegArray : public VEXObject {
public:
    int base;
    std::string elemTy;
    int nElems;

    PyIRRegArray(int base, const std::string& elemTy, int nElems)
        : base(base), elemTy(elemTy), nElems(nElems) {}

    std::string __str__() const {
        // Remove "Ity_" prefix for display
        std::string display_type = elemTy;
        if (display_type.substr(0, 4) == "Ity_") {
            display_type = display_type.substr(4);
        }
        return std::to_string(base) + ":" + display_type + "x" + std::to_string(nElems);
    }

    bool __eq__(const VEXObject& other) const override {
        if (const auto* other_arr = dynamic_cast<const PyIRRegArray*>(&other)) {
            return base == other_arr->base &&
                   elemTy == other_arr->elemTy &&
                   nElems == other_arr->nElems;
        }
        return false;
    }

    size_t __hash__() const override {
        return std::hash<int>{}(base) ^ 
               std::hash<std::string>{}(elemTy) ^ 
               std::hash<int>{}(nElems);
    }

    static std::shared_ptr<PyIRRegArray> _from_c(const IRRegArray* c_arr);
    static IRRegArray* _to_c(const PyIRRegArray& arr);
};

// Enum mapping globals
static std::unordered_map<int, std::string> ints_to_enums;
static std::unordered_map<std::string, int> enums_to_ints;
static std::unordered_map<std::string, int> irop_enums_to_ints;
static std::vector<std::string> will_be_overwritten = {"Ircr_GT", "Ircr_LT"};

// Enum utility functions
std::string get_enum_from_int(int i) {
    auto it = ints_to_enums.find(i);
    if (it != ints_to_enums.end()) {
        return it->second;
    }
    throw std::runtime_error("Unknown enum value: " + std::to_string(i));
}

int get_int_from_enum(const std::string& e) {
    auto it = enums_to_ints.find(e);
    if (it != enums_to_ints.end()) {
        return it->second;
    }
    throw std::runtime_error("Unknown enum string: " + e);
}

static int _add_enum_counter = 0;

void _add_enum(const std::string& s, int i = -1) {
    if (i == -1) {
        while (ints_to_enums.find(_add_enum_counter) != ints_to_enums.end()) {
            _add_enum_counter++;
        }
        i = _add_enum_counter;
        _add_enum_counter++;
    }
    
    auto existing = ints_to_enums.find(i);
    if (existing != ints_to_enums.end()) {
        // Check if it's in the will_be_overwritten list
        bool can_overwrite = false;
        for (const auto& allowed : will_be_overwritten) {
            if (existing->second == allowed) {
                can_overwrite = true;
                break;
            }
        }
        if (!can_overwrite) {
            throw std::runtime_error("Enum with intkey " + std::to_string(i) + " already present");
        }
    }
    
    enums_to_ints[s] = i;
    ints_to_enums[i] = s;
    if (s.substr(0, 4) == "Iop_") {
        irop_enums_to_ints[s] = i;
    }
}

// Implementation of IRRegArray methods that depend on enum functions
std::shared_ptr<PyIRRegArray> PyIRRegArray::_from_c(const IRRegArray* c_arr) {
    if (!c_arr) return nullptr;
    return std::make_shared<PyIRRegArray>(
        c_arr->base,
        get_enum_from_int(c_arr->elemTy),
        c_arr->nElems
    );
}

IRRegArray* PyIRRegArray::_to_c(const PyIRRegArray& arr) {
    return mkIRRegArray(arr.base, (IRType)get_int_from_enum(arr.elemTy), arr.nElems);
}

// VEX utility functions
int vex_endness_from_string(const std::string& endness_str) {
    return get_int_from_enum(endness_str);
}

// Default VEX archinfo (returns as Python dict through nanobind)
nb::dict default_vex_archinfo() {
    nb::dict archinfo;
    archinfo["hwcaps"] = 0;
    archinfo["endness"] = vex_endness_from_string("VexEndnessLE");
    archinfo["ppc_icache_line_szB"] = 0;
    archinfo["ppc_dcbz_szB"] = 0;
    archinfo["ppc_dcbzl_szB"] = 0;
    archinfo["arm64_dMinLine_lg2_szB"] = 0;
    archinfo["arm64_iMinLine_lg2_szB"] = 0;
    
    nb::dict hwcache_info;
    hwcache_info["num_levels"] = 0;
    hwcache_info["num_caches"] = 0;
    hwcache_info["caches"] = nb::none();
    hwcache_info["icaches_maintain_coherence"] = true;
    archinfo["hwcache_info"] = hwcache_info;
    
    archinfo["x86_cr0"] = 0xFFFFFFFF;
    
    return archinfo;
}

// Initialize enums from VEX constants
void _initialize_enums() {
    // Add VEX architecture constants
    _add_enum("VexArchX86", VexArchX86);
    _add_enum("VexArchAMD64", VexArchAMD64);
    _add_enum("VexArchARM", VexArchARM);
    _add_enum("VexArchARM64", VexArchARM64);
    _add_enum("VexArchPPC32", VexArchPPC32);
    _add_enum("VexArchPPC64", VexArchPPC64);
    _add_enum("VexArchS390X", VexArchS390X);
    _add_enum("VexArchMIPS32", VexArchMIPS32);
    _add_enum("VexArchMIPS64", VexArchMIPS64);
    _add_enum("VexArchRISCV64", VexArchRISCV64);
    
    // Add endness constants
    _add_enum("VexEndnessLE", VexEndnessLE);
    _add_enum("VexEndnessBE", VexEndnessBE);
    
    // Add IRType constants
    _add_enum("Ity_INVALID", Ity_INVALID);
    _add_enum("Ity_I1", Ity_I1);
    _add_enum("Ity_I8", Ity_I8);
    _add_enum("Ity_I16", Ity_I16);
    _add_enum("Ity_I32", Ity_I32);
    _add_enum("Ity_I64", Ity_I64);
    _add_enum("Ity_I128", Ity_I128);
    _add_enum("Ity_F16", Ity_F16);
    _add_enum("Ity_F32", Ity_F32);
    _add_enum("Ity_F64", Ity_F64);
    _add_enum("Ity_D32", Ity_D32);
    _add_enum("Ity_D64", Ity_D64);
    _add_enum("Ity_D128", Ity_D128);
    _add_enum("Ity_V128", Ity_V128);
    _add_enum("Ity_V256", Ity_V256);
    
    // Add IRConstTag constants
    _add_enum("Ico_U1", Ico_U1);
    _add_enum("Ico_U8", Ico_U8);
    _add_enum("Ico_U16", Ico_U16);
    _add_enum("Ico_U32", Ico_U32);
    _add_enum("Ico_U64", Ico_U64);
    _add_enum("Ico_F32", Ico_F32);
    _add_enum("Ico_F32i", Ico_F32i);
    _add_enum("Ico_F64", Ico_F64);
    _add_enum("Ico_F64i", Ico_F64i);
    _add_enum("Ico_V128", Ico_V128);
    _add_enum("Ico_V256", Ico_V256);
    
    // Add many more VEX constants as needed...
    // For now, we'll add them dynamically or as requested
}

// Nanobind module definition
void bind_enums(nb::module_& m) {
    // Initialize enum mappings
    _initialize_enums();
    
    // Base VEXObject class
    nb::class_<VEXObject>(m, "VEXObject")
        .def("__eq__", &VEXObject::__eq__)
        .def("__hash__", &VEXObject::__hash__);

    // PyIRCallee class
    nb::class_<PyIRCallee, VEXObject>(m, "IRCallee")
        .def(nb::init<int, const std::string&, int>())
        .def_rw("regparms", &PyIRCallee::regparms)
        .def_rw("name", &PyIRCallee::name)
        .def_rw("mcx_mask", &PyIRCallee::mcx_mask)
        .def("__str__", &PyIRCallee::__str__)
        .def_static("_from_c", &PyIRCallee::_from_c, nb::rv_policy::take_ownership)
        .def_static("_to_c", &PyIRCallee::_to_c, nb::rv_policy::take_ownership);

    // PyIRRegArray class
    nb::class_<PyIRRegArray, VEXObject>(m, "IRRegArray")
        .def(nb::init<int, const std::string&, int>())
        .def_rw("base", &PyIRRegArray::base)
        .def_rw("elemTy", &PyIRRegArray::elemTy)
        .def_rw("nElems", &PyIRRegArray::nElems)
        .def("__str__", &PyIRRegArray::__str__)
        .def_static("_from_c", &PyIRRegArray::_from_c, nb::rv_policy::take_ownership)
        .def_static("_to_c", &PyIRRegArray::_to_c, nb::rv_policy::take_ownership);

    // Enum utility functions
    m.def("get_enum_from_int", &get_enum_from_int);
    m.def("get_int_from_enum", &get_int_from_enum);
    
    // VEX utility functions
    m.def("vex_endness_from_string", &vex_endness_from_string);
    m.def("default_vex_archinfo", &default_vex_archinfo);

    // Expose enum dictionaries as read-only
    m.attr("ints_to_enums") = nb::cast(ints_to_enums, nb::rv_policy::reference_internal);
    m.attr("enums_to_ints") = nb::cast(enums_to_ints, nb::rv_policy::reference_internal);
    m.attr("irop_enums_to_ints") = nb::cast(irop_enums_to_ints, nb::rv_policy::reference_internal);
}