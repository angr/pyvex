#include <nanobind/nanobind.h>
#include <memory>
#include <string>
#include <unordered_map>
#include <regex>
extern "C" {
#include "pyvex.h"
}
#include "const.hpp"

namespace nb = nanobind;

void PyIRConst::pp() const {
    nb::print(nb::str(__str__().c_str()));
}

// U1 class
class U1 : public PyIRConst {
public:
    uint8_t value;

    U1(uint8_t value_) : PyIRConst() {
        type = "Ity_I1";
        size = 1;
        tag = "Ico_U1";
        op_format = "1";
        value = value_;
    }

    std::string __str__() const override {
        return std::to_string(value);
    }

    IRConst* _to_c() const override {
        return IRConst_U1(value ? 1 : 0);
    }

    bool __eq__(const U1& other) const {
        return type == other.type && value == other.value;
    }

    size_t __hash__() const override {
        return std::hash<std::string>()(type) ^ std::hash<uint8_t>()(value);
    }

    static std::shared_ptr<U1> _from_c(const IRConst* c_const) {
        return std::make_shared<U1>(c_const->Ico.U1);
    }
};

// U8 class
class U8 : public PyIRConst {
public:
    uint8_t value;

    U8(uint8_t value_) : PyIRConst() {
        type = "Ity_I8";
        size = 8;
        tag = "Ico_U8";
        op_format = "8";
        value = value_;
    }

    std::string __str__() const override {
        char buf[16];
        snprintf(buf, sizeof(buf), "0x%02x", (unsigned int)value);
        return std::string(buf);
    }

    IRConst* _to_c() const override {
        return IRConst_U8((UChar)value);
    }

    bool __eq__(const U8& other) const {
        return type == other.type && value == other.value;
    }

    size_t __hash__() const override {
        return std::hash<std::string>()(type) ^ std::hash<uint8_t>()(value);
    }

    static std::shared_ptr<U8> _from_c(const IRConst* c_const) {
        return _get_u8_pool_instance(c_const->Ico.U8);
    }

private:
    static std::shared_ptr<U8> _get_u8_pool_instance(int value) {
        static std::unordered_map<int, std::shared_ptr<U8>> pool;
        if (value >= 0 && value <= 255) {
            auto it = pool.find(value);
            if (it == pool.end()) {
                pool[value] = std::make_shared<U8>(value);
            }
            return pool[value];
        }
        return std::make_shared<U8>(value);
    }
};

// U16 class
class U16 : public PyIRConst {
public:
    uint16_t value;

    U16(uint16_t value_) : PyIRConst() {
        type = "Ity_I16";
        size = 16;
        tag = "Ico_U16";
        op_format = "16";
        value = value_;
    }

    std::string __str__() const override {
        char buf[16];
        snprintf(buf, sizeof(buf), "0x%04x", (unsigned int)value);
        return std::string(buf);
    }

    IRConst* _to_c() const override {
        return IRConst_U16((UShort)value);
    }

    bool __eq__(const U16& other) const {
        return type == other.type && value == other.value;
    }

    size_t __hash__() const override {
        return std::hash<std::string>()(type) ^ std::hash<uint16_t>()(value);
    }

    static std::shared_ptr<U16> _from_c(const IRConst* c_const) {
        return _get_u16_pool_instance(c_const->Ico.U16);
    }

private:
    static std::shared_ptr<U16> _get_u16_pool_instance(int value) {
        static std::unordered_map<int, std::shared_ptr<U16>> pool;
        // Pool for small values and high values
        if ((value >= 0 && value < 1024) || (value >= 0xFC00 && value <= 0xFFFF)) {
            auto it = pool.find(value);
            if (it == pool.end()) {
                pool[value] = std::make_shared<U16>(value);
            }
            return pool[value];
        }
        return std::make_shared<U16>(value);
    }
};

// U32 class
class U32 : public PyIRConst {
public:
    uint32_t value;

    U32(uint32_t value_) : PyIRConst() {
        type = "Ity_I32";
        size = 32;
        tag = "Ico_U32";
        op_format = "32";
        value = value_;
    }

    std::string __str__() const override {
        char buf[16];
        snprintf(buf, sizeof(buf), "0x%08x", (unsigned int)value);
        return std::string(buf);
    }

    IRConst* _to_c() const override {
        return IRConst_U32((UInt)value);
    }

    bool __eq__(const U32& other) const {
        return type == other.type && value == other.value;
    }

    size_t __hash__() const override {
        return std::hash<std::string>()(type) ^ std::hash<uint32_t>()(value);
    }

    static std::shared_ptr<U32> _from_c(const IRConst* c_const) {
        return _get_u32_pool_instance(c_const->Ico.U32);
    }

private:
    static std::shared_ptr<U32> _get_u32_pool_instance(uint32_t value) {
        static std::unordered_map<uint32_t, std::shared_ptr<U32>> pool;
        // Pool for small values and high values
        if ((value < 1024) || (value >= 0xFFFFFC00)) {
            auto it = pool.find(value);
            if (it == pool.end()) {
                pool[value] = std::make_shared<U32>(value);
            }
            return pool[value];
        }
        return std::make_shared<U32>(value);
    }
};

// U64 class
class U64 : public PyIRConst {
public:
    uint64_t value;

    U64(uint64_t value_) : PyIRConst() {
        type = "Ity_I64";
        size = 64;
        tag = "Ico_U64";
        op_format = "64";
        value = value_;
    }

    std::string __str__() const override {
        char buf[32];
        snprintf(buf, sizeof(buf), "0x%016lx", (unsigned long)value);
        return std::string(buf);
    }

    IRConst* _to_c() const override {
        return IRConst_U64((ULong)value);
    }

    bool __eq__(const U64& other) const {
        return type == other.type && value == other.value;
    }

    size_t __hash__() const override {
        return std::hash<std::string>()(type) ^ std::hash<uint64_t>()(value);
    }

    static std::shared_ptr<U64> _from_c(const IRConst* c_const) {
        return _get_u64_pool_instance(c_const->Ico.U64);
    }

private:
    static std::shared_ptr<U64> _get_u64_pool_instance(uint64_t value) {
        static std::unordered_map<uint64_t, std::shared_ptr<U64>> pool;
        // Pool for small values and high values
        if ((value < 1024) || (value >= 0xFFFFFFFFFFFFFC00ULL)) {
            auto it = pool.find(value);
            if (it == pool.end()) {
                pool[value] = std::make_shared<U64>(value);
            }
            return pool[value];
        }
        return std::make_shared<U64>(value);
    }
};

// F32 class
class F32 : public PyIRConst {
public:
    float value;

    F32(float value_) : PyIRConst() {
        type = "Ity_F32";
        size = 32;
        tag = "Ico_F32";
        op_format = "F32";
        value = value_;
    }

    std::string __str__() const override {
        char buf[32];
        snprintf(buf, sizeof(buf), "%f", value);
        return std::string(buf);
    }

    IRConst* _to_c() const override {
        return IRConst_F32(value);
    }

    bool __eq__(const F32& other) const {
        return type == other.type && value == other.value;
    }

    size_t __hash__() const override {
        return std::hash<std::string>()(type) ^ std::hash<float>()(value);
    }

    static std::shared_ptr<F32> _from_c(const IRConst* c_const) {
        return std::make_shared<F32>(c_const->Ico.F32);
    }
};

// F64 class
class F64 : public PyIRConst {
public:
    double value;

    F64(double value_) : PyIRConst() {
        type = "Ity_F64";
        size = 64;
        tag = "Ico_F64";
        op_format = "F64";
        value = value_;
    }

    std::string __str__() const override {
        char buf[32];
        snprintf(buf, sizeof(buf), "%f", value);
        return std::string(buf);
    }

    IRConst* _to_c() const override {
        return IRConst_F64(value);
    }

    bool __eq__(const F64& other) const {
        return type == other.type && value == other.value;
    }

    size_t __hash__() const override {
        return std::hash<std::string>()(type) ^ std::hash<double>()(value);
    }

    static std::shared_ptr<F64> _from_c(const IRConst* c_const) {
        return std::make_shared<F64>(c_const->Ico.F64);
    }
};

// PyV128 class
class PyV128 : public PyIRConst {
public:
    uint16_t value;

    PyV128(uint16_t value_) : PyIRConst() {
        type = "Ity_V128";
        size = 128;
        tag = "Ico_V128";
        op_format = "V128";
        value = value_;
    }

    std::string __str__() const override {
        char buf[32];
        snprintf(buf, sizeof(buf), "0x%04x", value);
        return std::string(buf);
    }

    IRConst* _to_c() const override {
        return IRConst_V128(value);
    }

    bool __eq__(const PyV128& other) const {
        return type == other.type && value == other.value;
    }

    size_t __hash__() const override {
        return std::hash<std::string>()(type) ^ std::hash<uint16_t>()(value);
    }

    static std::shared_ptr<PyV128> _from_c(const IRConst* c_const) {
        return std::make_shared<PyV128>(c_const->Ico.V128);
    }
};

// PyV256 class
class PyV256 : public PyIRConst {
public:
    uint32_t value;

    PyV256(uint32_t value_) : PyIRConst() {
        type = "Ity_V256";
        size = 256;
        tag = "Ico_V256";
        op_format = "V256";
        value = value_;
    }

    std::string __str__() const override {
        char buf[32];
        snprintf(buf, sizeof(buf), "0x%08x", value);
        return std::string(buf);
    }

    IRConst* _to_c() const override {
        return IRConst_V256(value);
    }

    bool __eq__(const PyV256& other) const {
        return type == other.type && value == other.value;
    }

    size_t __hash__() const override {
        return std::hash<std::string>()(type) ^ std::hash<uint32_t>()(value);
    }

    static std::shared_ptr<PyV256> _from_c(const IRConst* c_const) {
        return std::make_shared<PyV256>(c_const->Ico.V256);
    }
};

// Factory method implementation
std::shared_ptr<PyIRConst> PyIRConst::_from_c(const IRConst* c_const) {
    if (!c_const) {
        return nullptr;
    }

    switch (c_const->tag) {
        case Ico_U1: return U1::_from_c(c_const);
        case Ico_U8: return U8::_from_c(c_const);
        case Ico_U16: return U16::_from_c(c_const);
        case Ico_U32: return U32::_from_c(c_const);
        case Ico_U64: return U64::_from_c(c_const);
        case Ico_F32: return F32::_from_c(c_const);
        case Ico_F64: return F64::_from_c(c_const);
        case Ico_V128: return PyV128::_from_c(c_const);
        case Ico_V256: return PyV256::_from_c(c_const);
        default:
            throw std::runtime_error("Unknown/unsupported IRConstTag");
    }
}

// Utility functions
int get_type_size(const std::string& ty) {
    std::regex type_str_re(R"(Ity_[IFDV](\d+))");
    std::smatch match;
    if (std::regex_match(ty, match, type_str_re)) {
        return std::stoi(match[1].str());
    }
    throw std::invalid_argument("Type " + ty + " does not have size");
}

int get_tag_size(const std::string& tag) {
    std::regex tag_size_re(R"(Ico_[UFV](\d+)i?)");
    std::smatch match;
    if (std::regex_match(tag, match, tag_size_re)) {
        return std::stoi(match[1].str());
    }
    throw std::invalid_argument("Tag " + tag + " does not have size");
}

// Nanobind module definition
void bind_const(nb::module_& m) {
    // Base IRConst class
    nb::class_<PyIRConst>(m, "IRConst")
        .def("pp", &PyIRConst::pp)
        .def("__str__", &PyIRConst::__str__)
        .def_static("_from_c", &PyIRConst::_from_c, nb::rv_policy::take_ownership)
        .def("_to_c", &PyIRConst::_to_c, nb::rv_policy::take_ownership)
        .def_rw("type", &PyIRConst::type)
        .def_rw("size", &PyIRConst::size)
        .def_rw("tag", &PyIRConst::tag)
        .def_rw("op_format", &PyIRConst::op_format);

    // U1 class
    nb::class_<U1, PyIRConst>(m, "U1")
        .def(nb::init<uint8_t>())
        .def_rw("value", &U1::value)
        .def("__eq__", &U1::__eq__)
        .def("__hash__", &U1::__hash__)
        .def_static("_from_c", &U1::_from_c, nb::rv_policy::take_ownership);

    // U8 class
    nb::class_<U8, PyIRConst>(m, "U8")
        .def(nb::init<uint8_t>())
        .def_rw("value", &U8::value)
        .def("__eq__", &U8::__eq__)
        .def("__hash__", &U8::__hash__)
        .def_static("_from_c", &U8::_from_c, nb::rv_policy::take_ownership);

    // U16 class
    nb::class_<U16, PyIRConst>(m, "U16")
        .def(nb::init<uint16_t>())
        .def_rw("value", &U16::value)
        .def("__eq__", &U16::__eq__)
        .def("__hash__", &U16::__hash__)
        .def_static("_from_c", &U16::_from_c, nb::rv_policy::take_ownership);

    // U32 class
    nb::class_<U32, PyIRConst>(m, "U32")
        .def(nb::init<uint32_t>())
        .def_rw("value", &U32::value)
        .def("__eq__", &U32::__eq__)
        .def("__hash__", &U32::__hash__)
        .def_static("_from_c", &U32::_from_c, nb::rv_policy::take_ownership);

    // U64 class
    nb::class_<U64, PyIRConst>(m, "U64")
        .def(nb::init<uint64_t>())
        .def_rw("value", &U64::value)
        .def("__eq__", &U64::__eq__)
        .def("__hash__", &U64::__hash__)
        .def_static("_from_c", &U64::_from_c, nb::rv_policy::take_ownership);

    // F32 class
    nb::class_<F32, PyIRConst>(m, "F32")
        .def(nb::init<float>())
        .def_rw("value", &F32::value)
        .def("__eq__", &F32::__eq__)
        .def("__hash__", &F32::__hash__)
        .def_static("_from_c", &F32::_from_c, nb::rv_policy::take_ownership);

    // F64 class
    nb::class_<F64, PyIRConst>(m, "F64")
        .def(nb::init<double>())
        .def_rw("value", &F64::value)
        .def("__eq__", &F64::__eq__)
        .def("__hash__", &F64::__hash__)
        .def_static("_from_c", &F64::_from_c, nb::rv_policy::take_ownership);

    // V128 class
    nb::class_<PyV128, PyIRConst>(m, "V128")
        .def(nb::init<uint16_t>())
        .def_rw("value", &PyV128::value)
        .def("__eq__", &PyV128::__eq__)
        .def("__hash__", &PyV128::__hash__)
        .def_static("_from_c", &PyV128::_from_c, nb::rv_policy::take_ownership);

    // V256 class
    nb::class_<PyV256, PyIRConst>(m, "V256")
        .def(nb::init<uint32_t>())
        .def_rw("value", &PyV256::value)
        .def("__eq__", &PyV256::__eq__)
        .def("__hash__", &PyV256::__hash__)
        .def_static("_from_c", &PyV256::_from_c, nb::rv_policy::take_ownership);

    // Utility functions
    m.def("get_type_size", &get_type_size);
    m.def("get_tag_size", &get_tag_size);
}