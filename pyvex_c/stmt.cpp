#include <nanobind/nanobind.h>
#include <memory>
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
extern "C" {
#include "pyvex.h"
}

#include "const.hpp"
#include "expr.hpp"
#include "enums.hpp"
#include "typeenv.hpp"
#include "stmt.hpp"

namespace nb = nanobind;

void PyIRStmt::pp() const {
    nb::print(nb::str(__str__().c_str()));
}

// NoOp statement
class PyNoOp : public PyIRStmt {
public:
    PyNoOp() {
        tag = "Ist_NoOp";
    }

    std::vector<std::shared_ptr<PyIRExpr>> child_expressions() const override {
        return {};
    }

    std::vector<std::shared_ptr<PyIRConst>> constants() const override {
        return {};
    }

    bool typecheck(const PyIRTypeEnv& tyenv) const override {
        return true;
    }

    void replace_expression(const std::unordered_map<std::shared_ptr<PyIRExpr>, std::shared_ptr<PyIRExpr>>& replacements) override {
        // No expressions to replace
    }

    std::string pp_str(const std::string& reg_name, const std::string& arch, const PyIRTypeEnv* tyenv) const override {
        return "NoOp";
    }

    static std::shared_ptr<PyNoOp> _from_c(const IRStmt* c_stmt) {
        return std::make_shared<PyNoOp>();
    }
};

// IMark statement  
class PyIMark : public PyIRStmt {
public:
    uint64_t addr;
    int len;
    uint8_t delta;

    PyIMark(uint64_t addr, int len, uint8_t delta) : addr(addr), len(len), delta(delta) {
        tag = "Ist_IMark";
    }

    std::vector<std::shared_ptr<PyIRExpr>> child_expressions() const override {
        return {};
    }

    std::vector<std::shared_ptr<PyIRConst>> constants() const override {
        return {};
    }

    bool typecheck(const PyIRTypeEnv& tyenv) const override {
        return true;
    }

    void replace_expression(const std::unordered_map<std::shared_ptr<PyIRExpr>, std::shared_ptr<PyIRExpr>>& replacements) override {
        // No expressions to replace
    }

    std::string pp_str(const std::string& reg_name, const std::string& arch, const PyIRTypeEnv* tyenv) const override {
        char buf[64];
        snprintf(buf, sizeof(buf), "IMark(0x%lx, %d, %d)", addr, len, delta);
        return std::string(buf);
    }

    static std::shared_ptr<PyIMark> _from_c(const IRStmt* c_stmt) {
        return std::make_shared<PyIMark>(
            c_stmt->Ist.IMark.addr,
            c_stmt->Ist.IMark.len,
            c_stmt->Ist.IMark.delta
        );
    }
};

// AbiHint statement
class PyAbiHint : public PyIRStmt {
public:
    std::shared_ptr<PyIRExpr> base;
    int len;
    std::shared_ptr<PyIRExpr> nia;

    PyAbiHint(std::shared_ptr<PyIRExpr> base, int len, std::shared_ptr<PyIRExpr> nia)
        : base(base), len(len), nia(nia) {
        tag = "Ist_AbiHint";
    }

    std::vector<std::shared_ptr<PyIRExpr>> child_expressions() const override {
        return {base, nia};
    }

    std::vector<std::shared_ptr<PyIRConst>> constants() const override {
        return {};
    }

    bool typecheck(const PyIRTypeEnv& tyenv) const override {
        return true;
    }

    void replace_expression(const std::unordered_map<std::shared_ptr<PyIRExpr>, std::shared_ptr<PyIRExpr>>& replacements) override {
        // No expressions to replace
    }

    std::string pp_str(const std::string& reg_name, const std::string& arch, const PyIRTypeEnv* tyenv) const override {
        return "AbiHint(" + base->__str__() + ", " + std::to_string(len) + ", " + nia->__str__() + ")";
    }

    static std::shared_ptr<PyAbiHint> _from_c(const ::IRStmt* c_stmt) {
        // FIXME: Not implemented yet
    }
};

// Put statement
class PyPut : public PyIRStmt {
public:
    std::shared_ptr<PyIRExpr> data;
    int offset;

    PyPut(std::shared_ptr<PyIRExpr> data, int offset) : data(data), offset(offset) {
        tag = "Ist_Put";
    }

    std::vector<std::shared_ptr<PyIRExpr>> child_expressions() const override {
        return {data};
    }

    std::vector<std::shared_ptr<PyIRConst>> constants() const override {
        return {};
    }

    bool typecheck(const PyIRTypeEnv& tyenv) const override {
        return true;
    }

    void replace_expression(const std::unordered_map<std::shared_ptr<PyIRExpr>, std::shared_ptr<PyIRExpr>>& replacements) override {
        // No expressions to replace
    }

    std::string pp_str(const std::string& reg_name, const std::string& arch, const PyIRTypeEnv* tyenv) const override {
        return "Put(" + data->_pp_str() + ", " + std::to_string(offset) + ")";
    }

    static std::shared_ptr<PyPut> _from_c(const IRStmt* c_stmt) {
        // FIXME: Not implemented yet
    }
};

// PutI statement  
class PyPutI : public PyIRStmt {
public:
    std::shared_ptr<PyIRRegArray> descr;
    std::shared_ptr<PyIRExpr> ix;
    std::shared_ptr<PyIRExpr> data;
    int bias;

    PyPutI(std::shared_ptr<PyIRRegArray> descr, std::shared_ptr<PyIRExpr> ix, 
         std::shared_ptr<PyIRExpr> data, int bias)
        : descr(descr), ix(ix), data(data), bias(bias) {
        tag = "Ist_PutI";
    }

    std::vector<std::shared_ptr<PyIRExpr>> child_expressions() const override {
        return {ix, data};
    }

    std::vector<std::shared_ptr<PyIRConst>> constants() const override {
        return {};
    }

    bool typecheck(const PyIRTypeEnv& tyenv) const override {
        return true;
    }

    void replace_expression(const std::unordered_map<std::shared_ptr<PyIRExpr>, std::shared_ptr<PyIRExpr>>& replacements) override {
        // No expressions to replace
    }

    std::string pp_str(const std::string& reg_name, const std::string& arch, const PyIRTypeEnv* tyenv) const override {
        return "PutI(" + descr->__str__() + ", " + ix->__str__() + ", " + data->__str__() + ", " + std::to_string(bias) + ")";
    }

    static std::shared_ptr<PyPutI> _from_c(const IRStmt* c_stmt) {
        // FIXME: Not implemented yet
    }
};

// WrTmp statement
class PyWrTmp : public PyIRStmt {
public:
    std::shared_ptr<PyIRExpr> data;
    int tmp;

    PyWrTmp(std::shared_ptr<PyIRExpr> data, int tmp) : data(data), tmp(tmp) {
        tag = "Ist_WrTmp";
    }

    std::vector<std::shared_ptr<PyIRExpr>> child_expressions() const override {
        return {data};
    }

    std::vector<std::shared_ptr<PyIRConst>> constants() const override {
        return {};
    }

    bool typecheck(const PyIRTypeEnv& tyenv) const override {
        return true;
    }

    void replace_expression(const std::unordered_map<std::shared_ptr<PyIRExpr>, std::shared_ptr<PyIRExpr>>& replacements) override {
        // No expressions to replace
    }

    std::string pp_str(const std::string& reg_name, const std::string& arch, const PyIRTypeEnv* tyenv) const override {
        return "WrTmp(" + data->__str__() + ", " + std::to_string(tmp) + ")";
    }

    static std::shared_ptr<PyWrTmp> _from_c(const IRStmt* c_stmt) {
        // FIXME: Not implemented yet
    }
};

// Store statement
class PyStore : public PyIRStmt {
public:
    std::shared_ptr<PyIRExpr> addr;
    std::shared_ptr<PyIRExpr> data;
    std::string end;

    PyStore(std::shared_ptr<PyIRExpr> addr, std::shared_ptr<PyIRExpr> data, const std::string& end)
        : addr(addr), data(data), end(end) {
        tag = "Ist_Store";
    }

    std::string endness() const { return end; }

    std::vector<std::shared_ptr<PyIRExpr>> child_expressions() const override {
        return {addr, data};
    }

    std::vector<std::shared_ptr<PyIRConst>> constants() const override {
        return {};
    }

    bool typecheck(const PyIRTypeEnv& tyenv) const override {
        return true;
    }

    void replace_expression(const std::unordered_map<std::shared_ptr<PyIRExpr>, std::shared_ptr<PyIRExpr>>& replacements) override {
        // No expressions to replace
    }

    std::string pp_str(const std::string& reg_name, const std::string& arch, const PyIRTypeEnv* tyenv) const override {
        return "Store(" + addr->__str__() + ", " + data->__str__() + ", " + end + ")";
    }

    static std::shared_ptr<PyStore> _from_c(const IRStmt* c_stmt) {
        // FIXME: Not implemented yet
    }
};

// Exit statement
class PyExit : public PyIRStmt {
public:
    std::shared_ptr<PyIRExpr> guard;
    std::shared_ptr<PyIRConst> dst;
    int offsIP;
    std::string jk;

    PyExit(std::shared_ptr<PyIRExpr> guard, std::shared_ptr<PyIRConst> dst, int offsIP, const std::string& jk)
        : guard(guard), dst(dst), offsIP(offsIP), jk(jk) {
        tag = "Ist_Exit";
    }

    std::string jumpkind() const { return jk; }

    std::vector<std::shared_ptr<PyIRExpr>> child_expressions() const override {
        return {guard};
    }

    std::vector<std::shared_ptr<PyIRConst>> constants() const override {
        return {};
    }

    bool typecheck(const PyIRTypeEnv& tyenv) const override {
        return true;
    }

    void replace_expression(const std::unordered_map<std::shared_ptr<PyIRExpr>, std::shared_ptr<PyIRExpr>>& replacements) override {
        // No expressions to replace
    }

    std::string pp_str(const std::string& reg_name, const std::string& arch, const PyIRTypeEnv* tyenv) const override {
        return "Exit(" + guard->__str__() + ", " + dst->__str__() + ", " + std::to_string(offsIP) + ", " + jk + ")";
    }

    static std::shared_ptr<PyExit> _from_c(const IRStmt* c_stmt) {
        // FIXME: Not implemented yet
    }
};

// Global mapping for statement type lookup
static std::unordered_map<int, std::function<std::shared_ptr<PyIRStmt>(const IRStmt*)>> enum_to_stmt_factory;

// Initialize statement type mapping
void _initialize_stmt_mapping() {
    enum_to_stmt_factory[Ist_NoOp] = [](const IRStmt* c_stmt) -> std::shared_ptr<PyIRStmt> {
        return PyNoOp::_from_c(c_stmt);
    };
    enum_to_stmt_factory[Ist_IMark] = [](const IRStmt* c_stmt) -> std::shared_ptr<PyIRStmt> {
        return PyIMark::_from_c(c_stmt);
    };
    enum_to_stmt_factory[Ist_AbiHint] = [](const IRStmt* c_stmt) -> std::shared_ptr<PyIRStmt> {
        return PyAbiHint::_from_c(c_stmt);
    };
    enum_to_stmt_factory[Ist_Put] = [](const IRStmt* c_stmt) -> std::shared_ptr<PyIRStmt> {
        return PyPut::_from_c(c_stmt);
    };
    enum_to_stmt_factory[Ist_PutI] = [](const IRStmt* c_stmt) -> std::shared_ptr<PyIRStmt> {
        return PyPutI::_from_c(c_stmt);
    };
    enum_to_stmt_factory[Ist_WrTmp] = [](const IRStmt* c_stmt) -> std::shared_ptr<PyIRStmt> {
        return PyWrTmp::_from_c(c_stmt);
    };
    enum_to_stmt_factory[Ist_Store] = [](const IRStmt* c_stmt) -> std::shared_ptr<PyIRStmt> {
        return PyStore::_from_c(c_stmt);
    };
    enum_to_stmt_factory[Ist_Exit] = [](const IRStmt* c_stmt) -> std::shared_ptr<PyIRStmt> {
        return PyExit::_from_c(c_stmt);
    };
    // Add more statement types as needed...
}

// Factory method implementation
std::shared_ptr<PyIRStmt> PyIRStmt::_from_c(const IRStmt* c_stmt) {
    if (!c_stmt) return nullptr;
    
    auto it = enum_to_stmt_factory.find(c_stmt->tag);
    if (it != enum_to_stmt_factory.end()) {
        return it->second(c_stmt);
    }
    
    throw std::runtime_error("Unknown/unsupported IRStmtTag: " + std::to_string(c_stmt->tag));
}

// Nanobind module definition
void bind_stmt(nb::module_& m) {
    // Initialize statement mapping
    _initialize_stmt_mapping();

    // Base IRStmt class
    nb::class_<PyIRStmt>(m, "IRStmt")
        .def("pp", &PyIRStmt::pp)
        .def("child_expressions", &PyIRStmt::child_expressions)
        .def("expressions", &PyIRStmt::expressions)
        .def("constants", &PyIRStmt::constants)
        .def_static("_from_c", &PyIRStmt::_from_c, nb::rv_policy::take_ownership)
        .def("typecheck", &PyIRStmt::typecheck)
        .def("replace_expression", &PyIRStmt::replace_expression)
        .def("__str__", &PyIRStmt::__str__)
        .def("pp_str", &PyIRStmt::pp_str)
        .def_rw("tag", &PyIRStmt::tag)
        .def_rw("tag_int", &PyIRStmt::tag_int);

    // NoOp statement
    nb::class_<PyNoOp, PyIRStmt>(m, "NoOp")
        .def(nb::init<>())
        .def_static("_from_c", &PyNoOp::_from_c, nb::rv_policy::take_ownership);

    // IMark statement
    nb::class_<PyIMark, PyIRStmt>(m, "IMark")
        .def(nb::init<uint64_t, int, uint8_t>())
        .def_rw("addr", &PyIMark::addr)
        .def_rw("len", &PyIMark::len)
        .def_rw("delta", &PyIMark::delta)
        .def_static("_from_c", &PyIMark::_from_c, nb::rv_policy::take_ownership);

    // AbiHint statement
    nb::class_<PyAbiHint, PyIRStmt>(m, "AbiHint")
        .def(nb::init<std::shared_ptr<PyIRExpr>, int, std::shared_ptr<PyIRExpr>>())
        .def_rw("base", &PyAbiHint::base)
        .def_rw("len", &PyAbiHint::len)
        .def_rw("nia", &PyAbiHint::nia)
        .def_static("_from_c", &PyAbiHint::_from_c, nb::rv_policy::take_ownership);

    // Put statement
    nb::class_<PyPut, PyIRStmt>(m, "Put")
        .def(nb::init<std::shared_ptr<PyIRExpr>, int>())
        .def_rw("data", &PyPut::data)
        .def_rw("offset", &PyPut::offset)
        .def_static("_from_c", &PyPut::_from_c, nb::rv_policy::take_ownership);

    // PutI statement
    nb::class_<PyPutI, PyIRStmt>(m, "PutI")
        .def(nb::init<std::shared_ptr<PyIRRegArray>, std::shared_ptr<PyIRExpr>, std::shared_ptr<PyIRExpr>, int>())
        .def_rw("descr", &PyPutI::descr)
        .def_rw("ix", &PyPutI::ix)
        .def_rw("data", &PyPutI::data)
        .def_rw("bias", &PyPutI::bias)
        .def_static("_from_c", &PyPutI::_from_c, nb::rv_policy::take_ownership);

    // WrTmp statement
    nb::class_<PyWrTmp, PyIRStmt>(m, "WrTmp")
        .def(nb::init<std::shared_ptr<PyIRExpr>, int>())
        .def_rw("data", &PyWrTmp::data)
        .def_rw("tmp", &PyWrTmp::tmp)
        .def_static("_from_c", &PyWrTmp::_from_c, nb::rv_policy::take_ownership);

    // Store statement
    nb::class_<PyStore, PyIRStmt>(m, "Store")
        .def(nb::init<std::shared_ptr<PyIRExpr>, std::shared_ptr<PyIRExpr>, const std::string&>())
        .def_rw("addr", &PyStore::addr)
        .def_rw("data", &PyStore::data)
        .def_rw("end", &PyStore::end)
        .def_prop_ro("endness", &PyStore::endness)
        .def_static("_from_c", &PyStore::_from_c, nb::rv_policy::take_ownership);

    // Exit statement
    nb::class_<PyExit, PyIRStmt>(m, "Exit")
        .def(nb::init<std::shared_ptr<PyIRExpr>, std::shared_ptr<PyIRConst>, int, const std::string&>())
        .def_rw("guard", &PyExit::guard)
        .def_rw("dst", &PyExit::dst)
        .def_rw("offsIP", &PyExit::offsIP)
        .def_rw("jk", &PyExit::jk)
        .def_prop_ro("jumpkind", &PyExit::jumpkind)
        .def_static("_from_c", &PyExit::_from_c, nb::rv_policy::take_ownership);
}