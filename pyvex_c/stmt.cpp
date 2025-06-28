#include <nanobind/nanobind.h>
#include <memory>
#include <string>
#include <vector>
#include <unordered_map>
extern "C" {
#include "pyvex.h"
}

namespace nb = nanobind;

// Forward declarations
class IRExpr;
class IRConst;
class IRRegArray;
class IRCallee;
class IRTypeEnv;

// Base IRStmt class
class IRStmt {
public:
    std::string tag;
    int tag_int = 0;

    virtual ~IRStmt() = default;

    void pp() const {
        nb::print(nb::str(__str__().c_str()));
    }

    virtual std::vector<std::shared_ptr<IRExpr>> child_expressions() const = 0;
    
    std::vector<std::shared_ptr<IRExpr>> expressions() const {
        return child_expressions();
    }

    virtual std::vector<std::shared_ptr<IRConst>> constants() const;

    static std::shared_ptr<IRStmt> _from_c(const ::IRStmt* c_stmt);

    virtual bool typecheck(const IRTypeEnv& tyenv) const {
        return true;
    }

    virtual void replace_expression(const std::unordered_map<std::shared_ptr<IRExpr>, std::shared_ptr<IRExpr>>& replacements) = 0;

    virtual std::string __str__() const {
        return pp_str("", "", nullptr);
    }

    virtual std::string pp_str(const std::string& reg_name, const std::string& arch, const IRTypeEnv* tyenv) const = 0;
};

// NoOp statement
class NoOp : public IRStmt {
public:
    NoOp() {
        tag = "Ist_NoOp";
    }

    std::vector<std::shared_ptr<IRExpr>> child_expressions() const override {
        return {};
    }

    void replace_expression(const std::unordered_map<std::shared_ptr<IRExpr>, std::shared_ptr<IRExpr>>& replacements) override {
        // No expressions to replace
    }

    std::string pp_str(const std::string& reg_name, const std::string& arch, const IRTypeEnv* tyenv) const override {
        return "NoOp";
    }

    static std::shared_ptr<NoOp> _from_c(const ::IRStmt* c_stmt) {
        return std::make_shared<NoOp>();
    }
};

// IMark statement  
class IMark : public IRStmt {
public:
    uint64_t addr;
    int len;
    uint8_t delta;

    IMark(uint64_t addr, int len, uint8_t delta) : addr(addr), len(len), delta(delta) {
        tag = "Ist_IMark";
    }

    std::vector<std::shared_ptr<IRExpr>> child_expressions() const override {
        return {};
    }

    void replace_expression(const std::unordered_map<std::shared_ptr<IRExpr>, std::shared_ptr<IRExpr>>& replacements) override {
        // No expressions to replace
    }

    std::string pp_str(const std::string& reg_name, const std::string& arch, const IRTypeEnv* tyenv) const override {
        char buf[64];
        snprintf(buf, sizeof(buf), "IMark(0x%lx, %d, %d)", addr, len, delta);
        return std::string(buf);
    }

    static std::shared_ptr<IMark> _from_c(const ::IRStmt* c_stmt) {
        return std::make_shared<IMark>(
            c_stmt->Ist.IMark.addr,
            c_stmt->Ist.IMark.len,
            c_stmt->Ist.IMark.delta
        );
    }
};

// AbiHint statement
class AbiHint : public IRStmt {
public:
    std::shared_ptr<IRExpr> base;
    int len;
    std::shared_ptr<IRExpr> nia;

    AbiHint(std::shared_ptr<IRExpr> base, int len, std::shared_ptr<IRExpr> nia)
        : base(base), len(len), nia(nia) {
        tag = "Ist_AbiHint";
    }

    std::vector<std::shared_ptr<IRExpr>> child_expressions() const override;

    void replace_expression(const std::unordered_map<std::shared_ptr<IRExpr>, std::shared_ptr<IRExpr>>& replacements) override;

    std::string pp_str(const std::string& reg_name, const std::string& arch, const IRTypeEnv* tyenv) const override {
        return "AbiHint(" + base->__str__() + ", " + std::to_string(len) + ", " + nia->__str__() + ")";
    }

    static std::shared_ptr<AbiHint> _from_c(const ::IRStmt* c_stmt);
};

// Put statement
class Put : public IRStmt {
public:
    std::shared_ptr<IRExpr> data;
    int offset;

    Put(std::shared_ptr<IRExpr> data, int offset) : data(data), offset(offset) {
        tag = "Ist_Put";
    }

    std::vector<std::shared_ptr<IRExpr>> child_expressions() const override;

    void replace_expression(const std::unordered_map<std::shared_ptr<IRExpr>, std::shared_ptr<IRExpr>>& replacements) override;

    std::string pp_str(const std::string& reg_name, const std::string& arch, const IRTypeEnv* tyenv) const override;

    static std::shared_ptr<Put> _from_c(const ::IRStmt* c_stmt);
};

// PutI statement  
class PutI : public IRStmt {
public:
    std::shared_ptr<IRRegArray> descr;
    std::shared_ptr<IRExpr> ix;
    std::shared_ptr<IRExpr> data;
    int bias;

    PutI(std::shared_ptr<IRRegArray> descr, std::shared_ptr<IRExpr> ix, 
         std::shared_ptr<IRExpr> data, int bias)
        : descr(descr), ix(ix), data(data), bias(bias) {
        tag = "Ist_PutI";
    }

    std::vector<std::shared_ptr<IRExpr>> child_expressions() const override;

    void replace_expression(const std::unordered_map<std::shared_ptr<IRExpr>, std::shared_ptr<IRExpr>>& replacements) override;

    std::string pp_str(const std::string& reg_name, const std::string& arch, const IRTypeEnv* tyenv) const override;

    static std::shared_ptr<PutI> _from_c(const ::IRStmt* c_stmt);
};

// WrTmp statement
class WrTmp : public IRStmt {
public:
    std::shared_ptr<IRExpr> data;
    int tmp;

    WrTmp(std::shared_ptr<IRExpr> data, int tmp) : data(data), tmp(tmp) {
        tag = "Ist_WrTmp";
    }

    std::vector<std::shared_ptr<IRExpr>> child_expressions() const override;

    void replace_expression(const std::unordered_map<std::shared_ptr<IRExpr>, std::shared_ptr<IRExpr>>& replacements) override;

    std::string pp_str(const std::string& reg_name, const std::string& arch, const IRTypeEnv* tyenv) const override;

    static std::shared_ptr<WrTmp> _from_c(const ::IRStmt* c_stmt);
};

// Store statement
class Store : public IRStmt {
public:
    std::shared_ptr<IRExpr> addr;
    std::shared_ptr<IRExpr> data;
    std::string end;

    Store(std::shared_ptr<IRExpr> addr, std::shared_ptr<IRExpr> data, const std::string& end)
        : addr(addr), data(data), end(end) {
        tag = "Ist_Store";
    }

    std::string endness() const { return end; }

    std::vector<std::shared_ptr<IRExpr>> child_expressions() const override;

    void replace_expression(const std::unordered_map<std::shared_ptr<IRExpr>, std::shared_ptr<IRExpr>>& replacements) override;

    std::string pp_str(const std::string& reg_name, const std::string& arch, const IRTypeEnv* tyenv) const override;

    static std::shared_ptr<Store> _from_c(const ::IRStmt* c_stmt);
};

// Exit statement
class Exit : public IRStmt {
public:
    std::shared_ptr<IRExpr> guard;
    std::shared_ptr<IRConst> dst;
    int offsIP;
    std::string jk;

    Exit(std::shared_ptr<IRExpr> guard, std::shared_ptr<IRConst> dst, int offsIP, const std::string& jk)
        : guard(guard), dst(dst), offsIP(offsIP), jk(jk) {
        tag = "Ist_Exit";
    }

    std::string jumpkind() const { return jk; }

    std::vector<std::shared_ptr<IRExpr>> child_expressions() const override;

    void replace_expression(const std::unordered_map<std::shared_ptr<IRExpr>, std::shared_ptr<IRExpr>>& replacements) override;

    std::string pp_str(const std::string& reg_name, const std::string& arch, const IRTypeEnv* tyenv) const override;

    static std::shared_ptr<Exit> _from_c(const ::IRStmt* c_stmt);
};

// Global mapping for statement type lookup
static std::unordered_map<int, std::function<std::shared_ptr<IRStmt>(const ::IRStmt*)>> enum_to_stmt_factory;

// Initialize statement type mapping
void _initialize_stmt_mapping() {
    enum_to_stmt_factory[Ist_NoOp] = [](const ::IRStmt* c_stmt) -> std::shared_ptr<IRStmt> {
        return NoOp::_from_c(c_stmt);
    };
    enum_to_stmt_factory[Ist_IMark] = [](const ::IRStmt* c_stmt) -> std::shared_ptr<IRStmt> {
        return IMark::_from_c(c_stmt);
    };
    enum_to_stmt_factory[Ist_AbiHint] = [](const ::IRStmt* c_stmt) -> std::shared_ptr<IRStmt> {
        return AbiHint::_from_c(c_stmt);
    };
    enum_to_stmt_factory[Ist_Put] = [](const ::IRStmt* c_stmt) -> std::shared_ptr<IRStmt> {
        return Put::_from_c(c_stmt);
    };
    enum_to_stmt_factory[Ist_PutI] = [](const ::IRStmt* c_stmt) -> std::shared_ptr<IRStmt> {
        return PutI::_from_c(c_stmt);
    };
    enum_to_stmt_factory[Ist_WrTmp] = [](const ::IRStmt* c_stmt) -> std::shared_ptr<IRStmt> {
        return WrTmp::_from_c(c_stmt);
    };
    enum_to_stmt_factory[Ist_Store] = [](const ::IRStmt* c_stmt) -> std::shared_ptr<IRStmt> {
        return Store::_from_c(c_stmt);
    };
    enum_to_stmt_factory[Ist_Exit] = [](const ::IRStmt* c_stmt) -> std::shared_ptr<IRStmt> {
        return Exit::_from_c(c_stmt);
    };
    // Add more statement types as needed...
}

// Factory method implementation
std::shared_ptr<IRStmt> IRStmt::_from_c(const ::IRStmt* c_stmt) {
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
    nb::class_<IRStmt>(m, "IRStmt")
        .def("pp", &IRStmt::pp)
        .def("child_expressions", &IRStmt::child_expressions)
        .def("expressions", &IRStmt::expressions)
        .def("constants", &IRStmt::constants)
        .def_static("_from_c", &IRStmt::_from_c, nb::rv_policy::take_ownership)
        .def("typecheck", &IRStmt::typecheck)
        .def("replace_expression", &IRStmt::replace_expression)
        .def("__str__", &IRStmt::__str__)
        .def("pp_str", &IRStmt::pp_str)
        .def_readwrite("tag", &IRStmt::tag)
        .def_readwrite("tag_int", &IRStmt::tag_int);

    // NoOp statement
    nb::class_<NoOp, IRStmt>(m, "NoOp")
        .def(nb::init<>())
        .def_static("_from_c", &NoOp::_from_c, nb::rv_policy::take_ownership);

    // IMark statement
    nb::class_<IMark, IRStmt>(m, "IMark")
        .def(nb::init<uint64_t, int, uint8_t>())
        .def_readwrite("addr", &IMark::addr)
        .def_readwrite("len", &IMark::len)
        .def_readwrite("delta", &IMark::delta)
        .def_static("_from_c", &IMark::_from_c, nb::rv_policy::take_ownership);

    // AbiHint statement
    nb::class_<AbiHint, IRStmt>(m, "AbiHint")
        .def(nb::init<std::shared_ptr<IRExpr>, int, std::shared_ptr<IRExpr>>())
        .def_readwrite("base", &AbiHint::base)
        .def_readwrite("len", &AbiHint::len)
        .def_readwrite("nia", &AbiHint::nia)
        .def_static("_from_c", &AbiHint::_from_c, nb::rv_policy::take_ownership);

    // Put statement
    nb::class_<Put, IRStmt>(m, "Put")
        .def(nb::init<std::shared_ptr<IRExpr>, int>())
        .def_readwrite("data", &Put::data)
        .def_readwrite("offset", &Put::offset)
        .def_static("_from_c", &Put::_from_c, nb::rv_policy::take_ownership);

    // PutI statement
    nb::class_<PutI, IRStmt>(m, "PutI")
        .def(nb::init<std::shared_ptr<IRRegArray>, std::shared_ptr<IRExpr>, std::shared_ptr<IRExpr>, int>())
        .def_readwrite("descr", &PutI::descr)
        .def_readwrite("ix", &PutI::ix)
        .def_readwrite("data", &PutI::data)
        .def_readwrite("bias", &PutI::bias)
        .def_static("_from_c", &PutI::_from_c, nb::rv_policy::take_ownership);

    // WrTmp statement
    nb::class_<WrTmp, IRStmt>(m, "WrTmp")
        .def(nb::init<std::shared_ptr<IRExpr>, int>())
        .def_readwrite("data", &WrTmp::data)
        .def_readwrite("tmp", &WrTmp::tmp)
        .def_static("_from_c", &WrTmp::_from_c, nb::rv_policy::take_ownership);

    // Store statement
    nb::class_<Store, IRStmt>(m, "Store")
        .def(nb::init<std::shared_ptr<IRExpr>, std::shared_ptr<IRExpr>, const std::string&>())
        .def_readwrite("addr", &Store::addr)
        .def_readwrite("data", &Store::data)
        .def_readwrite("end", &Store::end)
        .def_property_readonly("endness", &Store::endness)
        .def_static("_from_c", &Store::_from_c, nb::rv_policy::take_ownership);

    // Exit statement
    nb::class_<Exit, IRStmt>(m, "Exit")
        .def(nb::init<std::shared_ptr<IRExpr>, std::shared_ptr<IRConst>, int, const std::string&>())
        .def_readwrite("guard", &Exit::guard)
        .def_readwrite("dst", &Exit::dst)
        .def_readwrite("offsIP", &Exit::offsIP)
        .def_readwrite("jk", &Exit::jk)
        .def_property_readonly("jumpkind", &Exit::jumpkind)
        .def_static("_from_c", &Exit::_from_c, nb::rv_policy::take_ownership);
}