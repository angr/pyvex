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
#include "typeenv.hpp"
#include "enums.hpp"

namespace nb = nanobind;

void PyIRExpr::pp() const {
    nb::print(nb::str(__str__().c_str()));
}

// Binder expression
class PyBinder : public PyIRExpr {
public:
    int binder;

    PyBinder(int binder) : binder(binder) {
        tag = "Iex_Binder";
    }

    std::string _pp_str() const override {
        return "BIND(" + std::to_string(binder) + ")";
    }

    std::vector<std::shared_ptr<PyIRConst>> constants() const override {
        return {};
    }

    std::vector<std::shared_ptr<PyIRExpr>> child_expressions() const override {
        return {};
    }

    std::string result_type(const PyIRTypeEnv& tyenv) const override {
        return "Ity_INVALID";
    }

    int result_size(const PyIRTypeEnv& tyenv) const override {
        return 0;
    }

    bool typecheck(const PyIRTypeEnv& tyenv) const override {
        return true;
    }

    void replace_expression(const std::unordered_map<std::shared_ptr<PyIRExpr>, std::shared_ptr<PyIRExpr>>& replacements) override {
        // No expressions to replace
    }

    static std::shared_ptr<PyBinder> _from_c(const IRExpr* c_expr) {
        return std::make_shared<PyBinder>(c_expr->Iex.Binder.binder);
    }
};

// VECRET expression
class PyVECRET : public PyIRExpr {
public:
    PyVECRET() {
        tag = "Iex_VECRET";
    }

    std::string _pp_str() const override {
        return "VECRET";
    }

    std::vector<std::shared_ptr<PyIRExpr>> child_expressions() const override {
        return {};
    }

    std::vector<std::shared_ptr<PyIRConst>> constants() const override {
        return {};
    }

    std::string result_type(const PyIRTypeEnv& tyenv) const override {
        return "Ity_V128";
    }

    int result_size(const PyIRTypeEnv& tyenv) const override {
        return 0;
    }

    bool typecheck(const PyIRTypeEnv& tyenv) const override {
        return true;
    }

    void replace_expression(const std::unordered_map<std::shared_ptr<PyIRExpr>, std::shared_ptr<PyIRExpr>>& replacements) override {
        // No expressions to replace
    }

    static std::shared_ptr<PyVECRET> _from_c(const IRExpr* c_expr) {
        return std::make_shared<PyVECRET>();
    }
};

// GSPTR expression
class PyGSPTR : public PyIRExpr {
public:
    PyGSPTR() {
        tag = "Iex_GSPTR";
    }

    std::string _pp_str() const override {
        return "GSPTR";
    }

    std::vector<std::shared_ptr<PyIRConst>> constants() const override {
        return {};
    }

    std::vector<std::shared_ptr<PyIRExpr>> child_expressions() const override {
        return {};
    }

    std::string result_type(const PyIRTypeEnv& tyenv) const override {
        return "Ity_I64";  // Usually word-sized pointer
    }

    int result_size(const PyIRTypeEnv& tyenv) const override {
        return 0;
    }

    bool typecheck(const PyIRTypeEnv& tyenv) const override {
        return true;
    }

    void replace_expression(const std::unordered_map<std::shared_ptr<PyIRExpr>, std::shared_ptr<PyIRExpr>>& replacements) override {
        // No expressions to replace
    }

    static std::shared_ptr<PyGSPTR> _from_c(const IRExpr* c_expr) {
        return std::make_shared<PyGSPTR>();
    }
};

// GetI expression
class PyGetI : public PyIRExpr {
public:
    std::shared_ptr<PyIRRegArray> descr;
    std::shared_ptr<PyIRExpr> ix;
    int bias;

    PyGetI(std::shared_ptr<PyIRRegArray> descr, std::shared_ptr<PyIRExpr> ix, int bias)
        : descr(descr), ix(ix), bias(bias) {
        tag = "Iex_GetI";
    }

    std::shared_ptr<PyIRRegArray> description() const { return descr; }
    std::shared_ptr<PyIRExpr> index() const { return ix; }

    std::string _pp_str() const override {
        return "GetI(" + descr->elemTy + ", " + ix->_pp_str() + ", " + std::to_string(bias) + ")";
    }

    std::vector<std::shared_ptr<PyIRExpr>> child_expressions() const override {
        return {ix};
    }

    std::vector<std::shared_ptr<PyIRConst>> constants() const override {
        return {};
    }

    std::string result_type(const PyIRTypeEnv& tyenv) const override {
        return descr->elemTy;
    }

    int result_size(const PyIRTypeEnv& tyenv) const override {
        return 0;
    }

    bool typecheck(const PyIRTypeEnv& tyenv) const override {
        return true;
    }

    void replace_expression(const std::unordered_map<std::shared_ptr<PyIRExpr>, std::shared_ptr<PyIRExpr>>& replacements) override {
        // No expressions to replace
    }

    static std::shared_ptr<PyGetI> _from_c(const IRExpr* c_expr) {
        return std::make_shared<PyGetI>(PyIRRegArray::_from_c(c_expr->Iex.GetI.descr), PyIRExpr::_from_c(c_expr->Iex.GetI.ix), c_expr->Iex.GetI.bias);
    }
};

// RdTmp expression with instance pooling
class PyRdTmp : public PyIRExpr {
public:
    int tmp;

    PyRdTmp(int tmp_) : tmp(tmp_) {
        tag = "Iex_RdTmp";
    }

    std::string _pp_str() const override {
        return "t" + std::to_string(tmp);
    }

    std::vector<std::shared_ptr<PyIRConst>> constants() const override {
        return {};
    }

    std::vector<std::shared_ptr<PyIRExpr>> child_expressions() const override {
        return {};
    }

    std::string result_type(const PyIRTypeEnv& tyenv) const override {
        return "Ity_INVALID"; // FIXME
    }

    int result_size(const PyIRTypeEnv& tyenv) const override {
        return 0;
    }

    bool typecheck(const PyIRTypeEnv& tyenv) const override {
        return true;
    }

    void replace_expression(const std::unordered_map<std::shared_ptr<PyIRExpr>, std::shared_ptr<PyIRExpr>>& replacements) override {
        // No expressions to replace
    }

    static std::shared_ptr<PyRdTmp> get_instance(int tmp) {
        if (_pool.find(tmp) == _pool.end()) {
            _pool[tmp] = std::make_shared<PyRdTmp>(tmp);
        }
        return _pool[tmp];
    }

    static std::shared_ptr<PyRdTmp> _from_c(const IRExpr* c_expr) {
        return get_instance(c_expr->Iex.RdTmp.tmp);
    }

private:
    static inline std::unordered_map<int, std::shared_ptr<PyRdTmp>> _pool;
};

// Get expression
class PyGet : public PyIRExpr {
public:
    int offset;
    int ty_int;

    PyGet(int offset, int ty_int) : offset(offset), ty_int(ty_int) {
        tag = "Iex_Get";
    }

    std::string ty() const { return "Ity_INVALID"; }
    std::string type() const { return ty(); }

    std::string _pp_str() const override {
        return "Get(" + std::to_string(offset) + ", " + std::to_string(ty_int) + ")";
    }

    std::vector<std::shared_ptr<PyIRConst>> constants() const override {
        return {};
    }

    std::vector<std::shared_ptr<PyIRExpr>> child_expressions() const override {
        return {};
    }

    std::string result_type(const PyIRTypeEnv& tyenv) const override {
        return ty();
    }

    int result_size(const PyIRTypeEnv& tyenv) const override {
        return 0;
    }

    bool typecheck(const PyIRTypeEnv& tyenv) const override {
        return true;
    }

    void replace_expression(const std::unordered_map<std::shared_ptr<PyIRExpr>, std::shared_ptr<PyIRExpr>>& replacements) override {
        // No expressions to replace
    }

    static std::shared_ptr<PyGet> _from_c(const IRExpr* c_expr) {
        // FIXME: Not implemented yet
        // return std::make_shared<PyGet>(c_expr->Iex.Get.offset, c_expr->Iex.Get.ty_int);
    }
};

// Qop expression (quaternary operation)
class PyQop : public PyIRExpr {
public:
    std::string op;
    std::vector<std::shared_ptr<PyIRExpr>> args;

    PyQop(const std::string& op, const std::vector<std::shared_ptr<PyIRExpr>>& args)
        : op(op), args(args) {
        tag = "Iex_Qop";
        if (args.size() != 4) {
            throw std::runtime_error("Qop requires exactly 4 arguments");
        }
    }

    std::string _pp_str() const override {
        return "Qop(" + op + ", " + args[0]->__str__() + ", " + args[1]->__str__() + ", " + args[2]->__str__() + ", " + args[3]->__str__() + ")";
    }

    std::vector<std::shared_ptr<PyIRExpr>> child_expressions() const override {
        return args;
    }

    std::vector<std::shared_ptr<PyIRConst>> constants() const override {
        return {};
    }

    std::string result_type(const PyIRTypeEnv& tyenv) const override {
        return "Ity_INVALID";
    }

    int result_size(const PyIRTypeEnv& tyenv) const override {
        return 0;
    }

    bool typecheck(const PyIRTypeEnv& tyenv) const override {
        return true;
    }

    void replace_expression(const std::unordered_map<std::shared_ptr<PyIRExpr>, std::shared_ptr<PyIRExpr>>& replacements) override {
        // No expressions to replace
    }

    static std::shared_ptr<PyQop> _from_c(const IRExpr* c_expr) {
        // FIXME: Not implemented yet
        // return std::make_shared<PyQop>(c_expr->Iex.Qop.op, PyIRExpr::_from_c(c_expr->Iex.Qop.args));
    }
};

// Triop expression (ternary operation)
class PyTriop : public PyIRExpr {
public:
    std::string op;
    std::vector<std::shared_ptr<PyIRExpr>> args;

    PyTriop(const std::string& op, const std::vector<std::shared_ptr<PyIRExpr>>& args)
        : op(op), args(args) {
        tag = "Iex_Triop";
        if (args.size() != 3) {
            throw std::runtime_error("Triop requires exactly 3 arguments");
        }
    }

    std::string _pp_str() const override {
        return "Triop(" + op + ", " + args[0]->__str__() + ", " + args[1]->__str__() + ", " + args[2]->__str__() + ")";
    }

    std::vector<std::shared_ptr<PyIRConst>> constants() const override {
        return {};
    }

    std::vector<std::shared_ptr<PyIRExpr>> child_expressions() const override {
        return args;
    }

    std::string result_type(const PyIRTypeEnv& tyenv) const override {
        return "Ity_INVALID";
    }

    int result_size(const PyIRTypeEnv& tyenv) const override {
        return 0;
    }

    bool typecheck(const PyIRTypeEnv& tyenv) const override {
        return true;
    }

    void replace_expression(const std::unordered_map<std::shared_ptr<PyIRExpr>, std::shared_ptr<PyIRExpr>>& replacements) override {
        // No expressions to replace
    }

    static std::shared_ptr<PyTriop> _from_c(const IRExpr* c_expr) {
        // FIXME: Not implemented yet
        // return std::make_shared<PyTriop>(c_expr->Iex.Triop.op, PyIRExpr::_from_c(c_expr->Iex.Triop.args));
    }
};

// Binop expression (binary operation)
class PyBinop : public PyIRExpr {
public:
    std::string op;
    int op_int;
    std::vector<std::shared_ptr<PyIRExpr>> args;

    PyBinop(const std::string& op_, const std::vector<std::shared_ptr<PyIRExpr>>& args)
        : op(op_), args(args) {
        tag = "Iex_Binop";
        if (args.size() != 2) {
            throw std::runtime_error("Binop requires exactly 2 arguments");
        }
    }

    std::string _pp_str() const override {
        return "Binop(" + op + ", " + args[0]->__str__() + ", " + args[1]->__str__() + ")";
    }

    std::vector<std::shared_ptr<PyIRExpr>> child_expressions() const override {
        return args;
    }

    std::vector<std::shared_ptr<PyIRConst>> constants() const override {
        return {};
    }

    std::string result_type(const PyIRTypeEnv& tyenv) const override {
        return "Ity_INVALID";
    }

    int result_size(const PyIRTypeEnv& tyenv) const override {
        return 0;
    }

    bool typecheck(const PyIRTypeEnv& tyenv) const override {
        return true;
    }

    void replace_expression(const std::unordered_map<std::shared_ptr<PyIRExpr>, std::shared_ptr<PyIRExpr>>& replacements) override {
        // No expressions to replace
    }

    static std::shared_ptr<PyBinop> _from_c(const IRExpr* c_expr) {
        // FIXME: Not implemented yet
        // return std::make_shared<PyBinop>(c_expr->Iex.Binop.op, PyIRExpr::_from_c(c_expr->Iex.Binop.args));
    }
};

// Unop expression (unary operation)
class PyUnop : public PyIRExpr {
public:
    std::string op;
    std::vector<std::shared_ptr<PyIRExpr>> args;

    PyUnop(const std::string& op, const std::vector<std::shared_ptr<PyIRExpr>>& args)
        : op(op), args(args) {
        tag = "Iex_Unop";
        if (args.size() != 1) {
            throw std::runtime_error("Unop requires exactly 1 argument");
        }
    }

    std::string _pp_str() const override {
        return "Unop(" + op + ", " + args[0]->__str__() + ")";
    }

    std::vector<std::shared_ptr<PyIRExpr>> child_expressions() const override {
        return args;
    }

    std::vector<std::shared_ptr<PyIRConst>> constants() const override {
        return {};
    }

    std::string result_type(const PyIRTypeEnv& tyenv) const override {
        return "Ity_INVALID";
    }

    int result_size(const PyIRTypeEnv& tyenv) const override {
        return 0;
    }

    bool typecheck(const PyIRTypeEnv& tyenv) const override {
        return true;
    }

    void replace_expression(const std::unordered_map<std::shared_ptr<PyIRExpr>, std::shared_ptr<PyIRExpr>>& replacements) override {
        // No expressions to replace
    }

    static std::shared_ptr<PyUnop> _from_c(const IRExpr* c_expr) {
        // FIXME: Not implemented yet
        // return std::make_shared<PyUnop>(c_expr->Iex.Unop.op, PyIRExpr::_from_c(c_expr->Iex.Unop.args));
    }
};

// Load expression
class PyLoad : public PyIRExpr {
public:
    std::string end;
    std::string ty;
    std::shared_ptr<PyIRExpr> addr;

    PyLoad(const std::string& end, const std::string& ty, std::shared_ptr<PyIRExpr> addr)
        : end(end), ty(ty), addr(addr) {
        tag = "Iex_Load";
    }

    std::string endness() const { return end; }
    std::string type() const { return ty; }

    std::string _pp_str() const override {
        return "Load(" + end + ", " + ty + ", " + addr->__str__() + ")";
    }

    std::vector<std::shared_ptr<PyIRExpr>> child_expressions() const override {
        return {addr};
    }

    std::vector<std::shared_ptr<PyIRConst>> constants() const override {
        return {};
    }

    std::string result_type(const PyIRTypeEnv& tyenv) const override {
        return ty;
    }

    int result_size(const PyIRTypeEnv& tyenv) const override {
        return 0;
    }

    bool typecheck(const PyIRTypeEnv& tyenv) const override {
        return true;
    }

    void replace_expression(const std::unordered_map<std::shared_ptr<PyIRExpr>, std::shared_ptr<PyIRExpr>>& replacements) override {
        // No expressions to replace
    }

    static std::shared_ptr<PyLoad> _from_c(const IRExpr* c_expr) {
        // FIXME: Not implemented yet
        // return std::make_shared<PyLoad>(c_expr->Iex.Load.end, c_expr->Iex.Load.ty, PyIRExpr::_
    }
};

// Const expression with instance pooling
class PyConst : public PyIRExpr {
public:
    std::shared_ptr<PyIRConst> _con;

    PyConst(std::shared_ptr<PyIRConst> con) : _con(con) {
        tag = "Iex_Const";
    }

    std::shared_ptr<PyIRConst> con() const { return _con; }

    std::string _pp_str() const override {
        return "Const(" + _con->__str__() + ")";
    }

    std::vector<std::shared_ptr<PyIRConst>> constants() const override {
        return {};
    }

    std::vector<std::shared_ptr<PyIRExpr>> child_expressions() const override {
        return {};
    }

    std::string result_type(const PyIRTypeEnv& tyenv) const override {
        return "Ity_INVALID";
    }

    int result_size(const PyIRTypeEnv& tyenv) const override {
        return 0;
    }

    bool typecheck(const PyIRTypeEnv& tyenv) const override {
        return true;
    }

    void replace_expression(const std::unordered_map<std::shared_ptr<PyIRExpr>, std::shared_ptr<PyIRExpr>>& replacements) override {
        // No expressions to replace
    }

    static std::shared_ptr<PyConst> get_instance(std::shared_ptr<PyIRConst> con) {
        return std::make_shared<PyConst>(con);
    }

    static std::shared_ptr<PyConst> _from_c(const IRExpr* c_expr) {
        // FIXME: Not implemented yet
        // return std::make_shared<PyConst>(PyIRConst::_from_c(c_expr->Iex.Const.con));
    }

private:
    static std::unordered_map<uint64_t, std::shared_ptr<PyConst>> _pool;
};

// ITE expression (if-then-else)
class PyITE : public PyIRExpr {
public:
    std::shared_ptr<PyIRExpr> cond;
    std::shared_ptr<PyIRExpr> iffalse;
    std::shared_ptr<PyIRExpr> iftrue;

    PyITE(std::shared_ptr<PyIRExpr> cond, std::shared_ptr<PyIRExpr> iftrue, std::shared_ptr<PyIRExpr> iffalse)
        : cond(cond), iffalse(iffalse), iftrue(iftrue) {
        tag = "Iex_ITE";
    }

    std::string _pp_str() const override {
        return "ITE(" + cond->_pp_str() + ", " + iftrue->_pp_str() + ", " + iffalse->_pp_str() + ")";
    }

    std::vector<std::shared_ptr<PyIRExpr>> child_expressions() const override {
        return {cond, iftrue, iffalse};
    }

    std::vector<std::shared_ptr<PyIRConst>> constants() const override {
        return {};
    }

    std::string result_type(const PyIRTypeEnv& tyenv) const override {
        return "Ity_INVALID";
    }

    int result_size(const PyIRTypeEnv& tyenv) const override {
        return 0;
    }

    bool typecheck(const PyIRTypeEnv& tyenv) const override {
        return true;
    }

    void replace_expression(const std::unordered_map<std::shared_ptr<PyIRExpr>, std::shared_ptr<PyIRExpr>>& replacements) override {
        // No expressions to replace
    }

    static std::shared_ptr<PyITE> _from_c(const IRExpr* c_expr) {
        // FIXME: Not implemented yet
        // return std::make_shared<PyITE>(PyIRExpr::_from_c(c_expr->Iex.ITE.cond), PyIRExpr::_from_c(c_expr->Iex.ITE.iftrue), PyIRExpr::_from_c(c_expr->Iex.ITE.iffalse));
    }
};

// CCall expression
class PyCCall : public PyIRExpr {
public:
    std::string retty;
    std::shared_ptr<PyIRCallee> cee;
    std::vector<std::shared_ptr<PyIRExpr>> args;

    PyCCall(const std::string& retty, std::shared_ptr<PyIRCallee> cee, const std::vector<std::shared_ptr<PyIRExpr>>& args)
        : retty(retty), cee(cee), args(args) {
        tag = "Iex_CCall";
    }

    std::string ret_type() const { return retty; }
    std::shared_ptr<PyIRCallee> callee() const { return cee; }

    std::string _pp_str() const override {
        return "CCall(" + retty + ", " + cee->__str__() + ", " + args[0]->__str__() + ", " + args[1]->__str__() + ", " + args[2]->__str__() + ")";
    }

    std::vector<std::shared_ptr<PyIRExpr>> child_expressions() const override {
        return args;
    }

    std::vector<std::shared_ptr<PyIRConst>> constants() const override {
        return {};
    }

    std::string result_type(const PyIRTypeEnv& tyenv) const override {
        return retty;
    }

    int result_size(const PyIRTypeEnv& tyenv) const override {
        return 0;
    }

    bool typecheck(const PyIRTypeEnv& tyenv) const override {
        return true;
    }

    void replace_expression(const std::unordered_map<std::shared_ptr<PyIRExpr>, std::shared_ptr<PyIRExpr>>& replacements) override {
        // No expressions to replace
    }

    static std::shared_ptr<PyCCall> _from_c(const IRExpr* c_expr) {
        // FIXME: Not implemented yet
        // return std::make_shared<PyCCall>(c_expr->Iex.CCall.retty, PyIRCallee::_from_c(c_expr->Iex.CCall.cee), PyIRExpr::_from_c(c_expr->Iex.CCall.args));
    }
};

// Global mapping for expression type lookup
static std::unordered_map<int, std::function<std::shared_ptr<PyIRExpr>(const IRExpr*)>> enum_to_expr_factory;

// Initialize expression type mapping
void _initialize_expr_mapping() {
    enum_to_expr_factory[Iex_Binder] = [](const IRExpr* c_expr) -> std::shared_ptr<PyIRExpr> {
        return PyBinder::_from_c(c_expr);
    };
    enum_to_expr_factory[Iex_VECRET] = [](const IRExpr* c_expr) -> std::shared_ptr<PyIRExpr> {
        return PyVECRET::_from_c(c_expr);
    };
    enum_to_expr_factory[Iex_GSPTR] = [](const IRExpr* c_expr) -> std::shared_ptr<PyIRExpr> {
        return PyGSPTR::_from_c(c_expr);
    };
    enum_to_expr_factory[Iex_GetI] = [](const IRExpr* c_expr) -> std::shared_ptr<PyIRExpr> {
        return PyGetI::_from_c(c_expr);
    };
    enum_to_expr_factory[Iex_RdTmp] = [](const IRExpr* c_expr) -> std::shared_ptr<PyIRExpr> {
        return PyRdTmp::_from_c(c_expr);
    };
    enum_to_expr_factory[Iex_Get] = [](const IRExpr* c_expr) -> std::shared_ptr<PyIRExpr> {
        return PyGet::_from_c(c_expr);
    };
    enum_to_expr_factory[Iex_Qop] = [](const IRExpr* c_expr) -> std::shared_ptr<PyIRExpr> {
        return PyQop::_from_c(c_expr);
    };
    enum_to_expr_factory[Iex_Triop] = [](const IRExpr* c_expr) -> std::shared_ptr<PyIRExpr> {
        return PyTriop::_from_c(c_expr);
    };
    enum_to_expr_factory[Iex_Binop] = [](const IRExpr* c_expr) -> std::shared_ptr<PyIRExpr> {
        return PyBinop::_from_c(c_expr);
    };
    enum_to_expr_factory[Iex_Unop] = [](const IRExpr* c_expr) -> std::shared_ptr<PyIRExpr> {
        return PyUnop::_from_c(c_expr);
    };
    enum_to_expr_factory[Iex_Load] = [](const IRExpr* c_expr) -> std::shared_ptr<PyIRExpr> {
        return PyLoad::_from_c(c_expr);
    };
    enum_to_expr_factory[Iex_Const] = [](const IRExpr* c_expr) -> std::shared_ptr<PyIRExpr> {
        return PyConst::_from_c(c_expr);
    };
    enum_to_expr_factory[Iex_ITE] = [](const IRExpr* c_expr) -> std::shared_ptr<PyIRExpr> {
        return PyITE::_from_c(c_expr);
    };
    enum_to_expr_factory[Iex_CCall] = [](const IRExpr* c_expr) -> std::shared_ptr<PyIRExpr> {
        return PyCCall::_from_c(c_expr);
    };
}

// Factory method implementation
std::shared_ptr<PyIRExpr> PyIRExpr::_from_c(const IRExpr* c_expr) {
    if (!c_expr) return nullptr;
    
    auto it = enum_to_expr_factory.find(c_expr->tag);
    if (it != enum_to_expr_factory.end()) {
        return it->second(c_expr);
    }
    
    throw std::runtime_error("Unknown/unsupported IRExprTag: " + std::to_string(c_expr->tag));
}

// Nanobind module definition
void bind_expr(nb::module_& m) {
    // Initialize expression mapping
    _initialize_expr_mapping();

    // Base IRExpr class
    nb::class_<PyIRExpr>(m, "IRExpr")
        .def("pp", &PyIRExpr::pp)
        .def("__str__", &PyIRExpr::__str__)
        .def("_pp_str", &PyIRExpr::_pp_str)
        .def("child_expressions", &PyIRExpr::child_expressions)
        .def("constants", &PyIRExpr::constants)
        .def("result_size", &PyIRExpr::result_size)
        .def("result_type", &PyIRExpr::result_type)
        .def("replace_expression", &PyIRExpr::replace_expression)
        .def("typecheck", &PyIRExpr::typecheck)
        .def_static("_from_c", &PyIRExpr::_from_c, nb::rv_policy::take_ownership)
        // .def_static("_to_c", &PyIRExpr::_to_c, nb::rv_policy::take_ownership)
        .def_static("_translate", &PyIRExpr::_translate, nb::rv_policy::take_ownership)
        .def_rw("tag", &PyIRExpr::tag);

    // All expression subclasses
    nb::class_<PyBinder, PyIRExpr>(m, "Binder")
        .def(nb::init<int>())
        .def_rw("binder", &PyBinder::binder)
        .def_static("_from_c", &PyBinder::_from_c, nb::rv_policy::take_ownership);

    nb::class_<PyVECRET, PyIRExpr>(m, "VECRET")
        .def(nb::init<>())
        .def_static("_from_c", &PyVECRET::_from_c, nb::rv_policy::take_ownership);

    nb::class_<PyGSPTR, PyIRExpr>(m, "GSPTR")
        .def(nb::init<>())
        .def_static("_from_c", &PyGSPTR::_from_c, nb::rv_policy::take_ownership);

    nb::class_<PyGetI, PyIRExpr>(m, "GetI")
        .def(nb::init<std::shared_ptr<PyIRRegArray>, std::shared_ptr<PyIRExpr>, int>())
        .def_rw("descr", &PyGetI::descr)
        .def_rw("ix", &PyGetI::ix)
        .def_rw("bias", &PyGetI::bias)
        .def_prop_ro("description", &PyGetI::description)
        .def_prop_ro("index", &PyGetI::index)
        .def_static("_from_c", &PyGetI::_from_c, nb::rv_policy::take_ownership);

    nb::class_<PyRdTmp, PyIRExpr>(m, "RdTmp")
        .def(nb::init<int>())
        .def_rw("tmp", &PyRdTmp::tmp)
        .def_static("get_instance", &PyRdTmp::get_instance, nb::rv_policy::take_ownership)
        .def_static("_from_c", &PyRdTmp::_from_c, nb::rv_policy::take_ownership);

    nb::class_<PyGet, PyIRExpr>(m, "Get")
        .def(nb::init<int, int>())
        .def_rw("offset", &PyGet::offset)
        .def_rw("ty_int", &PyGet::ty_int)
        .def_prop_ro("ty", &PyGet::ty)
        .def_prop_ro("type", &PyGet::type)
        .def_static("_from_c", &PyGet::_from_c, nb::rv_policy::take_ownership);

    nb::class_<PyQop, PyIRExpr>(m, "Qop")
        .def(nb::init<std::string, std::vector<std::shared_ptr<PyIRExpr>>>())
        .def_rw("op", &PyQop::op)
        .def_rw("args", &PyQop::args)
        .def_static("_from_c", &PyQop::_from_c, nb::rv_policy::take_ownership);

    nb::class_<PyTriop, PyIRExpr>(m, "Triop")
        .def(nb::init<std::string, std::vector<std::shared_ptr<PyIRExpr>>>())
        .def_rw("op", &PyTriop::op)
        .def_rw("args", &PyTriop::args)
        .def_static("_from_c", &PyTriop::_from_c, nb::rv_policy::take_ownership);

    nb::class_<PyBinop, PyIRExpr>(m, "Binop")
        .def(nb::init<std::string, std::vector<std::shared_ptr<PyIRExpr>>>())
        .def_rw("op", &PyBinop::op)
        .def_rw("args", &PyBinop::args)
        .def_static("_from_c", &PyBinop::_from_c, nb::rv_policy::take_ownership);

    nb::class_<PyUnop, PyIRExpr>(m, "Unop")
        .def(nb::init<std::string, std::vector<std::shared_ptr<PyIRExpr>>>())
        .def_rw("op", &PyUnop::op)
        .def_rw("args", &PyUnop::args)
        .def_static("_from_c", &PyUnop::_from_c, nb::rv_policy::take_ownership);

    nb::class_<PyLoad, PyIRExpr>(m, "Load")
        .def(nb::init<std::string, std::string, std::shared_ptr<PyIRExpr>>())
        .def_rw("end", &PyLoad::end)
        .def_rw("ty", &PyLoad::ty)
        .def_rw("addr", &PyLoad::addr)
        .def_static("_from_c", &PyLoad::_from_c, nb::rv_policy::take_ownership);

    nb::class_<PyConst, PyIRExpr>(m, "Const")
        .def(nb::init<std::shared_ptr<PyIRConst>>())
        // .def_rw("con", &PyConst::con)
        .def_static("_from_c", &PyConst::_from_c, nb::rv_policy::take_ownership);

    nb::class_<PyITE, PyIRExpr>(m, "ITE")
        .def(nb::init<std::shared_ptr<PyIRExpr>, std::shared_ptr<PyIRExpr>, std::shared_ptr<PyIRExpr>>())
        .def_rw("cond", &PyITE::cond)
        .def_rw("iffalse", &PyITE::iffalse)
        .def_rw("iftrue", &PyITE::iftrue)
        .def_static("_from_c", &PyITE::_from_c, nb::rv_policy::take_ownership);
}