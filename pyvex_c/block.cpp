#include <nanobind/nanobind.h>
#include <nanobind/stl/string.h>
#include <memory>
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
extern "C" {
#include "pyvex.h"
}
#include "const.hpp"
#include "expr.hpp"
#include "stmt.hpp"
#include "typeenv.hpp"
#include "arches.hpp"

namespace nb = nanobind;
using namespace nb::literals;

// Forward declarations
class PyIRStmt;

// Data reference tracking
class PyDataRef {
public:
    uint64_t ins_addr;
    uint64_t mem_addr;
    int size;
    std::string data_type;

    PyDataRef(uint64_t ins_addr, uint64_t mem_addr, int size, const std::string& data_type)
        : ins_addr(ins_addr), mem_addr(mem_addr), size(size), data_type(data_type) {}

    std::string __str__() const {
        char buf[128];
        snprintf(buf, sizeof(buf), "<DataRef: 0x%lx -> 0x%lx (%d bytes, %s)>", 
                ins_addr, mem_addr, size, data_type.c_str());
        return std::string(buf);
    }
};

// Constant value tracking
class PyConstVal {
public:
    uint64_t ins_addr;
    std::shared_ptr<PyIRConst> value;

    PyConstVal(uint64_t ins_addr, std::shared_ptr<PyIRConst> value)
        : ins_addr(ins_addr), value(value) {}

    std::string __str__() const {
        char buf[64];
        snprintf(buf, sizeof(buf), "<ConstVal: 0x%lx -> %s>", ins_addr, value->__str__().c_str());
        return std::string(buf);
    }
};

// Main PyIRSB class
class PyIRSB {
public:
    // Core attributes
    uint64_t addr;
    std::shared_ptr<PyvexArch> arch;
    std::vector<std::shared_ptr<PyIRStmt>> statements;
    std::shared_ptr<PyIRExpr> next;
    std::shared_ptr<PyIRTypeEnv> _tyenv;
    std::string jumpkind;
    bool is_noop_block;

    // Cached properties
    mutable std::optional<bool> _direct_next;
    mutable std::optional<int> _size;
    mutable std::optional<int> _instructions;
    mutable std::optional<std::vector<std::shared_ptr<PyIRStmt>>> _exit_statements;
    mutable std::optional<uint64_t> default_exit_target;
    mutable std::optional<std::vector<uint64_t>> _instruction_addresses;

    // Analysis data
    std::vector<PyDataRef> data_refs;
    std::vector<PyConstVal> const_vals;

    // Constructor for empty block
    PyIRSB() : addr(0), arch(ARCH_AMD64), is_noop_block(false), jumpkind("Ijk_Boring") {
        _tyenv = std::make_shared<PyIRTypeEnv>();
    }

    // Constructor with lifting (simplified)
    PyIRSB(const nb::bytes& data, uint64_t mem_addr, ArchType arch_type,
         int max_inst = 99, int max_bytes = 800, int bytes_offset = 0,
         int traceflags = 0, int opt_level = 1)
        : addr(mem_addr), arch(arch_from_archtype(arch_type)), is_noop_block(false), jumpkind("Ijk_Boring") {
        _tyenv = std::make_shared<PyIRTypeEnv>();
        // TODO: Implement actual lifting via pyvex.lifting.lift()
        // For now, create empty block
    }

    // Properties with lazy evaluation
    int size() const {
        if (!_size.has_value()) {
            int total_size = 0;
            for (const auto& stmt : statements) {
                // Check if this is an IMark statement
                if (stmt->tag == "Ist_IMark") {
                    // Cast to IMark and get length
                    // This would need proper RTTI or visitor pattern
                    total_size += 1; // Simplified for now
                }
            }
            _size = total_size;
        }
        return _size.value();
    }

    int instructions() const {
        if (!_instructions.has_value()) {
            int count = 0;
            for (const auto& stmt : statements) {
                if (stmt->tag == "Ist_IMark") {
                    count++;
                }
            }
            _instructions = count;
        }
        return _instructions.value();
    }

    std::vector<uint64_t> instruction_addresses() const {
        if (!_instruction_addresses.has_value()) {
            std::vector<uint64_t> addrs;
            for (const auto& stmt : statements) {
                if (stmt->tag == "Ist_IMark") {
                    // Extract address from IMark
                    // This would need proper casting
                    addrs.push_back(addr); // Simplified
                }
            }
            _instruction_addresses = addrs;
        }
        return _instruction_addresses.value();
    }

    bool direct_next() const {
        if (!_direct_next.has_value()) {
            // Check if next is a constant
            if (next && next->tag == "Iex_Const") {
                _direct_next = true;
            } else {
                _direct_next = false;
            }
        }
        return _direct_next.value();
    }

    std::vector<std::shared_ptr<PyIRStmt>> exit_statements() const {
        if (!_exit_statements.has_value()) {
            std::vector<std::shared_ptr<PyIRStmt>> exits;
            for (const auto& stmt : statements) {
                if (stmt->tag == "Ist_Exit") {
                    exits.push_back(stmt);
                }
            }
            _exit_statements = exits;
        }
        return _exit_statements.value();
    }

    // Type environment access
    std::shared_ptr<PyIRTypeEnv> tyenv() const {
        return _tyenv;
    }

    // Block manipulation
    void extend(const PyIRSB& extendwith) {
        // Create tmp number mapping to avoid collisions
        std::unordered_map<int, int> conversion_dict;
        int next_tmp = _tyenv->types_used();
        
        // Extend type environment
        for (const auto& ty : extendwith._tyenv->types) {
            _tyenv->extend(ty);
        }

        // Add statements with tmp renumbering
        for (const auto& stmt : extendwith.statements) {
            // Deep copy and renumber temps
            auto new_stmt = deep_copy_and_renumber_stmt(stmt, conversion_dict, next_tmp);
            statements.push_back(new_stmt);
        }

        // Update next expression
        if (extendwith.next) {
            next = deep_copy_and_renumber_expr(extendwith.next, conversion_dict, next_tmp);
        }

        // Clear cached properties
        _clear_cache();
    }

    std::shared_ptr<PyIRSB> copy() const {
        auto new_block = std::make_shared<PyIRSB>();
        new_block->addr = addr;
        new_block->arch = arch;
        new_block->jumpkind = jumpkind;
        new_block->is_noop_block = is_noop_block;
        
        // Deep copy type environment
        new_block->_tyenv = std::make_shared<PyIRTypeEnv>(_tyenv->types, _tyenv->wordty);
        
        // Deep copy statements
        for (const auto& stmt : statements) {
            new_block->statements.push_back(deep_copy_stmt(stmt));
        }
        
        // Deep copy next expression
        if (next) {
            new_block->next = deep_copy_expr(next);
        }
        
        // Copy analysis data
        new_block->data_refs = data_refs;
        new_block->const_vals = const_vals;
        
        return new_block;
    }

    bool typecheck() const {
        // Basic type checking
        for (const auto& stmt : statements) {
            if (!stmt->typecheck(*_tyenv)) {
                return false;
            }
        }
        return true;
    }

    // Analysis methods
    std::vector<std::shared_ptr<PyIRExpr>> expressions() const {
        std::vector<std::shared_ptr<PyIRExpr>> all_exprs;
        for (const auto& stmt : statements) {
            auto stmt_exprs = stmt->child_expressions();
            all_exprs.insert(all_exprs.end(), stmt_exprs.begin(), stmt_exprs.end());
        }
        if (next) {
            auto next_exprs = next->child_expressions();
            all_exprs.insert(all_exprs.end(), next_exprs.begin(), next_exprs.end());
            all_exprs.push_back(next);
        }
        return all_exprs;
    }

    std::vector<std::shared_ptr<PyIRConst>> constants() const {
        std::vector<std::shared_ptr<PyIRConst>> all_consts;
        for (const auto& stmt : statements) {
            auto stmt_consts = stmt->constants();
            all_consts.insert(all_consts.end(), stmt_consts.begin(), stmt_consts.end());
        }
        return all_consts;
    }

    std::vector<std::string> operations() const {
        std::vector<std::string> ops;
        for (const auto& expr : expressions()) {
            // Extract operation names from expressions
            if (expr->tag == "Iex_Binop" || expr->tag == "Iex_Unop" || 
                expr->tag == "Iex_Triop" || expr->tag == "Iex_Qop") {
                // Extract op field - would need proper casting
                // ops.push_back(expr->op);
            }
        }
        return ops;
    }

    std::vector<uint64_t> constant_jump_targets() const {
        std::vector<uint64_t> targets;
        
        // Check default exit
        if (direct_next()) {
            // Extract constant value from next
            // targets.push_back(next->constant_value());
        }
        
        // Check conditional exits
        for (const auto& exit_stmt : exit_statements()) {
            // Extract target from exit statement
            // targets.push_back(exit_stmt->target());
        }
        
        return targets;
    }

    std::string __str__() const {
        std::string result = "IRSB {\n";
        for (const auto& stmt : statements) {
            result += "   " + stmt->__str__() + "\n";
        }
        if (next) {
            result += "   NEXT: PUT(rip) = " + next->__str__() + "; " + jumpkind + "\n";
        }
        result += "}";
        return result;
    }

    // Static factory methods
    static std::shared_ptr<PyIRSB> _from_c(const IRSB* c_irsb) {
        // FIXME: Not implemented yet
    }

private:
    void _clear_cache() const {
        _direct_next.reset();
        _size.reset();
        _instructions.reset();
        _exit_statements.reset();
        default_exit_target.reset();
        _instruction_addresses.reset();
    }

    // Helper methods for deep copying and renumbering
    std::shared_ptr<PyIRStmt> deep_copy_stmt(const std::shared_ptr<PyIRStmt>& stmt) const {
        // FIXME: Not implemented yet
    }
    std::shared_ptr<PyIRExpr> deep_copy_expr(const std::shared_ptr<PyIRExpr>& expr) const {
        // FIXME: Not implemented yet
    }
    std::shared_ptr<PyIRStmt> deep_copy_and_renumber_stmt(const std::shared_ptr<PyIRStmt>& stmt,
                                                        std::unordered_map<int, int>& conversion_dict,
                                                        int& next_tmp) const {
        // FIXME: Not implemented yet
    }
    std::shared_ptr<PyIRExpr> deep_copy_and_renumber_expr(const std::shared_ptr<PyIRExpr>& expr,
                                                        std::unordered_map<int, int>& conversion_dict,
                                                        int& next_tmp) const {
        // FIXME: Not implemented yet
    }
};

// Nanobind module definition
void bind_block(nb::module_& m) {
    // DataRef class
    nb::class_<PyDataRef>(m, "DataRef")
        .def(nb::init<uint64_t, uint64_t, int, const std::string&>())
        .def_rw("ins_addr", &PyDataRef::ins_addr)
        .def_rw("mem_addr", &PyDataRef::mem_addr)
        .def_rw("size", &PyDataRef::size)
        .def_rw("data_type", &PyDataRef::data_type)
        .def("__str__", &PyDataRef::__str__);

    // ConstVal class
    nb::class_<PyConstVal>(m, "ConstVal")
        .def(nb::init<uint64_t, std::shared_ptr<PyIRConst>>())
        .def_rw("ins_addr", &PyConstVal::ins_addr)
        .def_rw("value", &PyConstVal::value)
        .def("__str__", &PyConstVal::__str__);

    // PyIRSB class
    nb::class_<PyIRSB>(m, "IRSB")
        .def(nb::init<>())
        .def(nb::init<const nb::bytes&, uint64_t, ArchType, int, int, int, int, int>(),
            "data"_a, "mem_addr"_a, "arch"_a, "max_inst"_a = 99, "max_bytes"_a = 800,
            "bytes_offset"_a = 0, "traceflags"_a = 0, "opt_level"_a = 1)
        .def_rw("addr", &PyIRSB::addr)
        .def_rw("arch", &PyIRSB::arch)
        .def_rw("statements", &PyIRSB::statements)
        .def_rw("next", &PyIRSB::next)
        .def_rw("jumpkind", &PyIRSB::jumpkind)
        .def_rw("is_noop_block", &PyIRSB::is_noop_block)
        .def_rw("data_refs", &PyIRSB::data_refs)
        .def_rw("const_vals", &PyIRSB::const_vals)
        .def_prop_ro("size", &PyIRSB::size)
        .def_prop_ro("instructions", &PyIRSB::instructions)
        .def_prop_ro("instruction_addresses", &PyIRSB::instruction_addresses)
        .def_prop_ro("direct_next", &PyIRSB::direct_next)
        .def_prop_ro("exit_statements", &PyIRSB::exit_statements)
        .def_prop_ro("tyenv", &PyIRSB::tyenv)
        .def("extend", &PyIRSB::extend)
        .def("copy", &PyIRSB::copy)
        .def("typecheck", &PyIRSB::typecheck)
        .def("expressions", &PyIRSB::expressions)
        .def("constants", &PyIRSB::constants)
        .def("operations", &PyIRSB::operations)
        .def("constant_jump_targets", &PyIRSB::constant_jump_targets)
        .def("__str__", &PyIRSB::__str__)
        .def_static("_from_c", &PyIRSB::_from_c, nb::rv_policy::take_ownership);
}