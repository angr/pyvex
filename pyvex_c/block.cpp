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
class IRStmt;
class IRExpr;
class IRConst;

// IRTypeEnv class for managing temporary variable types
class IRTypeEnv {
public:
    std::vector<std::string> types;
    std::string wordty;

    IRTypeEnv() : wordty("Ity_I64") {}

    IRTypeEnv(const std::vector<std::string>& types, const std::string& wordty)
        : types(types), wordty(wordty) {}

    void extend(const std::string& ty) {
        types.push_back(ty);
    }

    std::string lookup(int tmp) const {
        if (tmp >= 0 && tmp < static_cast<int>(types.size())) {
            return types[tmp];
        }
        throw std::runtime_error("Invalid temporary number: " + std::to_string(tmp));
    }

    size_t types_used() const {
        return types.size();
    }

    std::string __str__() const {
        std::string result = "IRTypeEnv([";
        for (size_t i = 0; i < types.size(); ++i) {
            if (i > 0) result += ", ";
            result += types[i];
        }
        result += "])";
        return result;
    }

    static std::shared_ptr<IRTypeEnv> _from_c(const ::IRTypeEnv* c_tyenv);
};

// Data reference tracking
class DataRef {
public:
    uint64_t ins_addr;
    uint64_t mem_addr;
    int size;
    std::string data_type;

    DataRef(uint64_t ins_addr, uint64_t mem_addr, int size, const std::string& data_type)
        : ins_addr(ins_addr), mem_addr(mem_addr), size(size), data_type(data_type) {}

    std::string __str__() const {
        char buf[128];
        snprintf(buf, sizeof(buf), "<DataRef: 0x%lx -> 0x%lx (%d bytes, %s)>", 
                ins_addr, mem_addr, size, data_type.c_str());
        return std::string(buf);
    }
};

// Constant value tracking
class ConstVal {
public:
    uint64_t ins_addr;
    std::shared_ptr<IRConst> value;

    ConstVal(uint64_t ins_addr, std::shared_ptr<IRConst> value)
        : ins_addr(ins_addr), value(value) {}

    std::string __str__() const {
        char buf[64];
        snprintf(buf, sizeof(buf), "<ConstVal: 0x%lx -> %s>", ins_addr, value->__str__().c_str());
        return std::string(buf);
    }
};

// Main IRSB class
class IRSB {
public:
    // Core attributes
    uint64_t addr;
    std::string arch;  // Architecture name (simplified)
    std::vector<std::shared_ptr<IRStmt>> statements;
    std::shared_ptr<IRExpr> next;
    std::shared_ptr<IRTypeEnv> _tyenv;
    std::string jumpkind;
    bool is_noop_block;

    // Cached properties
    mutable std::optional<bool> _direct_next;
    mutable std::optional<int> _size;
    mutable std::optional<int> _instructions;
    mutable std::optional<std::vector<std::shared_ptr<IRStmt>>> _exit_statements;
    mutable std::optional<uint64_t> default_exit_target;
    mutable std::optional<std::vector<uint64_t>> _instruction_addresses;

    // Analysis data
    std::vector<DataRef> data_refs;
    std::vector<ConstVal> const_vals;

    // Constants
    static const int MAX_EXITS = 400;
    static const int MAX_DATA_REFS = 2000;
    static const int MAX_CONST_VALS = 1000;

    // Constructor for empty block
    IRSB() : addr(0), arch("unknown"), is_noop_block(false), jumpkind("Ijk_Boring") {
        _tyenv = std::make_shared<IRTypeEnv>();
    }

    // Constructor with lifting (simplified)
    IRSB(const std::vector<uint8_t>& data, uint64_t mem_addr, const std::string& arch_name,
         int max_inst = 99, int max_bytes = 800, int bytes_offset = 0,
         int traceflags = 0, int opt_level = 1)
        : addr(mem_addr), arch(arch_name), is_noop_block(false), jumpkind("Ijk_Boring") {
        _tyenv = std::make_shared<IRTypeEnv>();
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

    std::vector<std::shared_ptr<IRStmt>> exit_statements() const {
        if (!_exit_statements.has_value()) {
            std::vector<std::shared_ptr<IRStmt>> exits;
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
    std::shared_ptr<IRTypeEnv> tyenv() const {
        return _tyenv;
    }

    // Block manipulation
    void extend(const IRSB& extendwith) {
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

    std::shared_ptr<IRSB> copy() const {
        auto new_block = std::make_shared<IRSB>();
        new_block->addr = addr;
        new_block->arch = arch;
        new_block->jumpkind = jumpkind;
        new_block->is_noop_block = is_noop_block;
        
        // Deep copy type environment
        new_block->_tyenv = std::make_shared<IRTypeEnv>(_tyenv->types, _tyenv->wordty);
        
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
    std::vector<std::shared_ptr<IRExpr>> expressions() const {
        std::vector<std::shared_ptr<IRExpr>> all_exprs;
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

    std::vector<std::shared_ptr<IRConst>> constants() const {
        std::vector<std::shared_ptr<IRConst>> all_consts;
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
    static std::shared_ptr<IRSB> _from_c(const ::IRSB* c_irsb);
    static std::shared_ptr<IRSB> _from_py(const IRSB& py_irsb);

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
    std::shared_ptr<IRStmt> deep_copy_stmt(const std::shared_ptr<IRStmt>& stmt) const;
    std::shared_ptr<IRExpr> deep_copy_expr(const std::shared_ptr<IRExpr>& expr) const;
    std::shared_ptr<IRStmt> deep_copy_and_renumber_stmt(const std::shared_ptr<IRStmt>& stmt,
                                                        std::unordered_map<int, int>& conversion_dict,
                                                        int& next_tmp) const;
    std::shared_ptr<IRExpr> deep_copy_and_renumber_expr(const std::shared_ptr<IRExpr>& expr,
                                                        std::unordered_map<int, int>& conversion_dict,
                                                        int& next_tmp) const;
};

// Nanobind module definition
void bind_block(nb::module_& m) {
    // IRTypeEnv class
    nb::class_<IRTypeEnv>(m, "IRTypeEnv")
        .def(nb::init<>())
        .def(nb::init<const std::vector<std::string>&, const std::string&>())
        .def_readwrite("types", &IRTypeEnv::types)
        .def_readwrite("wordty", &IRTypeEnv::wordty)
        .def("extend", &IRTypeEnv::extend)
        .def("lookup", &IRTypeEnv::lookup)
        .def("types_used", &IRTypeEnv::types_used)
        .def("__str__", &IRTypeEnv::__str__)
        .def_static("_from_c", &IRTypeEnv::_from_c, nb::rv_policy::take_ownership);

    // DataRef class
    nb::class_<DataRef>(m, "DataRef")
        .def(nb::init<uint64_t, uint64_t, int, const std::string&>())
        .def_readwrite("ins_addr", &DataRef::ins_addr)
        .def_readwrite("mem_addr", &DataRef::mem_addr)
        .def_readwrite("size", &DataRef::size)
        .def_readwrite("data_type", &DataRef::data_type)
        .def("__str__", &DataRef::__str__);

    // ConstVal class
    nb::class_<ConstVal>(m, "ConstVal")
        .def(nb::init<uint64_t, std::shared_ptr<IRConst>>())
        .def_readwrite("ins_addr", &ConstVal::ins_addr)
        .def_readwrite("value", &ConstVal::value)
        .def("__str__", &ConstVal::__str__);

    // IRSB class
    nb::class_<IRSB>(m, "IRSB")
        .def(nb::init<>())
        .def(nb::init<const std::vector<uint8_t>&, uint64_t, const std::string&, int, int, int, int, int>(),
             "data"_a, "mem_addr"_a, "arch"_a, "max_inst"_a = 99, "max_bytes"_a = 800,
             "bytes_offset"_a = 0, "traceflags"_a = 0, "opt_level"_a = 1)
        .def_readwrite("addr", &IRSB::addr)
        .def_readwrite("arch", &IRSB::arch)
        .def_readwrite("statements", &IRSB::statements)
        .def_readwrite("next", &IRSB::next)
        .def_readwrite("jumpkind", &IRSB::jumpkind)
        .def_readwrite("is_noop_block", &IRSB::is_noop_block)
        .def_readwrite("data_refs", &IRSB::data_refs)
        .def_readwrite("const_vals", &IRSB::const_vals)
        .def_property_readonly("size", &IRSB::size)
        .def_property_readonly("instructions", &IRSB::instructions)
        .def_property_readonly("instruction_addresses", &IRSB::instruction_addresses)
        .def_property_readonly("direct_next", &IRSB::direct_next)
        .def_property_readonly("exit_statements", &IRSB::exit_statements)
        .def_property_readonly("tyenv", &IRSB::tyenv)
        .def("extend", &IRSB::extend)
        .def("copy", &IRSB::copy)
        .def("typecheck", &IRSB::typecheck)
        .def("expressions", &IRSB::expressions)
        .def("constants", &IRSB::constants)
        .def("operations", &IRSB::operations)
        .def("constant_jump_targets", &IRSB::constant_jump_targets)
        .def("__str__", &IRSB::__str__)
        .def_static("_from_c", &IRSB::_from_c, nb::rv_policy::take_ownership)
        .def_static("_from_py", &IRSB::_from_py, nb::rv_policy::take_ownership)
        .def_readonly_static("MAX_EXITS", &IRSB::MAX_EXITS)
        .def_readonly_static("MAX_DATA_REFS", &IRSB::MAX_DATA_REFS)
        .def_readonly_static("MAX_CONST_VALS", &IRSB::MAX_CONST_VALS);
}