#include <nanobind/nanobind.h>
#include <tuple>
#include <string>
extern "C" {
#include "pyvex.h"
}

#include "const.hpp"
#include "enums.hpp"
#include "stmt.hpp"
#include "expr.hpp"
#include "block.hpp"
#include "typeenv.hpp"

namespace nb = nanobind;
using namespace nb::literals;

// Helper function to convert IRConst* to Python object
nb::object wrap_irconst(IRConst* c) {
    if (!c) return nb::none();
    return nb::cast(c, nb::rv_policy::take_ownership);
}

// Helper function to convert IRExpr* to Python object  
nb::object wrap_irexpr(IRExpr* e) {
    if (!e) return nb::none();
    return nb::cast(e, nb::rv_policy::take_ownership);
}

NB_MODULE(_pyvex, m) {
    m.doc() = "PyVEX nanobind module";

    // Initialize VEX
    m.def("vex_init", &vex_init, "Initialize VEX");
    
    // Logging functions
    m.def("clear_log", &clear_log, "Clear log buffer");
    m.def("LibVEX_ShowAllocStats", &LibVEX_ShowAllocStats, "Show allocation statistics");
    
    // Main lifting function - simplified for now
    m.def("vex_lift", [](int vex_arch, nb::object archinfo, nb::bytes data, 
                        unsigned long long addr, unsigned int max_inst, unsigned int max_bytes,
                        int opt_level, int traceflags, int allow_arch_optimizations,
                        int strict_block_end, int collect_data_refs, int load_from_ro_regions, 
                        int const_prop, int px_control, unsigned int lookback) -> nb::object {
        // For now, return None - full implementation needs complex type conversions
        return nb::none();
    }, "vex_arch"_a, "archinfo"_a, "data"_a, "addr"_a, "max_inst"_a, 
       "max_bytes"_a, "opt_level"_a, "traceflags"_a, "allow_arch_optimizations"_a,
       "strict_block_end"_a, "collect_data_refs"_a, "load_from_ro_regions"_a, "const_prop"_a,
       "px_control"_a, "lookback"_a, "Lift VEX IR from binary code");

    // VEX architecture constants
    m.attr("VexArchX86") = int(VexArchX86);
    m.attr("VexArchAMD64") = int(VexArchAMD64);
    m.attr("VexArchARM") = int(VexArchARM);
    m.attr("VexArchARM64") = int(VexArchARM64);
    m.attr("VexArchPPC32") = int(VexArchPPC32);
    m.attr("VexArchPPC64") = int(VexArchPPC64);
    m.attr("VexArchS390X") = int(VexArchS390X);
    m.attr("VexArchMIPS32") = int(VexArchMIPS32);
    m.attr("VexArchMIPS64") = int(VexArchMIPS64);
    m.attr("VexArchRISCV64") = int(VexArchRISCV64);
    
    // NULL constant
    m.attr("NULL") = nb::none();
    
    // // Message buffer access - use functions instead of direct pointer access
    // m.def("msg_buffer", []() -> nb::object {
    //     return msg_buffer;
    // }, "Get message buffer pointer as integer");
    
    m.def("msg_current_size", []() -> size_t {
        return msg_current_size;
    }, "Get message current size pointer as integer");
    
    m.def("log_level", []() -> int {
        return log_level;
    }, "Get log level pointer as integer");
    
    // VEX control structure - stub for now (needs proper implementation)
    m.def("vex_control", []() -> nb::object {
        return nb::none();
    }, "Get VEX control structure pointer");

    // Bind typeenv class
    bind_typeenv(m);

    // Bind const classes
    bind_const(m);
    
    // Bind enums classes
    bind_enums(m);

    // Bind expr classes
    bind_expr(m);

    // Bind stmt classes
    bind_stmt(m);
    
    // Bind block classes
    bind_block(m);
}