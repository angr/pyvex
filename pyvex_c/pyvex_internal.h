#include "pyvex.h"

void arm_post_processor_determine_calls(Addr irsb_addr, Int irsb_size, Int irsb_insts, IRSB *irsb);
void mips32_post_processor_fix_unconditional_exit(IRSB *irsb);

void remove_noops(IRSB* irsb);
void zero_division_side_exits(IRSB* irsb);
void get_exits_and_inst_addrs(IRSB *irsb, VEXLiftResult *lift_r);
void get_default_exit_target(IRSB *irsb, VEXLiftResult *lift_r);
void get_is_noop_block(IRSB *irsb, VEXLiftResult *lift_r);
void execute_irsb(IRSB *irsb, VEXLiftResult *lift_r, VexArch guest, Bool load_from_ro_regions, Bool collect_data_refs, Bool const_prop);
Addr get_value_from_const_expr(IRConst* con);
