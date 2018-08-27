#include <libvex.h>
#include <libvex_guest_arm.h>
#include <stddef.h>

#include "pyvex.h"

//
// Jumpkind fixes for ARM
//
// If PC is moved to LR, then this should be an Ijk_Call
//
// Example:
// MOV LR, PC
// MOV PC, R8
//
// Note that the value of PC is directly used in IRStatements, i.e
// instead of having:
//   t0 = GET:I32(pc)
//   PUT(lr) = t0
// we have:
//   PUT(lr) = 0x10400
// The only case (that I've seen so far) where a temporary variable
// is assigned to LR is:
//   t2 = ITE(cond, t0, t1)
//   PUT(lr) = t2
//
void arm_post_processor_determine_calls(
	Addr irsb_addr,  // Address of this IRSB
	Int irsb_size,  // Size of this IRSB
	Int irsb_insts,  // Number of instructions
	IRSB *irsb) {

// Offset to the link register
#define ARM_OFFB_LR      offsetof(VexGuestARMState,guest_R14)
// The maximum number of tmps
#define MAX_TMP 		 1000
// The maximum offset of registers
#define MAX_REG_OFFSET	 1000
// Dummy value
#define DUMMY 0xffeffeff

	if (irsb->jumpkind != Ijk_Boring) {
		return;
	}

	// Emulated CPU context
	Addr tmps[MAX_TMP + 1] = { DUMMY };
	Addr regs[MAX_REG_OFFSET + 1] = { DUMMY };

	Int lr_store_pc = 0;
	Int inst_ctr = 0;
	Addr next_irsb_addr = (irsb_addr & (~1)) + irsb_size; // Clear the least significant bit
	Int i;

	for (i = 0; i < irsb->stmts_used; ++i) {
		IRStmt *stmt = irsb->stmts[i];

		if (stmt->tag == Ist_Put) {
			// LR is modified just before the last instruction of the block...
			if (stmt->Ist.Put.offset == ARM_OFFB_LR /*&& inst_ctr == irsb_insts - 1*/) {
				// ... by a constant, so test whether it is the address of the next IRSB
				if (stmt->Ist.Put.data->tag == Iex_Const) {
					IRConst *con = stmt->Ist.Put.data->Iex.Const.con;
					if (get_value_from_const_expr(con) == next_irsb_addr) {
						lr_store_pc = 1;
					}
				} else if (stmt->Ist.Put.data->tag == Iex_RdTmp) {
					Int tmp = stmt->Ist.Put.data->Iex.RdTmp.tmp;
					if (tmp <= MAX_TMP && next_irsb_addr == tmps[tmp]) {
						lr_store_pc = 1;
					}
				}
				break;
			} else {
				Int reg_offset = stmt->Ist.Put.offset;
				if (reg_offset <= MAX_REG_OFFSET) {
					IRExpr *data = stmt->Ist.Put.data;
					if (data->tag == Iex_Const) {
						regs[reg_offset] = get_value_from_const_expr(stmt->Ist.Put.data->Iex.Const.con);
					} else if (data->tag == Iex_RdTmp) {
						Int tmp = data->Iex.RdTmp.tmp;
						if (tmp <= MAX_TMP && tmps[tmp] != DUMMY) {
							regs[reg_offset] = tmps[tmp];
						}
					} else if (data->tag == Iex_Get) {
						Int src_reg = data->Iex.Get.offset;
						if (src_reg <= MAX_REG_OFFSET && regs[src_reg] != DUMMY) {
							regs[reg_offset] = regs[src_reg];
						}
					}
				}
			}
		}
		else if (stmt->tag == Ist_WrTmp && stmt->Ist.WrTmp.tmp <= MAX_TMP) {
			// The PC value may propagate through the block, and since
			// LR is modified at the end of the block, the PC value have
			// to be incremented in order to match the address of the
			// next IRSB. So the only propagation ways that can lead to
			// a function call are:
			//
			//   - Iop_Add* operations (even "sub r0, #-4" is compiled
			//   as "add r0, #4")
			//   - Iop_And*, Iop_Or*, Iop_Xor*, Iop_Sh*, Iop_Not* (there
			//   may be some tricky and twisted ways to increment PC)
			//
			Int tmp_dst = stmt->Ist.WrTmp.tmp;
			if (stmt->Ist.WrTmp.data->tag == Iex_Binop) {
				IRExpr* data = stmt->Ist.WrTmp.data;
				Addr op0 = DUMMY, op1 = DUMMY;
				// Extract op0
				if (data->Iex.Binop.arg1->tag == Iex_Const) {
					op0 = get_value_from_const_expr(data->Iex.Binop.arg1->Iex.Const.con);
				} else if (data->Iex.Binop.arg1->tag == Iex_RdTmp) {
					Int tmp = data->Iex.Binop.arg1->Iex.RdTmp.tmp;
					if (tmp <= MAX_TMP && tmps[tmp] != DUMMY) {
						op0 = tmps[tmp];
					}
				}
				// Extract op1
				if (data->Iex.Binop.arg2->tag == Iex_Const) {
					op1 = get_value_from_const_expr(data->Iex.Binop.arg2->Iex.Const.con);
				} else if (data->Iex.Binop.arg2->tag == Iex_RdTmp) {
					Int tmp = data->Iex.Binop.arg2->Iex.RdTmp.tmp;
					if (tmp <= MAX_TMP && tmps[tmp] != DUMMY) {
						op1 = tmps[tmp];
					}
				}
				if (op0 != DUMMY && op1 != DUMMY) {
					// Both operands are loaded. Perfom calculation.
					switch (data->Iex.Binop.op) {
					case Iop_Add8: case Iop_Add16: case Iop_Add32: case Iop_Add64:
						tmps[tmp_dst] = op0 + op1;
						break;
					case Iop_Sub8: case Iop_Sub16: case Iop_Sub32: case Iop_Sub64:
						tmps[tmp_dst] = op0 - op1;
						break;
					case Iop_And8: case Iop_And16: case Iop_And32: case Iop_And64:
						tmps[tmp_dst] = op0 & op1;
						break;
					case Iop_Or8: case Iop_Or16: case Iop_Or32: case Iop_Or64:
						tmps[tmp_dst] = op0 | op1;
						break;
					case Iop_Xor8: case Iop_Xor16: case Iop_Xor32: case Iop_Xor64:
						tmps[tmp_dst] = op0 ^ op1;
						break;
					case Iop_Shl8: case Iop_Shl16: case Iop_Shl32: case Iop_Shl64:
						tmps[tmp_dst] = op0 << op1;
						break;
					case Iop_Shr8: case Iop_Shr16: case Iop_Shr32: case Iop_Shr64:
					case Iop_Sar8: case Iop_Sar16: case Iop_Sar32: case Iop_Sar64:
						tmps[tmp_dst] = op0 >> op1;
						break;
					default:
						// Unsupported operation
						break;
					}
				}
			} else if (stmt->Ist.WrTmp.data->tag == Iex_Get) {
				Int reg_offset = stmt->Ist.WrTmp.data->Iex.Get.offset;
				if (reg_offset <= MAX_REG_OFFSET && regs[reg_offset] != DUMMY) {
					tmps[tmp_dst] = regs[reg_offset];
				}
			} else if (stmt->Ist.WrTmp.data->tag == Iex_ITE) {
				// Parse iftrue and iffalse
				IRExpr *data = stmt->Ist.WrTmp.data;
				if (data->Iex.ITE.iffalse->tag == Iex_Const) {
					tmps[tmp_dst] = get_value_from_const_expr(data->Iex.ITE.iffalse->Iex.Const.con);
				} else if (data->Iex.ITE.iffalse->tag == Iex_RdTmp) {
					Int tmp = data->Iex.ITE.iffalse->Iex.RdTmp.tmp;
					if (tmp <= MAX_TMP && tmps[tmp] != DUMMY) {
						tmps[tmp_dst] = tmps[tmp];
					}
				}
				if (data->Iex.ITE.iftrue->tag == Iex_Const) {
					tmps[tmp_dst] = get_value_from_const_expr(data->Iex.ITE.iftrue->Iex.Const.con);
				} else if (data->Iex.ITE.iftrue->tag == Iex_RdTmp) {
					Int tmp = data->Iex.ITE.iftrue->Iex.RdTmp.tmp;
					if (tmp <= MAX_TMP && tmps[tmp] != DUMMY) {
						tmps[tmp_dst] = tmps[tmp];
					}
				}
			} else if (stmt->Ist.WrTmp.data->tag == Iex_RdTmp) {
				IRExpr *data = stmt->Ist.WrTmp.data;
				Int tmp = data->Iex.RdTmp.tmp;
				if (tmp <= MAX_TMP && tmps[tmp] != DUMMY) {
					tmps[tmp_dst] = tmps[tmp];
				}
			} else if (stmt->Ist.WrTmp.data->tag == Iex_Const) {
				IRConst *con = stmt->Ist.WrTmp.data->Iex.Const.con;
				tmps[tmp_dst] = get_value_from_const_expr(con);
			}
		}
		else if (stmt->tag == Ist_IMark) {
			inst_ctr++;
		}
	}

	if (lr_store_pc) {
		irsb->jumpkind = Ijk_Call;
	}

// Undefine all defined values
#undef ARM_OFFB_LR
#undef MAX_TMP
#undef MAX_REG_OFFSET
#undef DUMMY
}


//
// Unconditional branch fixes for MIPS32
//
// Handle unconditional branches
// `beq $zero, $zero, xxxx`
// It is translated to
//
// 15 | ------ IMark(0x401684, 4, 0) ------
// 16 | t0 = CmpEQ32(0x00000000, 0x00000000)
// 17 | PUT(128) = 0x00401688
// 18 | ------ IMark(0x401688, 4, 0) ------
// 19 | if (t0) goto {Ijk_Boring} 0x401684
// 20 | PUT(128) = 0x0040168c
// 21 | t4 = GET:I32(128)
// NEXT: PUT(128) = t4; Ijk_Boring
//
void mips32_post_processor_fix_unconditional_exit(
	IRSB *irsb) {

#define INVALID		0xffff

	Int i;
	Int tmp_exit = INVALID, exit_stmt_idx = INVALID;
	IRConst *dst = NULL;

	for (i = irsb->stmts_used - 1; i >= 0; --i) {
		IRStmt *stmt = irsb->stmts[i];
		if (tmp_exit == INVALID) {
			// Looking for the Exit statement
			if (stmt->tag == Ist_Exit &&
					stmt->Ist.Exit.jk == Ijk_Boring &&
					stmt->Ist.Exit.guard->tag == Iex_RdTmp) {
				tmp_exit = stmt->Ist.Exit.guard->Iex.RdTmp.tmp;
				dst = stmt->Ist.Exit.dst;
				exit_stmt_idx = i;
			}
		}
		else if (stmt->tag == Ist_WrTmp && stmt->Ist.WrTmp.tmp == tmp_exit) {
			// Looking for the WrTmp statement
			IRExpr *data = stmt->Ist.WrTmp.data;
			if (data->tag == Iex_Binop &&
				data->Iex.Binop.op == Iop_CmpEQ32 &&
				data->Iex.Binop.arg1->tag == Iex_Const &&
				data->Iex.Binop.arg2->tag == Iex_Const &&
				get_value_from_const_expr(data->Iex.Binop.arg1->Iex.Const.con) ==
					get_value_from_const_expr(data->Iex.Binop.arg2->Iex.Const.con)) {
						// We found it

						// Update the statements
						Int j;
						for (j = exit_stmt_idx; j < irsb->stmts_used - 1; ++j) {
							irsb->stmts[j] = irsb->stmts[j + 1];
						}
						irsb->stmts_used -= 1;
						// Update the default of the IRSB
						irsb->next = IRExpr_Const(dst);
			}
			break;
		}
	}

#undef INVALID
}

