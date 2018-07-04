/*
This is shamelessly ripped from Vine, because those guys have very very strange language preferences.
Vine is Copyright (C) 2006-2009, BitBlaze Team.

You can redistribute and modify it under the terms of the GNU GPL,
version 2 or later, but it is made available WITHOUT ANY WARRANTY.
See the top-level README file for more details.

For more information about Vine and other BitBlaze software, see our
web site at: http://bitblaze.cs.berkeley.edu/
*/

//======================================================================
//
// This file provides the interface to VEX that allows block by block
// translation from binary to VEX IR.
//
//======================================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <setjmp.h>
#include <libvex.h>
#include <libvex_guest_arm.h>

#include "pyvex.h"
#include "logging.h"

//======================================================================
//
// Globals
//
//======================================================================

// Some info required for translation
VexArchInfo         vai_host;
VexGuestExtents     vge;
VexTranslateArgs    vta;
VexTranslateResult  vtr;
VexAbiInfo	        vbi;
VexControl          vc;

// Log message buffer, from vex itself
char *msg_buffer = NULL;
size_t msg_capacity = 0, msg_current_size = 0;

jmp_buf jumpout;

//======================================================================
//
// Functions needed for the VEX translation
//
//======================================================================

#ifdef _MSC_VER
__declspec(noreturn)
#else
__attribute__((noreturn))
#endif
static void failure_exit(void) {
	longjmp(jumpout, 1);
}

static void log_bytes(const HChar* bytes, SizeT nbytes) {
	if (msg_buffer == NULL) {
		msg_buffer = malloc(nbytes);
		msg_capacity = nbytes;
	}
	if (nbytes + msg_current_size > msg_capacity) {
		do {
			msg_capacity *= 2;
		} while (nbytes + msg_current_size > msg_capacity);
		msg_buffer = realloc(msg_buffer, msg_capacity);
	}

	memcpy(&msg_buffer[msg_current_size], bytes, nbytes);
	msg_current_size += nbytes;
}

void clear_log() {
	if (msg_buffer != NULL) {
			free(msg_buffer);
			msg_buffer = NULL;
			msg_capacity = 0;
			msg_current_size = 0;
	}
}

static Bool chase_into_ok(void *closureV, Addr addr64) {
	return False;
}

static UInt needs_self_check(void *callback_opaque, VexRegisterUpdates* pxControl, const VexGuestExtents *guest_extents) {
	return 0;
}

static void *dispatch(void) {
	return NULL;
}


//----------------------------------------------------------------------
// Initializes VEX
// It must be called before using VEX for translation to Valgrind IR
//----------------------------------------------------------------------
void vex_init() {
	static int initialized = 0;
	pyvex_debug("Initializing VEX.\n");

	if (initialized) {
		pyvex_debug("VEX already initialized.\n");
		return;
	}
	initialized = 1;

	// Initialize VEX
	LibVEX_default_VexControl(&vc);
	LibVEX_default_VexArchInfo(&vai_host);
	LibVEX_default_VexAbiInfo(&vbi);

	vc.iropt_verbosity              = 0;
	vc.iropt_level                  = 0;    // No optimization by default
	//vc.iropt_precise_memory_exns    = False;
	vc.iropt_unroll_thresh          = 0;
	vc.guest_max_insns              = 1;    // By default, we vex 1 instruction at a time
	vc.guest_chase_thresh           = 0;
	vc.arm64_allow_reordered_writeback = 0;
	vc.x86_optimize_callpop_idiom = 0;
	vc.arm_strict_block_end = 0;

	pyvex_debug("Calling LibVEX_Init()....\n");
	// the 0 is the debug level
	LibVEX_Init(&failure_exit, &log_bytes, 0, &vc);
	pyvex_debug("LibVEX_Init() done....\n");

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	vai_host.endness = VexEndnessLE;
#else
	vai_host.endness = VexEndnessBE;
#endif

	// various settings to make stuff work
	// ... former is set to 'unspecified', but gets set in vex_inst for archs which care
	// ... the latter two are for dealing with gs and fs in VEX
	vbi.guest_stack_redzone_size = 0;
	vbi.guest_amd64_assume_fs_is_const = True;
	vbi.guest_amd64_assume_gs_is_const = True;

	//------------------------------------
	// options for instruction translation

	//
	// Architecture info
	//
	vta.arch_guest          = VexArch_INVALID; // to be assigned later
#if __amd64__ || _WIN64
	vta.arch_host = VexArchAMD64;
#elif __i386__ || _WIN32
	vta.arch_host = VexArchX86;
#elif __arm__
	vta.arch_host = VexArchARM;
	vai_host.hwcaps = 7;
#elif __aarch64__
	vta.arch_host = VexArchARM64;
#else
#error "Unsupported host arch"
#endif

	vta.archinfo_host = vai_host;

	//
	// The actual stuff to vex
	//
	vta.guest_bytes         = NULL;             // Set in vex_insts
	vta.guest_bytes_addr    = 0;                // Set in vex_insts

	//
	// callbacks
	//
	vta.callback_opaque     = NULL;             // Used by chase_into_ok, but never actually called
	vta.chase_into_ok       = chase_into_ok;    // Always returns false
	vta.preamble_function   = NULL;
	vta.instrument1         = NULL;
	vta.instrument2         = NULL;
	vta.finaltidy	    	= NULL;
	vta.needs_self_check	= needs_self_check;	

	vta.disp_cp_chain_me_to_slowEP = (void *)dispatch; // Not used
	vta.disp_cp_chain_me_to_fastEP = (void *)dispatch; // Not used
	vta.disp_cp_xindir = (void *)dispatch; // Not used
	vta.disp_cp_xassisted = (void *)dispatch; // Not used

	vta.guest_extents       = &vge;
	vta.host_bytes          = NULL;           // Buffer for storing the output binary
	vta.host_bytes_size     = 0;
	vta.host_bytes_used     = NULL;
	// doesn't exist? vta.do_self_check       = False;
	vta.traceflags          = 0;                // Debug verbosity
	//vta.traceflags          = -1;                // Debug verbosity
}

// Prepare the VexArchInfo struct
static void vex_prepare_vai(VexArch arch, VexArchInfo *vai) {
	switch (arch) {
		case VexArchX86:
			vai->hwcaps =   VEX_HWCAPS_X86_MMXEXT |
							VEX_HWCAPS_X86_SSE1 |
							VEX_HWCAPS_X86_SSE2 |
							VEX_HWCAPS_X86_SSE3 |
							VEX_HWCAPS_X86_LZCNT;
			break;
		case VexArchAMD64:
			vai->hwcaps =   VEX_HWCAPS_AMD64_SSE3 |
							VEX_HWCAPS_AMD64_CX16 |
							VEX_HWCAPS_AMD64_LZCNT |
							VEX_HWCAPS_AMD64_AVX |
							VEX_HWCAPS_AMD64_RDTSCP |
							VEX_HWCAPS_AMD64_BMI |
							VEX_HWCAPS_AMD64_AVX2;
			break;
		case VexArchARM:
			vai->hwcaps = VEX_ARM_ARCHLEVEL(7) |
							VEX_HWCAPS_ARM_NEON |
							VEX_HWCAPS_ARM_VFP3;
			break;
		case VexArchARM64:
			vai->hwcaps = 0;
			vai->arm64_dMinLine_lg2_szB = 6;
			vai->arm64_iMinLine_lg2_szB = 6;
			break;
		case VexArchPPC32:
			vai->hwcaps =   VEX_HWCAPS_PPC32_F |
							VEX_HWCAPS_PPC32_V |
							VEX_HWCAPS_PPC32_FX |
							VEX_HWCAPS_PPC32_GX |
							VEX_HWCAPS_PPC32_VX |
							VEX_HWCAPS_PPC32_DFP |
							VEX_HWCAPS_PPC32_ISA2_07;
			vai->ppc_icache_line_szB = 32; // unsure if correct
			break;
		case VexArchPPC64:
			vai->hwcaps =   VEX_HWCAPS_PPC64_V |
							VEX_HWCAPS_PPC64_FX |
							VEX_HWCAPS_PPC64_GX |
							VEX_HWCAPS_PPC64_VX |
							VEX_HWCAPS_PPC64_DFP |
							VEX_HWCAPS_PPC64_ISA2_07;
			vai->ppc_icache_line_szB = 64; // unsure if correct
			break;
		case VexArchS390X:
			vai->hwcaps = 0;
			break;
		case VexArchMIPS32:
		case VexArchMIPS64:
			vai->hwcaps = VEX_PRID_COMP_CAVIUM;
			break;
		default:
			pyvex_error("Invalid arch in vex_prepare_vai.\n");
			break;
	}
}

// Prepare the VexAbiInfo
static void vex_prepare_vbi(VexArch arch, VexAbiInfo *vbi) {
	// only setting the guest_stack_redzone_size for now
	// this attribute is only specified by the PPC64 and AMD64 ABIs

	switch (arch) {
		case VexArchAMD64:
			vbi->guest_stack_redzone_size = 128;
			break;
		case VexArchPPC64:
			vbi->guest_stack_redzone_size = 288;
			break;
		default:
			break;
	}
}


void remove_noops(
	IRSB* irsb
	) {
	Int noops = 0, i;
	Int pos = 0;

	for (i = 0; i < irsb->stmts_used; ++i) {
		if (irsb->stmts[i]->tag != Ist_NoOp) {
			if (i != pos) {
				irsb->stmts[pos] = irsb->stmts[i];
			}
			pos++;
		}
		else {
			noops++;
		}
	}

	irsb->stmts_used -= noops;
}


void get_exits_and_inst_addrs(
		IRSB *irsb,
		VEXLiftResult *lift_r ) {
	Int i, exit_ctr = 0, inst_count = 0;
	Addr ins_addr;
	UInt size = 0;
	for (i = 0; i < irsb->stmts_used; ++i) {
		IRStmt* stmt = irsb->stmts[i];
		if (stmt->tag == Ist_Exit) {
			if (exit_ctr < MAX_EXITS) {
				lift_r->exits[exit_ctr].ins_addr = ins_addr;
				lift_r->exits[exit_ctr].stmt_idx = i;
				lift_r->exits[exit_ctr].stmt = stmt;
			}
			exit_ctr += 1;
		}
		else if (stmt->tag == Ist_IMark) {
			ins_addr = stmt->Ist.IMark.addr + stmt->Ist.IMark.delta;
			size += stmt->Ist.IMark.len;
			if (inst_count < sizeof(lift_r->inst_addrs) / sizeof(Addr)) {
				lift_r->inst_addrs[inst_count] = ins_addr;
			}
			// inst_count is incremented anyway. If lift_r->insts > 200, the overflowed
			// instruction addresses will not be written into inst_addrs.
			inst_count++;
		}
	}

	lift_r->exit_count = exit_ctr;
	lift_r->size = size;
	lift_r->insts = inst_count;
}

void get_default_exit_target(
		IRSB *irsb,
		VEXLiftResult *lift_r ) {

	IRTemp tmp;
	Int reg = -1;
	IRType reg_type = Ity_INVALID;
	Int i;

	lift_r->is_default_exit_constant = 0;

	if (irsb->jumpkind != Ijk_Boring && irsb->jumpkind != Ijk_Call) {
		return;
	}

	if (irsb->next->tag == Iex_Const) {
		IRConst *con = irsb->next->Iex.Const.con;
		switch (con->tag) {
		case Ico_U16:
			lift_r->is_default_exit_constant = 1;
			lift_r->default_exit = con->Ico.U16;
			break;
		case Ico_U32:
			lift_r->is_default_exit_constant = 1;
			lift_r->default_exit = con->Ico.U32;
			break;
		case Ico_U64:
			lift_r->is_default_exit_constant = 1;
			lift_r->default_exit = con->Ico.U64;
			break;
		default:
			// A weird address... we don't support it.
			break;
		}
		return;
	}

	if (irsb->next->tag != Iex_RdTmp) {
		// Unexpected irsb->next type
		return;
	}

	// Scan statements backwards to find the assigning statement
	tmp = irsb->next->Iex.RdTmp.tmp;
	for (i = irsb->stmts_used - 1; i >= 0; --i) {
		IRExpr *data = NULL;
		IRStmt *stmt = irsb->stmts[i];
		if (stmt->tag == Ist_WrTmp &&
				stmt->Ist.WrTmp.tmp == tmp) {
			data = stmt->Ist.WrTmp.data;
		}
		else if (stmt->tag == Ist_Put &&
				stmt->Ist.Put.offset == reg) {
			IRType put_type = typeOfIRExpr(irsb->tyenv, stmt->Ist.Put.data);
			if (put_type != reg_type) {
				// The size does not match. Give up.
				return;
			}
			data = stmt->Ist.Put.data;
		}
		else if (stmt->tag == Ist_LoadG) {
			// We do not handle LoadG. Give up.
			return;
		}
		else {
			continue;
		}

		if (data->tag == Iex_Const) {
			lift_r->is_default_exit_constant = 1;
			IRConst *con = data->Iex.Const.con;
			switch (con->tag) {
			case Ico_U16:
				lift_r->is_default_exit_constant = 1;
				lift_r->default_exit = con->Ico.U16;
				break;
			case Ico_U32:
				lift_r->is_default_exit_constant = 1;
				lift_r->default_exit = con->Ico.U32;
				break;
			case Ico_U64:
				lift_r->is_default_exit_constant = 1;
				lift_r->default_exit = con->Ico.U64;
				break;
			default:
				// A weird address... we don't support it.
				break;
			}
			return;
		}
		else if (data->tag == Iex_RdTmp) {
			// Reading another temp variable
			tmp = data->Iex.RdTmp.tmp;
			reg = -1;
		}
		else if (data->tag == Iex_Get) {
			// Reading from a register
			tmp = IRTemp_INVALID;
			reg = data->Iex.Get.offset;
			reg_type = typeOfIRExpr(irsb->tyenv, data);
		}
		else {
			// Something we don't currently support
			return;
		}
	}

	// We cannot resolve it to a constant value.
	return;
}


Addr get_value_from_const_expr(
	IRConst* con) {

	switch (con->tag) {
	case Ico_U8:
		return con->Ico.U8;
	case Ico_U16:
		return con->Ico.U16;
	case Ico_U32:
		return con->Ico.U32;
	case Ico_U64:
		return con->Ico.U64;
	default:
		// A weird address...
		return 0;
	}
}


//
// Jumpkind fixes for ARM
//
// If PC is moved to LR, then this should be an Ijk_Call
//
// Example:
// MOV LR, PC
// MOV PC, R8

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
			if (stmt->Ist.Put.offset == ARM_OFFB_LR && inst_ctr == irsb_insts - 1) {
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
}

VEXLiftResult _lift_r;

//----------------------------------------------------------------------
// Main entry point. Do a lift.
//----------------------------------------------------------------------
VEXLiftResult *vex_lift(
		VexArch guest,
		VexArchInfo archinfo,
		unsigned char *insn_start,
		unsigned long long insn_addr,
		unsigned int max_insns,
		unsigned int max_bytes,
		int opt_level,
		int traceflags,
		int allow_lookback,
		int strict_block_end) {
	VexRegisterUpdates pxControl;

	vex_prepare_vai(guest, &archinfo);
	vex_prepare_vbi(guest, &vbi);

	pyvex_debug("Guest arch: %d\n", guest);
	pyvex_debug("Guest arch hwcaps: %08x\n", archinfo.hwcaps);

	vta.archinfo_guest = archinfo;
	vta.arch_guest = guest;
	vta.abiinfo_both = vbi; // Set the vbi value

	vta.guest_bytes         = (UChar *)(insn_start);  // Ptr to actual bytes of start of instruction
	vta.guest_bytes_addr    = (Addr64)(insn_addr);
	vta.traceflags          = traceflags;

	vc.guest_max_bytes     = max_bytes;
	vc.guest_max_insns     = max_insns;
	vc.iropt_level         = opt_level;
	vc.arm_allow_optimizing_lookback = allow_lookback;
	vc.arm_strict_block_end = strict_block_end;

	clear_log();

	// Do the actual translation
	if (setjmp(jumpout) == 0) {
		LibVEX_Update_Control(&vc);
		_lift_r.irsb = LibVEX_Lift(&vta, &vtr, &pxControl);
		if (!_lift_r.irsb) {
			// Lifting failed
			return NULL;
		}
		remove_noops(_lift_r.irsb);
		get_exits_and_inst_addrs(_lift_r.irsb, &_lift_r);
		get_default_exit_target(_lift_r.irsb, &_lift_r);
		if (guest == VexArchARM && _lift_r.insts > 0) {
			arm_post_processor_determine_calls(_lift_r.inst_addrs[0], _lift_r.size, _lift_r.insts, _lift_r.irsb);
		}
		return &_lift_r;
	} else {
		return NULL;
	}
}
