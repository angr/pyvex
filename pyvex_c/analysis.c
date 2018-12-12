#include <libvex.h>
#include <stddef.h>
#include <assert.h>

#include "pyvex.h"

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
		VEXLiftResult *lift_r) {
	Int i, exit_ctr = 0, inst_count = 0;
	Addr ins_addr = -1;
	UInt size = 0;
	for (i = 0; i < irsb->stmts_used; ++i) {
		IRStmt* stmt = irsb->stmts[i];
		if (stmt->tag == Ist_Exit) {
			assert(ins_addr != -1);
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

	if (irsb->jumpkind != Ijk_InvalICache && irsb->jumpkind != Ijk_Boring && irsb->jumpkind != Ijk_Call) {
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
// Collect data references
//


void record_data_reference(
	VEXLiftResult *lift_r,
	Addr data_addr,
	Int size,
	DataRefTypes data_type,
	Int stmt_idx,
	Addr inst_addr) {

	if (lift_r->data_ref_count < MAX_DATA_REFS) {
		Int idx = lift_r->data_ref_count;
		lift_r->data_refs[idx].size = size;
		lift_r->data_refs[idx].data_addr = data_addr;
		lift_r->data_refs[idx].data_type = data_type;
		lift_r->data_refs[idx].stmt_idx = stmt_idx;
		lift_r->data_refs[idx].ins_addr = inst_addr;
	}
	lift_r->data_ref_count++;
}

void record_const(
	VEXLiftResult *lift_r,
	IRExpr *const_expr,
	Int size,
	DataRefTypes data_type,
	Int stmt_idx,
	Addr inst_addr,
	Addr next_inst_addr) {

	if (const_expr->tag != Iex_Const) {
		// Why are you calling me?
		assert (const_expr->tag == Iex_Const);
		return;
	}

	Addr addr = get_value_from_const_expr(const_expr->Iex.Const.con);
	if (addr != next_inst_addr) {
		record_data_reference(lift_r, addr, size, data_type, stmt_idx, inst_addr);
	}

}


void collect_data_references(
	IRSB *irsb,
	VEXLiftResult *lift_r) {

	Int i;
	Addr inst_addr = -1, next_inst_addr = -1;

	for (i = 0; i < irsb->stmts_used; ++i) {
		IRStmt *stmt = irsb->stmts[i];
		switch (stmt->tag) {
		case Ist_IMark:
			inst_addr = stmt->Ist.IMark.addr + stmt->Ist.IMark.delta;
			next_inst_addr = inst_addr + stmt->Ist.IMark.len;
			break;
		case Ist_WrTmp:
			assert(inst_addr != -1 && next_inst_addr != -1);
			{
				IRExpr *data = stmt->Ist.WrTmp.data;
				switch (data->tag) {
				case Iex_Load:
					// load
					// e.g. t7 = LDle:I64(0x0000000000600ff8)
					if (data->Iex.Load.addr->tag == Iex_Const) {
						Int size;
						size = sizeofIRType(typeOfIRTemp(irsb->tyenv, stmt->Ist.WrTmp.tmp));
						record_const(lift_r, data->Iex.Load.addr, size, Dt_Integer, i, inst_addr, next_inst_addr);
					}
					break;
				case Iex_Binop:
					if (data->Iex.Binop.op == Iop_Add32 || data->Iex.Binop.op == Iop_Add64) {
						if (data->Iex.Binop.arg1->tag == Iex_Const && data->Iex.Binop.arg2->tag == Iex_Const) {
							// ip-related addressing
							Addr addr;
							addr = get_value_from_const_expr(data->Iex.Binop.arg1->Iex.Const.con) +
								get_value_from_const_expr(data->Iex.Binop.arg2->Iex.Const.con);
							if (addr != next_inst_addr) {
								record_data_reference(lift_r, addr, 0, Dt_Unknown, i, inst_addr);
							}
						}
					}
					else {
						// Normal binary operations
						if (data->Iex.Binop.arg1->tag == Iex_Const) {
							record_const(lift_r, data->Iex.Binop.arg1, 0, Dt_Unknown, i, inst_addr, next_inst_addr);
						}
						if (data->Iex.Binop.arg2->tag == Iex_Const) {
							record_const(lift_r, data->Iex.Binop.arg2, 0, Dt_Unknown, i, inst_addr, next_inst_addr);
						}
					}
					break;
				case Iex_Const:
					{
						record_const(lift_r, data, 0, Dt_Unknown, i, inst_addr, next_inst_addr);
					}
					break;
				case Iex_ITE:
					{
						if (data->Iex.ITE.iftrue->tag == Iex_Const) {
							record_const(lift_r, data->Iex.ITE.iftrue, 0, Dt_Unknown, i, inst_addr, next_inst_addr);
						}
						if (data->Iex.ITE.iffalse->tag == Iex_Const) {
							record_const(lift_r, data->Iex.ITE.iffalse, 0, Dt_Unknown, i, inst_addr, next_inst_addr);
						}
					}
					break;
				default:
					// Unsupported for now
					break;
				} // end switch (data->tag)
			}
			break;
		case Ist_Put:
			// put
			// e.g. PUT(rdi) = 0x0000000000400714
			assert(inst_addr != -1 && next_inst_addr != -1);
			{
				IRExpr *data = stmt->Ist.Put.data;
				if (data->tag == Iex_Const) {
					record_const(lift_r, data, 0, Dt_Unknown, i, inst_addr, next_inst_addr);
				}
			}
			break;
		case Ist_Store:
			// Store
			assert(inst_addr != -1 && next_inst_addr != -1);
			{
				IRExpr *store_dst = stmt->Ist.Store.addr;
				IRExpr *store_data = stmt->Ist.Store.data;
				if (store_dst->tag == Iex_Const) {
					// Writing to a memory destination. We can get its size by analyzing the size of store_data
					IRType data_type = typeOfIRExpr(irsb->tyenv, stmt->Ist.Put.data);
					Int data_size = 0;
					if (data_type != Ity_INVALID) {
						data_size = sizeofIRType(data_type);
					}
					record_const(lift_r, store_dst, data_size,
						data_size == 0? Dt_Unknown : Dt_Integer,
						i, inst_addr, next_inst_addr);
				}
				if (store_data->tag == Iex_Const) {
					record_const(lift_r, store_data, 0, Dt_Unknown, i, inst_addr, next_inst_addr);
				}
			}
			break;
		case Ist_Dirty:
			// Dirty
			assert(inst_addr != -1 && next_inst_addr != -1);
			if (stmt->Ist.Dirty.details->mAddr != NULL &&
				stmt->Ist.Dirty.details->mAddr->tag == Iex_Const) {
				IRExpr *m_addr = stmt->Ist.Dirty.details->mAddr;
				record_const(lift_r, m_addr, stmt->Ist.Dirty.details->mSize, Dt_FP, i, inst_addr, next_inst_addr);
			}
			break;
		default:
			break;
		} // end switch (stmt->tag)
	}
}
