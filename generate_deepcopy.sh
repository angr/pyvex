#!/bin/bash

VALGRIND_HOME=~/valgrind/valgrind-3.9.0/

cat > pyvex/pyvex_deepcopy.c <<END
#include <libvex_ir.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "pyvex_logging.h"
#include "pyvex_deepcopy.h"

#define vpanic(x) { error(x "\n"); assert(0); }

#define PYVEX_SHALLOW_FUNC(type) type *pyvex_shallowCopy_##type(type *x) { type *o = malloc(sizeof(type)); memcpy(o, x, sizeof(type)); return o; }

PYVEX_SHALLOW_FUNC(IRConst)
#define IRConst_U1(...) pyvex_shallowCopy_IRConst(IRConst_U1(__VA_ARGS__))
#define IRConst_U8(...) pyvex_shallowCopy_IRConst(IRConst_U8(__VA_ARGS__))
#define IRConst_U16(...) pyvex_shallowCopy_IRConst(IRConst_U16(__VA_ARGS__))
#define IRConst_U32(...) pyvex_shallowCopy_IRConst(IRConst_U32(__VA_ARGS__))
#define IRConst_U64(...) pyvex_shallowCopy_IRConst(IRConst_U64(__VA_ARGS__))
#define IRConst_F32(...) pyvex_shallowCopy_IRConst(IRConst_F32(__VA_ARGS__))
#define IRConst_F64(...) pyvex_shallowCopy_IRConst(IRConst_F64(__VA_ARGS__))
#define IRConst_F32i(...) pyvex_shallowCopy_IRConst(IRConst_F32i(__VA_ARGS__))
#define IRConst_F64i(...) pyvex_shallowCopy_IRConst(IRConst_F64i(__VA_ARGS__))
#define IRConst_V128(...) pyvex_shallowCopy_IRConst(IRConst_V128(__VA_ARGS__))
#define IRConst_V256(...) pyvex_shallowCopy_IRConst(IRConst_V256(__VA_ARGS__))

PYVEX_SHALLOW_FUNC(IRCallee)
#define mkIRCallee(...) pyvex_shallowCopy_IRCallee(mkIRCallee(__VA_ARGS__))

PYVEX_SHALLOW_FUNC(IRRegArray)
#define mkIRRegArray(...) pyvex_shallowCopy_IRRegArray(mkIRRegArray(__VA_ARGS__))

PYVEX_SHALLOW_FUNC(IRExpr)
#define IRExpr_Get(...) pyvex_shallowCopy_IRExpr(IRExpr_Get(__VA_ARGS__))
#define IRExpr_GetI(...) pyvex_shallowCopy_IRExpr(IRExpr_GetI(__VA_ARGS__))
#define IRExpr_RdTmp(...) pyvex_shallowCopy_IRExpr(IRExpr_RdTmp(__VA_ARGS__))
#define IRExpr_Qop(...) pyvex_shallowCopy_IRExpr(IRExpr_Qop(__VA_ARGS__))
#define IRExpr_Triop(...) pyvex_shallowCopy_IRExpr(IRExpr_Triop(__VA_ARGS__))
#define IRExpr_Binop(...) pyvex_shallowCopy_IRExpr(IRExpr_Binop(__VA_ARGS__))
#define IRExpr_Unop(...) pyvex_shallowCopy_IRExpr(IRExpr_Unop(__VA_ARGS__))
#define IRExpr_Load(...) pyvex_shallowCopy_IRExpr(IRExpr_Load(__VA_ARGS__))
#define IRExpr_Const(...) pyvex_shallowCopy_IRExpr(IRExpr_Const(__VA_ARGS__))
#define IRExpr_CCall(...) pyvex_shallowCopy_IRExpr(IRExpr_CCall(__VA_ARGS__))
#define IRExpr_ITE(...) pyvex_shallowCopy_IRExpr(IRExpr_ITE(__VA_ARGS__))

PYVEX_SHALLOW_FUNC(IRDirty)
#define emptyIRDirty(...) pyvex_shallowCopy_IRDirty(emptyIRDirty(__VA_ARGS__))

PYVEX_SHALLOW_FUNC(IRCAS)
#define mkIRCAS(...) pyvex_shallowCopy_IRCAS(mkIRCAS(__VA_ARGS__))

PYVEX_SHALLOW_FUNC(IRPutI)
#define mkIRPutI(...) pyvex_shallowCopy_IRPutI(mkIRPutI(__VA_ARGS__))

PYVEX_SHALLOW_FUNC(IRStmt)
#define IRStmt_NoOp(...) pyvex_shallowCopy_IRStmt(IRStmt_NoOp(__VA_ARGS__))
#define IRStmt_AbiHint(...) pyvex_shallowCopy_IRStmt(IRStmt_AbiHint(__VA_ARGS__))
#define IRStmt_IMark(...) pyvex_shallowCopy_IRStmt(IRStmt_IMark(__VA_ARGS__))
#define IRStmt_Put(...) pyvex_shallowCopy_IRStmt(IRStmt_Put(__VA_ARGS__))
#define IRStmt_PutI(...) pyvex_shallowCopy_IRStmt(IRStmt_PutI(__VA_ARGS__))
#define IRStmt_WrTmp(...) pyvex_shallowCopy_IRStmt(IRStmt_WrTmp(__VA_ARGS__))
#define IRStmt_Store(...) pyvex_shallowCopy_IRStmt(IRStmt_Store(__VA_ARGS__))
#define IRStmt_CAS(...) pyvex_shallowCopy_IRStmt(IRStmt_CAS(__VA_ARGS__))
#define IRStmt_LLSC(...) pyvex_shallowCopy_IRStmt(IRStmt_LLSC(__VA_ARGS__))
#define IRStmt_Dirty(...) pyvex_shallowCopy_IRStmt(IRStmt_Dirty(__VA_ARGS__))
#define IRStmt_MBE(...) pyvex_shallowCopy_IRStmt(IRStmt_MBE(__VA_ARGS__))
#define IRStmt_Exit(...) pyvex_shallowCopy_IRStmt(IRStmt_Exit(__VA_ARGS__))
#define IRStmt_StoreG(...) pyvex_shallowCopy_IRStmt(IRStmt_StoreG(__VA_ARGS__))
#define IRStmt_LoadG(...) pyvex_shallowCopy_IRStmt(IRStmt_LoadG(__VA_ARGS__))

PYVEX_SHALLOW_FUNC(IRTypeEnv)
// nothing for this guy

PYVEX_SHALLOW_FUNC(IRSB)
#define emptyIRSB(...) pyvex_shallowCopy_IRSB(emptyIRSB(__VA_ARGS__))
END

cat $VALGRIND_HOME/VEX/priv/ir_defs.c |
	grep -A1000000 "(Deep) copy constructors" |
	grep -B10000000 "Primop types" |
	sed -e "s/shallowCopy/pyvex_shallowCopy/g" |
	sed -e "s/deepCopy/pyvex_deepCopy/g" |
	sed -e "s/bb2->next *= *pyvex_deepCopyIRExpr(bb->next)/bb2->next = NULL; if (bb->next) &/" |
	sed -e "s/case Ico_V128: return IRConst_V128(c->Ico.V128);/&\ncase Ico_V256: return IRConst_V256(c->Ico.V256);/" |
	sed -e "s/LibVEX_Alloc/malloc/g" >> pyvex/pyvex_deepcopy.c

cat >> pyvex/pyvex_deepcopy.c <<END
#undef IRConst_U1
#undef IRConst_U8
#undef IRConst_U16
#undef IRConst_U32
#undef IRConst_U64
#undef IRConst_F32
#undef IRConst_F64
#undef IRConst_F32i
#undef IRConst_F64i
#undef IRConst_V128
#undef IRConst_V256
#undef mkIRCallee
#undef mkIRCallee
#undef mkIRRegArray
#undef IRExpr_Get
#undef IRExpr_GetI
#undef IRExpr_RdTmp
#undef IRExpr_Qop
#undef IRExpr_Triop
#undef IRExpr_Binop
#undef IRExpr_Unop
#undef IRExpr_Load
#undef IRExpr_Const
#undef IRExpr_CCall
#undef IRExpr_ITE
#undef emptyIRDirty
#undef mkIRCAS
#undef mkIRPutI
#undef IRStmt_NoOp
#undef IRStmt_AbiHint
#undef IRStmt_IMark
#undef IRStmt_Put
#undef IRStmt_PutI
#undef IRStmt_WrTmp
#undef IRStmt_Store
#undef IRStmt_CAS
#undef IRStmt_LLSC
#undef IRStmt_Dirty
#undef IRStmt_MBE
#undef IRStmt_Exit
#undef IRStmt_StoreG
#undef IRStmt_LoadG
#undef emptyIRSB
END
