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
#define IRExpr_Mux0X(...) pyvex_shallowCopy_IRExpr(IRExpr_Mux0X(__VA_ARGS__))

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

PYVEX_SHALLOW_FUNC(IRTypeEnv)
// nothing for this guy

PYVEX_SHALLOW_FUNC(IRSB)
#define emptyIRSB(...) pyvex_shallowCopy_IRSB(emptyIRSB(__VA_ARGS__))
/*--- (Deep) copy constructors.  These make complete copies   ---*/
/*--- the original, which can be modified without affecting   ---*/
/*--- the original.                                           ---*/
/*---------------------------------------------------------------*/

/* Copying IR Expr vectors (for call args). */

/* Shallow copy of an IRExpr vector */

IRExpr** pyvex_shallowCopyIRExprVec ( IRExpr** vec )
{
   Int      i;
   IRExpr** newvec;
   for (i = 0; vec[i]; i++)
      ;
   newvec = malloc((i+1)*sizeof(IRExpr*));
   for (i = 0; vec[i]; i++)
      newvec[i] = vec[i];
   newvec[i] = NULL;
   return newvec;
}

/* Deep copy of an IRExpr vector */

IRExpr** pyvex_deepCopyIRExprVec ( IRExpr** vec )
{
   Int      i;
   IRExpr** newvec = pyvex_shallowCopyIRExprVec( vec );
   for (i = 0; newvec[i]; i++)
      newvec[i] = pyvex_deepCopyIRExpr(newvec[i]);
   return newvec;
}

/* Deep copy constructors for all heap-allocated IR types follow. */

IRConst* pyvex_deepCopyIRConst ( IRConst* c )
{
   switch (c->tag) {
      case Ico_U1:   return IRConst_U1(c->Ico.U1);
      case Ico_U8:   return IRConst_U8(c->Ico.U8);
      case Ico_U16:  return IRConst_U16(c->Ico.U16);
      case Ico_U32:  return IRConst_U32(c->Ico.U32);
      case Ico_U64:  return IRConst_U64(c->Ico.U64);
      case Ico_F32:  return IRConst_F32(c->Ico.F32);
      case Ico_F32i: return IRConst_F32i(c->Ico.F32i);
      case Ico_F64:  return IRConst_F64(c->Ico.F64);
      case Ico_F64i: return IRConst_F64i(c->Ico.F64i);
      case Ico_V128: return IRConst_V128(c->Ico.V128);
case Ico_V256: return IRConst_V256(c->Ico.V256);
      default: vpanic("pyvex_deepCopyIRConst");
   }
}

IRCallee* pyvex_deepCopyIRCallee ( IRCallee* ce )
{
   IRCallee* ce2 = mkIRCallee(ce->regparms, ce->name, ce->addr);
   ce2->mcx_mask = ce->mcx_mask;
   return ce2;
}

IRRegArray* pyvex_deepCopyIRRegArray ( IRRegArray* d )
{
   return mkIRRegArray(d->base, d->elemTy, d->nElems);
}

IRExpr* pyvex_deepCopyIRExpr ( IRExpr* e )
{
   switch (e->tag) {
      case Iex_Get: 
         return IRExpr_Get(e->Iex.Get.offset, e->Iex.Get.ty);
      case Iex_GetI: 
         return IRExpr_GetI(pyvex_deepCopyIRRegArray(e->Iex.GetI.descr), 
                            pyvex_deepCopyIRExpr(e->Iex.GetI.ix),
                            e->Iex.GetI.bias);
      case Iex_RdTmp: 
         return IRExpr_RdTmp(e->Iex.RdTmp.tmp);
      case Iex_Qop: {
         IRQop* qop = e->Iex.Qop.details;

         return IRExpr_Qop(qop->op,
                           pyvex_deepCopyIRExpr(qop->arg1),
                           pyvex_deepCopyIRExpr(qop->arg2),
                           pyvex_deepCopyIRExpr(qop->arg3),
                           pyvex_deepCopyIRExpr(qop->arg4));
      }
      case Iex_Triop:  {
         IRTriop *triop = e->Iex.Triop.details;

         return IRExpr_Triop(triop->op,
                             pyvex_deepCopyIRExpr(triop->arg1),
                             pyvex_deepCopyIRExpr(triop->arg2),
                             pyvex_deepCopyIRExpr(triop->arg3));
      }
      case Iex_Binop: 
         return IRExpr_Binop(e->Iex.Binop.op,
                             pyvex_deepCopyIRExpr(e->Iex.Binop.arg1),
                             pyvex_deepCopyIRExpr(e->Iex.Binop.arg2));
      case Iex_Unop: 
         return IRExpr_Unop(e->Iex.Unop.op,
                            pyvex_deepCopyIRExpr(e->Iex.Unop.arg));
      case Iex_Load: 
         return IRExpr_Load(e->Iex.Load.end,
                            e->Iex.Load.ty,
                            pyvex_deepCopyIRExpr(e->Iex.Load.addr));
      case Iex_Const: 
         return IRExpr_Const(pyvex_deepCopyIRConst(e->Iex.Const.con));
      case Iex_CCall:
         return IRExpr_CCall(pyvex_deepCopyIRCallee(e->Iex.CCall.cee),
                             e->Iex.CCall.retty,
                             pyvex_deepCopyIRExprVec(e->Iex.CCall.args));

      case Iex_ITE: 
         return IRExpr_ITE(pyvex_deepCopyIRExpr(e->Iex.ITE.cond),
                           pyvex_deepCopyIRExpr(e->Iex.ITE.iftrue),
                           pyvex_deepCopyIRExpr(e->Iex.ITE.iffalse));
      case Iex_VECRET:
         return IRExpr_VECRET();

      case Iex_BBPTR:
         return IRExpr_BBPTR();

      default:
         vpanic("pyvex_deepCopyIRExpr");
   }
}

IRDirty* pyvex_deepCopyIRDirty ( IRDirty* d )
{
   Int      i;
   IRDirty* d2 = emptyIRDirty();
   d2->cee   = pyvex_deepCopyIRCallee(d->cee);
   d2->guard = pyvex_deepCopyIRExpr(d->guard);
   d2->args  = pyvex_deepCopyIRExprVec(d->args);
   d2->tmp   = d->tmp;
   d2->mFx   = d->mFx;
   d2->mAddr = d->mAddr==NULL ? NULL : pyvex_deepCopyIRExpr(d->mAddr);
   d2->mSize = d->mSize;
   d2->nFxState = d->nFxState;
   for (i = 0; i < d2->nFxState; i++)
      d2->fxState[i] = d->fxState[i];
   return d2;
}

IRCAS* pyvex_deepCopyIRCAS ( IRCAS* cas )
{
   return mkIRCAS( cas->oldHi, cas->oldLo, cas->end,
                   pyvex_deepCopyIRExpr(cas->addr),
                   cas->expdHi==NULL ? NULL : pyvex_deepCopyIRExpr(cas->expdHi),
                   pyvex_deepCopyIRExpr(cas->expdLo),
                   cas->dataHi==NULL ? NULL : pyvex_deepCopyIRExpr(cas->dataHi),
                   pyvex_deepCopyIRExpr(cas->dataLo) );
}

IRPutI* pyvex_deepCopyIRPutI ( IRPutI * puti )
{
  return mkIRPutI( pyvex_deepCopyIRRegArray(puti->descr),
                   pyvex_deepCopyIRExpr(puti->ix),
                   puti->bias, 
                   pyvex_deepCopyIRExpr(puti->data));
}

IRStmt* pyvex_deepCopyIRStmt ( IRStmt* s )
{
   switch (s->tag) {
      case Ist_NoOp:
         return IRStmt_NoOp();
      case Ist_AbiHint:
         return IRStmt_AbiHint(pyvex_deepCopyIRExpr(s->Ist.AbiHint.base),
                               s->Ist.AbiHint.len,
                               pyvex_deepCopyIRExpr(s->Ist.AbiHint.nia));
      case Ist_IMark:
         return IRStmt_IMark(s->Ist.IMark.addr,
                             s->Ist.IMark.len,
                             s->Ist.IMark.delta);
      case Ist_Put: 
         return IRStmt_Put(s->Ist.Put.offset, 
                           pyvex_deepCopyIRExpr(s->Ist.Put.data));
      case Ist_PutI: 
         return IRStmt_PutI(pyvex_deepCopyIRPutI(s->Ist.PutI.details));
      case Ist_WrTmp:
         return IRStmt_WrTmp(s->Ist.WrTmp.tmp,
                             pyvex_deepCopyIRExpr(s->Ist.WrTmp.data));
      case Ist_Store: 
         return IRStmt_Store(s->Ist.Store.end,
                             pyvex_deepCopyIRExpr(s->Ist.Store.addr),
                             pyvex_deepCopyIRExpr(s->Ist.Store.data));
      case Ist_StoreG: {
         IRStoreG* sg = s->Ist.StoreG.details;
         return IRStmt_StoreG(sg->end,
                              pyvex_deepCopyIRExpr(sg->addr),
                              pyvex_deepCopyIRExpr(sg->data),
                              pyvex_deepCopyIRExpr(sg->guard));
      }
      case Ist_LoadG: {
         IRLoadG* lg = s->Ist.LoadG.details;
         return IRStmt_LoadG(lg->end, lg->cvt, lg->dst,
                             pyvex_deepCopyIRExpr(lg->addr),
                             pyvex_deepCopyIRExpr(lg->alt),
                             pyvex_deepCopyIRExpr(lg->guard));
      }
      case Ist_CAS:
         return IRStmt_CAS(pyvex_deepCopyIRCAS(s->Ist.CAS.details));
      case Ist_LLSC:
         return IRStmt_LLSC(s->Ist.LLSC.end,
                            s->Ist.LLSC.result,
                            pyvex_deepCopyIRExpr(s->Ist.LLSC.addr),
                            s->Ist.LLSC.storedata
                               ? pyvex_deepCopyIRExpr(s->Ist.LLSC.storedata)
                               : NULL);
      case Ist_Dirty: 
         return IRStmt_Dirty(pyvex_deepCopyIRDirty(s->Ist.Dirty.details));
      case Ist_MBE:
         return IRStmt_MBE(s->Ist.MBE.event);
      case Ist_Exit: 
         return IRStmt_Exit(pyvex_deepCopyIRExpr(s->Ist.Exit.guard),
                            s->Ist.Exit.jk,
                            pyvex_deepCopyIRConst(s->Ist.Exit.dst),
                            s->Ist.Exit.offsIP);
      default: 
         vpanic("pyvex_deepCopyIRStmt");
   }
}

IRTypeEnv* pyvex_deepCopyIRTypeEnv ( IRTypeEnv* src )
{
   Int        i;
   IRTypeEnv* dst = malloc(sizeof(IRTypeEnv));
   dst->types_size = src->types_size;
   dst->types_used = src->types_used;
   dst->types = malloc(dst->types_size * sizeof(IRType));
   for (i = 0; i < src->types_used; i++)
      dst->types[i] = src->types[i];
   return dst;
}

IRSB* pyvex_deepCopyIRSB ( IRSB* bb )
{
   Int      i;
   IRStmt** sts2;
   IRSB* bb2 = pyvex_deepCopyIRSBExceptStmts(bb);
   bb2->stmts_used = bb2->stmts_size = bb->stmts_used;
   sts2 = malloc(bb2->stmts_used * sizeof(IRStmt*));
   for (i = 0; i < bb2->stmts_used; i++)
      sts2[i] = pyvex_deepCopyIRStmt(bb->stmts[i]);
   bb2->stmts = sts2;
   return bb2;
}

IRSB* pyvex_deepCopyIRSBExceptStmts ( IRSB* bb )
{
   IRSB* bb2     = emptyIRSB();
   bb2->tyenv    = pyvex_deepCopyIRTypeEnv(bb->tyenv);
   bb2->next = NULL; if (bb->next) bb2->next     = pyvex_deepCopyIRExpr(bb->next);
   bb2->jumpkind = bb->jumpkind;
   bb2->offsIP   = bb->offsIP;
   return bb2;
}


/*---------------------------------------------------------------*/
/*--- Primop types                                            ---*/
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
#undef IRExpr_Mux0X
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
#undef emptyIRSB
