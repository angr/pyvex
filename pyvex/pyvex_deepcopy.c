#include <libvex_ir.h>
#include <stdlib.h>
#include <assert.h>

#include "pyvex_logging.h"
#include "pyvex_deepcopy.h"

#define vpanic(x) { error(x "\n"); assert(0); }

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

      case Iex_Mux0X: 
         return IRExpr_Mux0X(pyvex_deepCopyIRExpr(e->Iex.Mux0X.cond),
                             pyvex_deepCopyIRExpr(e->Iex.Mux0X.expr0),
                             pyvex_deepCopyIRExpr(e->Iex.Mux0X.exprX));
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
   d2->needsBBP = d->needsBBP;
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
   bb->next == NULL;
   if (bb->next) bb2->next = pyvex_deepCopyIRExpr(bb->next);
   bb2->jumpkind = bb->jumpkind;
   bb2->offsIP   = bb->offsIP;
   return bb2;
}


/*---------------------------------------------------------------*/
/*--- Primop types                                            ---*/
