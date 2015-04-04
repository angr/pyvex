// This code is GPLed by Yan Shoshitaishvili

#ifndef __PYMARE_TYPES_H
#define __PYMARE_TYPES_H

#include "libvex.h"
#include <Python.h>

// the module itself
extern PyObject *module;

// exceptions from pyvex
extern PyObject *PyVEXError;

// blocks
PyObject *init_IRSB(PyObject *, PyObject *, PyObject *);
extern PyObject *pyvexIRSB;

// type env
extern PyObject *pyvexIRTypeEnv;

// ir constants
extern PyObject *pyvexIRConst;
extern PyObject *pyvexIRConstU1;
extern PyObject *pyvexIRConstU8;
extern PyObject *pyvexIRConstU16;
extern PyObject *pyvexIRConstU32;
extern PyObject *pyvexIRConstU64;
extern PyObject *pyvexIRConstF32;
extern PyObject *pyvexIRConstF32i;
extern PyObject *pyvexIRConstF64;
extern PyObject *pyvexIRConstF64i;
extern PyObject *pyvexIRConstV128;
extern PyObject *pyvexIRConstV256;

// statements
extern PyObject *pyvexIRStmt;
extern PyObject *pyvexIRStmtNoOp;
extern PyObject *pyvexIRStmtIMark;
extern PyObject *pyvexIRStmtAbiHint;
extern PyObject *pyvexIRStmtPut;
extern PyObject *pyvexIRStmtPutI;
extern PyObject *pyvexIRStmtWrTmp;
extern PyObject *pyvexIRStmtStore;
extern PyObject *pyvexIRStmtCAS;
extern PyObject *pyvexIRStmtLLSC;
extern PyObject *pyvexIRStmtMBE;
extern PyObject *pyvexIRStmtDirty;
extern PyObject *pyvexIRStmtExit;
extern PyObject *pyvexIRStmtLoadG;
extern PyObject *pyvexIRStmtStoreG;

// expressions
extern PyObject *pyvexIRExpr;
extern PyObject *pyvexIRExprBinder;
extern PyObject *pyvexIRExprVECRET;
extern PyObject *pyvexIRExprBBPTR;
extern PyObject *pyvexIRExprGetI;
extern PyObject *pyvexIRExprRdTmp;
extern PyObject *pyvexIRExprGet;
extern PyObject *pyvexIRExprQop;
extern PyObject *pyvexIRExprTriop;
extern PyObject *pyvexIRExprBinop;
extern PyObject *pyvexIRExprUnop;
extern PyObject *pyvexIRExprLoad;
extern PyObject *pyvexIRExprConst;
extern PyObject *pyvexIRExprITE;
extern PyObject *pyvexIRExprCCall;

// IRCallee
extern PyObject *pyvexIRCallee;

// IRRegArray
extern PyObject *pyvexIRRegArray;

#endif
