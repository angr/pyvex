#pragma once
	
IRExpr** pyvex_deepCopyIRExprVec ( IRExpr** vec );
IRConst* pyvex_deepCopyIRConst ( IRConst* c );
IRCallee* pyvex_deepCopyIRCallee ( IRCallee* ce );
IRRegArray* pyvex_deepCopyIRRegArray ( IRRegArray* d );
IRExpr* pyvex_deepCopyIRExpr ( IRExpr* e );
IRDirty* pyvex_deepCopyIRDirty ( IRDirty* d );
IRCAS* pyvex_deepCopyIRCAS ( IRCAS* cas );
IRPutI* pyvex_deepCopyIRPutI ( IRPutI * puti );
IRStmt* pyvex_deepCopyIRStmt ( IRStmt* s );
IRTypeEnv* pyvex_deepCopyIRTypeEnv ( IRTypeEnv* src );
IRSB* pyvex_deepCopyIRSB ( IRSB* bb );
IRSB* pyvex_deepCopyIRSBExceptStmts ( IRSB* bb );
