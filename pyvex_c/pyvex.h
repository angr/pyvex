// This code is GPLed by Yan Shoshitaishvili

#ifndef __VEXIR_H
#define __VEXIR_H

#include <libvex.h>

// Some info required for translation
extern int log_level;
extern VexTranslateArgs    vta;

extern char *msg_buffer;
extern size_t msg_current_size;
void clear_log(void);

//
// Initializes VEX. This function must be called before vex_lift
// can be used. 
//
void vex_init(void);

typedef struct _ExitInfo {
	Int stmt_idx;
	Addr ins_addr;
	IRStmt *stmt;
} ExitInfo;

typedef enum {
	Dt_Unknown = 0x9000,
	Dt_Integer,
	Dt_FP
} DataRefTypes;

typedef struct _DataRef {
	Addr data_addr;
	Int size;
	DataRefTypes data_type;
	Int stmt_idx;
	Addr ins_addr;
} DataRef;

#define MAX_EXITS 32
#define MAX_DATA_REFS 2000

typedef struct _VEXLiftResult {
	IRSB* irsb;
	Int size;
	// Conditional exits
	Int exit_count;
	ExitInfo exits[MAX_EXITS];
	// The default exit
	Int is_default_exit_constant;
	Addr default_exit;
	// Instruction addresses
	Int insts;
	Addr inst_addrs[200];
	// Data references
	Int data_ref_count;
	DataRef data_refs[MAX_DATA_REFS];
} VEXLiftResult;

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
		int strict_block_end,
		int collect_data_refs);

#endif
