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
int vex_init(void);

typedef struct _ExitInfo {
	Int stmt_idx;
	Addr ins_addr;
	IRStmt *stmt;
} ExitInfo;

typedef enum {
	Dt_Unknown = 0x9000,
	Dt_Integer,
	Dt_FP,
	Dt_StoreInteger
} DataRefTypes;

typedef struct _DataRef {
	Addr data_addr;
	Int size;
	DataRefTypes data_type;
	Int stmt_idx;
	Addr ins_addr;
} DataRef;

typedef struct _ConstVal {
	Int tmp;
	Int stmt_idx;
	ULong value;  // 64-bit max
} ConstVal;

#define MAX_EXITS 400
#define MAX_DATA_REFS 2000
#define MAX_CONST_VALS 1000

typedef struct _VEXLiftResult {
	IRSB* irsb;
	Int size;
	Bool is_noop_block;
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
	// Constant propagation
	Int const_val_count;
	ConstVal const_vals[MAX_CONST_VALS];
} VEXLiftResult;

// Simple FIFO queue structure for addresses
typedef struct
{

	Addr *addresses; // Array of addresses
	size_t size; // Current size of the queue
	size_t capacity; // Maximum capacity of the queue
	size_t front; // Index of the front element
	size_t rear; // Index of the rear element

} AddressQueue;

VEXLiftResult *vex_lift(
		VexArch guest,
		VexArchInfo archinfo,
		unsigned char *insn_start,
		unsigned long long insn_addr,
		unsigned int max_insns,
		unsigned int max_bytes,
		int opt_level,
		int traceflags,
		int allow_arch_optimizations,
		int strict_block_end,
		int collect_data_refs,
		int load_from_ro_regions,
		int const_prop,
		VexRegisterUpdates px_control,
		unsigned int lookback_amount,
        Bool clear
);

Bool register_readonly_region(ULong start, ULong size, unsigned char* content);
void deregister_all_readonly_regions();
Bool register_initial_register_value(UInt offset, UInt size, ULong value);
Bool reset_initial_register_values();

// Multi lift functions
#define MAX_LIFTED_BLOCKS 1000
int vex_lift_multi(
	VexArch guest,
	VexArchInfo archinfo,
	unsigned long long insn_addr, // the first time this is the prime address to lift from
	unsigned char *insn_start, // this is the pointer to the start of the instruction bytes
	unsigned int max_blocks, // maximum number of blocks to lift
	unsigned int max_insns, // for each block
	unsigned int max_bytes, // for each block
	int opt_level,
	int traceflags,
	int allow_arch_optimizations,
	int strict_block_end,
	int collect_data_refs,
	int load_from_ro_regions,
	int const_prop,
	VexRegisterUpdates px_control,
	unsigned int lookback,
	VEXLiftResult *lift_results
	);
static void exits_to_fifo (VEXLiftResult *simple_irsb_result, AddressQueue *queue);
static void post_process_irsb(IRSB *irsb, VEXLiftResult *lift_result, VexArch guest,
                              Bool collect_data_refs, Bool load_from_ro_regions, Bool const_prop);
static void vex_prepare_vta_multi(VexArch guest, VexArchInfo archinfo, VexAbiInfo vbi, int traceflags);
static void vex_prepare_vc_multi(unsigned int max_insns, unsigned int max_bytes, int opt_level,
                                 unsigned int lookback, int allow_arch_optimizations, int strict_block_end);
static void vex_update_vta_address(Addr new_addr, unsigned char *new_start);

// FIFO functions
static void init_queue(AddressQueue *queue, int capacity);
static void enqueue(AddressQueue *queue, Addr addr);
static Addr dequeue(AddressQueue *queue);
static Bool is_queue_empty(AddressQueue *queue);
static int is_block_already_lifted(Addr addr, VEXLiftResult *lift_results, int blocks_lifted);
static void clear_queue(AddressQueue *queue);

// Debug/Print functions
static void print_vex_lift_result(const VEXLiftResult *result, const char *label);


#endif
