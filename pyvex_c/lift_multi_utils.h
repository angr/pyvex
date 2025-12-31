#include <stdlib.h>

#include "pyvex.h"
#include "pyvex_internal.h"
#include "logging.h"

// Simple FIFO queue structure for addresses
typedef struct
{

	Addr *addresses; // Array of addresses
	size_t size; // Current size of the queue
	size_t capacity; // Maximum capacity of the queue
	size_t front; // Index of the front element
	size_t rear; // Index of the rear element

} AddressQueue;

// FIFO functions
void exits_to_fifo (VEXLiftResult *simple_irsb_result, AddressQueue *queue, int branch_delay_slot);
void init_queue(AddressQueue *queue, int capacity);
void enqueue(AddressQueue *queue, Addr addr);
Addr dequeue(AddressQueue *queue);
void clear_queue(AddressQueue *queue);
Bool is_queue_empty(AddressQueue *queue);

// Miscelaneous
int is_block_already_lifted(Addr addr, Addr *lifted_addrs, int blocks_lifted);
Bool is_branch_VEX_artifact_only(int branch_delay_slot, Addr branch_inst_addr, IRStmt *stmt, VEXLiftResult *lift_result);
Addr irconst_to_addr(const IRConst *c);
