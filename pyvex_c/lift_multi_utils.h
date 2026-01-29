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

// Hash set bucket size (should be > 2x MAX_LIFTED_BLOCKS for good hash performance)
enum {
	BUCKET_SIZE = 256,
	HASHSET_SIZE = 1024
};

typedef struct
{
	Addr values[BUCKET_SIZE];
	size_t size;
} AddressHashSetValues;

// Hash set for O(1) address lookups (open addressing with linear probing)
// Uses fixed-size global arrays to avoid malloc/calloc overhead
typedef struct
{
	AddressHashSetValues buckets[HASHSET_SIZE];      // Fixed-size array of address slots
	Bool occupied[HASHSET_SIZE];     // Track which slots are used
} AddressHashSet;

// FIFO functions
void exits_to_fifo (VEXLiftResult *simple_irsb_result, AddressQueue *queue, int branch_delay_slot);
void init_queue(AddressQueue *queue, int capacity);
void enqueue(AddressQueue *queue, Addr addr);
Addr dequeue(AddressQueue *queue);
void clear_queue(AddressQueue *queue);
Bool is_queue_empty(AddressQueue *queue);

// Hash set functions for fast address lookups
void init_address_set(AddressHashSet *set);
Bool address_set_contains(AddressHashSet *set, Addr addr);
void address_set_insert(AddressHashSet *set, Addr addr);
void clear_address_set(AddressHashSet *set);

// Miscelaneous
int is_block_already_lifted(Addr addr, Addr *lifted_addrs, int blocks_lifted);
Bool is_branch_VEX_artifact_only(int branch_delay_slot, Addr branch_inst_addr, IRStmt *stmt, VEXLiftResult *lift_result);
Addr irconst_to_addr(const IRConst *c);
