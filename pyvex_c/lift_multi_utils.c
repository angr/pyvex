//======================================================================
//
// This file provides the necesary functions to the multi lift feature
// of angr, as a part of Bruno Guglielmotti and Franco Rodriguez tesis
//
//======================================================================

#include <stdio.h>
#include "lift_multi_utils.h"

//======================================================================
// Queue Functions
//======================================================================

// Initialize queue
void init_queue(AddressQueue *queue, int capacity) {
    queue->addresses = malloc(capacity * sizeof(Addr));
    queue->front = 0;
    queue->rear = 0;
    queue->size = 0;
    queue->capacity = capacity;
}

// Add address to queue
void enqueue(AddressQueue *queue, Addr addr) {
    if (queue->size < queue->capacity) {
        queue->addresses[queue->rear] = addr;
        queue->rear = (queue->rear + 1) % queue->capacity;
        queue->size++;
    }
}

// Remove address from queue
Addr dequeue(AddressQueue *queue) {
    if (queue->size > 0) {
        Addr addr = queue->addresses[queue->front];
        queue->front = (queue->front + 1) % queue->capacity;
        queue->size--;
        return addr;
    }
    return 0; // Invalid address
}

// Delete queue
void clear_queue(AddressQueue *queue) {
	free(queue->addresses);
	queue->addresses = NULL;
	queue->front = 0;
	queue->rear = 0;
	queue->size = 0;
	queue->capacity = 0;
}

// Check if queue is empty
Bool is_queue_empty(AddressQueue *queue) {
    return queue->size == 0;
}

// Enqueue all exit addresses into the FIFO queue
void exits_to_fifo (VEXLiftResult *simple_irsb_result, AddressQueue *queue, int branch_delay_slot) {

    // Enqueue the default exit address if it is constant
	if ( simple_irsb_result->is_default_exit_constant == 1 ){
		enqueue(queue, (unsigned long long)simple_irsb_result->default_exit);
	}
    else{
        pyvex_debug("\t\tDefault exit is not constant\n");
    }

    // Enqueue all conditional exit addresses into the FIFO queue
	for (int i = 0; i < simple_irsb_result->exit_count; i++) {
        // Skip branch artifacts that VEX adds for delay slots
        if (is_branch_VEX_artifact_only(branch_delay_slot,
                                        simple_irsb_result->exits[i].ins_addr,
                                        simple_irsb_result->exits[i].stmt,
                                        simple_irsb_result)) {
            continue;
        }
        Addr target_addr = irconst_to_addr(simple_irsb_result->exits[i].stmt->Ist.Exit.dst);
		enqueue(queue, target_addr);
	}
}

//======================================================================
// Hash Set Functions (for fast O(1) address lookups)
//======================================================================

// Hash function using Knuth's multiplicative method
static size_t hash_addr(Addr addr) {
    return (size_t)((addr * 2654435761ULL) % HASHSET_SIZE);
}

// Initialize the hash set (resets the fixed-size arrays)
void init_address_set(AddressHashSet *set) {
    for (size_t i = 0; i < HASHSET_SIZE; i++) {
        set->occupied[i] = False;
	set->buckets[i].size = 0;
    }
}

// Check if an address exists in the set - O(1) average case
Bool address_set_contains(AddressHashSet *set, Addr addr) {
    size_t index = hash_addr(addr);
    if (!set->occupied[index]) {
	    return False;
    }
    AddressHashSetValues *bucket = &set->buckets[index];
    size_t i = 0;

    while (i < bucket->size) {
        if (bucket->values[i] == addr) {
            return True;
        }
        i = i + 1;
        if (i == BUCKET_SIZE) {
            break; // reached the end
        }
    }
    return False;
}

// Insert an address into the set - O(1) average case
void address_set_insert(AddressHashSet *set, Addr addr) {
    size_t index = hash_addr(addr);
    AddressHashSetValues *bucket = &set->buckets[index];

    if (bucket->size >= BUCKET_SIZE) {
        pyvex_error("AddressHashSet is full, cannot insert.\n");
        return;
    }
    size_t i = 0;

    while (i < bucket->size) {
        if (bucket->values[i] == addr) {
            return;  // Already exists
        }
        i = i + 1;
    }

    set->occupied[index] = 1;
    bucket->values[i] = addr;
    bucket->size++;
}

// Reset the hash set (no memory to free since arrays are fixed-size)
void clear_address_set(AddressHashSet *set) {
	return;
    for (size_t i = 0; i < HASHSET_SIZE; i++) {
        set->occupied[i] = False;
	set->buckets[i].size = 0;
    }
}

//======================================================================
// Miscelaneous
//======================================================================

Addr irconst_to_addr(const IRConst *c) {
    switch (c->tag) {
        case Ico_U8:
            return (Addr)c->Ico.U8;
        case Ico_U16:
            return (Addr)c->Ico.U16;
        case Ico_U32:
            return (Addr)c->Ico.U32;
        case Ico_U64:
            return (Addr)c->Ico.U64;
        default:
            pyvex_error("Invalid IRConst tag in irconst_to_addr.\n");
            return 0;
    }
}

Bool is_branch_VEX_artifact_only(int branch_delay_slot, Addr branch_inst_addr, IRStmt *stmt, VEXLiftResult *lift_result) {
    return !branch_delay_slot &&
           lift_result->insts > 0 &&
           lift_result->inst_addrs[lift_result->insts - 1] != branch_inst_addr &&
           irconst_to_addr(stmt->Ist.Exit.dst) == branch_inst_addr &&
           stmt->Ist.Exit.jk == Ijk_Boring;
}

// Check if a block has already been lifted to avoid duplicates
int is_block_already_lifted(Addr addr, Addr *lifted_addrs, int blocks_lifted) {
	for (int i = 0; i < blocks_lifted; i++) {
		if (lifted_addrs[i] == addr) {
			return 1; // Block already lifted
		}
	}
	return 0; // Block not lifted yet
}
