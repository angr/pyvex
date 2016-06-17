// This code is GPLed by Yan Shoshitaishvili

#ifndef __VEXIR_H
#define __VEXIR_H

#include <libvex.h>

// Some info required for translation
extern VexTranslateArgs    vta;

extern char *last_error;

//
// Initializes VEX. This function must be called before vex_insn
// can be used. 
//
void vex_init(void);

//
// Translates assembly instructions and blocks into VEX
IRSB *vex_block_bytes(VexArch guest, VexArchInfo archinfo, unsigned char *instructions, unsigned long long block_addr, unsigned int num_bytes, int basic_only);
IRSB *vex_block_inst(VexArch guest, VexArchInfo archinfo, unsigned char *instructions, unsigned long long block_addr, unsigned int num_inst);
unsigned int vex_count_instructions(VexArch guest, VexArchInfo archinfo, unsigned char *instructions, unsigned long long block_addr, unsigned int num_bytes, int basic_only);
void set_iropt_level(int level);
void enable_debug(int debug);

#endif
