// This code is GPLed by Yan Shoshitaishvili

#ifndef __VEXIR_H
#define __VEXIR_H

#include <libvex.h>

// Some info required for translation
extern VexArchInfo         vai_host;
extern VexArchInfo         vai_guest;
extern VexGuestExtents     vge;
extern VexTranslateArgs    vta;
extern VexTranslateResult  vtr;
extern VexAbiInfo	   vbi;
extern VexControl	   vc;

extern char *last_error;

//
// Initializes VEX. This function must be called before vex_insn
// can be used. 
//
void vex_init(void);

//
// Translates assembly instructions and blocks into VEX
IRSB *vex_instruction(VexArch guest, VexEndness endness, unsigned char *insn_start, unsigned int insn_addr, int max_insns);
IRSB *vex_block_bytes(VexArch guest, VexEndness endness, unsigned char *instructions, unsigned long long block_addr, unsigned int num_bytes, int basic_only);
IRSB *vex_block_inst(VexArch guest, VexEndness endness, unsigned char *instructions, unsigned long long block_addr, unsigned int num_inst);
unsigned int vex_count_instructions(VexArch guest, VexEndness endness, unsigned char *instructions, unsigned long long block_addr, unsigned int num_bytes, int basic_only);
void set_iropt_level(int level);

#endif
