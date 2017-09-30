// This code is GPLed by Yan Shoshitaishvili

#ifndef __VEXIR_H
#define __VEXIR_H

#include <libvex.h>

// Some info required for translation
extern int log_level;
extern VexTranslateArgs    vta;

extern char *msg_buffer;
extern size_t msg_current_size;

//
// Initializes VEX. This function must be called before vex_lift
// can be used. 
//
void vex_init(void);

IRSB *vex_lift(
		VexArch guest,
		VexArchInfo archinfo,
		unsigned char *insn_start,
		unsigned long long insn_addr,
		unsigned int max_insns,
		unsigned int max_bytes,
		int opt_level,
		int traceflags,
		int allow_lookback);

#endif
