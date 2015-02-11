// This code is GPLed by Yan Shoshitaishvili

#ifndef __COMMON_H
#define __COMMON_H

extern int debug_on;
extern int info_on;
extern int error_on;

void debug(char *, ...);
void info(char *, ...);
void pyvex_error(char *, ...);

#endif
