#ifndef __def_stack_reg
#define __def_stack_reg

#include <stdint.h>

uint64_t read_from_address_64(uint64_t);
uint32_t read_from_address_32(uint64_t);

/*
 * Prints the stack frame of the caller. When this function is entered, the stack looks like
 * this (from high address to low address):
 *
 * 0. The return address from the caller
 * 1. The value RBP had at the start of the caller function
 * 2. Stack space for the caller function
 * 3. The return address from the callee
 * 4. Pointer to the base of the frame (RBP) of the caller function
 * 5. Stack space for this function
 *
 * We want to access the data located at point #2. To do this we get the value of #1 and
 * go in words decrements until the point #3 is reached.
 */
void print_stack_frame();

/*
 * Prints the contents of the registers on the CPU. To do that, we push (save) the values
 * of all registers and then pop them into the local variables in the frame stack.
 */
void print_registers();

#endif // __def_stack_reg

