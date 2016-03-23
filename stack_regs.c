#include <stdio.h>
#include "stack_regs.h"

/*
 * Reads from an address on 64 bits.
 */
uint64_t read_from_address_64(uint64_t address) {
    uint64_t complete;
    asm ("movq (%1),%0" : "=r" (complete) : "r" (address));
    return complete;
}

/*
 * Reads an address on 32 bits.
 */
uint32_t read_from_address_32(uint64_t address) {
    return *((int *)address);
}

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
void print_stack_frame() {

    uint64_t caller_base_addr; // #1, the address where the base of the stack of the caller is
    uint64_t callee_base_addr; // #4, the address where the base of the stack of the callee is
    asm ("mov (%%rbp),%0" : "=r" (caller_base_addr));
    asm ("lea (%%rbp),%0" : "=r" (callee_base_addr));

    printf("curr stack frame    %016llx\n", caller_base_addr);

    uint64_t caller_old_rbp = read_from_address_64(caller_base_addr);
    printf("prev stack frame    %016llx\n", caller_old_rbp);

    // This is the address where the caller will return once its execution is complete.
    // Since an address is 8 bytes, it is located 8 bytes before the base of the stack.
    uint64_t caller_addr_ret = read_from_address_64(caller_base_addr + 8);
    printf("return to           %016llx\n", caller_addr_ret);

    printf("  - locals space -\n");

    // The instruction is 'callq' so the return address pushed on stack is 8 bytes. We don't
    // want to print it. Same for the thing that is at [RBP], we don't want to print it so
    // we start at caller_base - 8.
    uint64_t read_addr = caller_base_addr - 8;
    int index = 0;

    while (read_addr != callee_base_addr + 8) {

        uint32_t read_word = read_from_address_32(read_addr);
        uint8_t a_read = (uint8_t)(read_word & 0x000000ff);
        uint8_t b_read = (uint8_t)((read_word & 0x0000ff00) >> 8);
        uint8_t c_read = (uint8_t)((read_word & 0x00ff0000) >> 16);
        uint8_t d_read = (uint8_t)((read_word & 0xff000000) >> 24);

        printf("* %016llx    %%rbp-%x:\t", read_addr, index);
        printf("%02x %02x %02x %02x\n", d_read, c_read, b_read, a_read);

        index += 4;
        read_addr -= 4;
    }

    printf("  - top of stack -\n");
}

/*
 * Prints the contents of the registers on the CPU. To do that, we push (save) the values
 * of all registers and then pop them into the local variables in the frame stack.
 */
void print_registers() {

    // 17 64-bit registers
    int64_t rax, rbx, rcx, rdx, rbp, rsp, rsi, rdi;
    int64_t r8, r9, r10, r11, r12, r13, r14, r15;
    int64_t rip;

    // 17 registers of 8 bytes each = 17*8 = 88 bytes for locals reserved on the stack.
    asm volatile (
      "pushq %%rax\npushq %%rbx\npushq %%rcx\npushq %%rdx\n"
      "pushq %%rsi\npushq %%rdi\npushq %%r8 \npushq %%r9 \npushq %%r10\n"
      "pushq %%r11\npushq %%r12\npushq %%r13\npushq %%r14\npushq %%r15\n"

      // To RSP may have been modified in the prologue. We put it back to the start of the
      // stack frame (the value of RBP)
      "pushq %%rbp\n"

      // The RBP register contains the bottom of our stack frame, but we want to print the
      // bottom of the caller's stack frame. This address is located at the base of the
      // current stack frame.
      "movq (%%rbp),%%rax\n"
      "pushq %%rax"
      ::: "memory"
    );

    // We pop back the values of the registers into the right local variables
    asm volatile (
      "popq %0\npopq %1\npopq %2\npopq %3\npopq %4\npopq %5\n popq %6\npopq %7"
      : "=r"(rbp), "=r"(rsp), "=r"(r15), "=r"(r14), "=r"(r13), "=r"(r12), "=r"(r11), "=r"(r10)
    );
    asm volatile (
      "popq %0\npopq %1\npopq %2\npopq %3\npopq %4\npopq %5\n popq %6\npopq %7"
      : "=r"(r9), "=r"(r8), "=r"(rdi), "=r"(rsi), "=r"(rdx), "=r"(rcx), "=r"(rbx), "=r"(rax)
    );

    // Get the value of RIP in the old stack frame (that is, current RBP+8)
    asm volatile ("movq 0x8(%%rbp),%0" : "=r"(rip));

    // We print the contents of the registers on the screen in no particular order
    printf("rax %016llx\n", rax); printf("rbx %016llx\n", rbx);
    printf("rcx %016llx\n", rcx); printf("rdx %016llx\n", rdx);
    printf("rbp %016llx\n", rbp); printf("rsp %016llx\n", rsp);
    printf("rsi %016llx\n", rsi); printf("rdi %016llx\n", rdi);
    printf("rip %016llx\n", rip); printf("r8  %016llx\n", r8);
    printf("r9  %016llx\n", r9);  printf("r10 %016llx\n", r10);
    printf("r11 %016llx\n", r11); printf("r12 %016llx\n", r12);
    printf("r13 %016llx\n", r13); printf("r14 %016llx\n", r14);
    printf("r15 %016llx\n", r15);
}

