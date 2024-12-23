#ifndef OFFSETS_H
#define OFFSETS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>

enum koffsets {
    offsetof_OSSerializer_serialize,  // OSSerializer::serialize
    offsetof_OSSymbol_getMetaClass,   // OSSymbol::getMetaClass
    offsetof_calend_gettime,          // calend_gettime
    offsetof_bufattr_cpx,             // _bufattr_cpx
    offsetof_clock_ops,               // clock_ops
    offsetof_copyin,                  // _copyin
    offsetof_bx_lr,                   // BX LR
    offsetof_write_gadget,            // write_gadget: str r1, [r0, #0xc] , bx lr
    offsetof_vm_kernel_addrperm,      // vm_kernel_addrperm
    offsetof_kernel_pmap,             // kernel_pmap
    offsetof_flush_dcache,            // flush_dcache
    offsetof_invalidate_tlb,          // invalidate_tlb
    offsetof_task_for_pid,            // task_for_pid
    offsetof_pid_check,               // pid_check_addr offset
    offsetof_posix_check,             // posix_check_ret_addr offset
    offsetof_mac_proc_check,          // mac_proc_check_ret_addr offset
    offsetof_allproc,                 // allproc
    offsetof_p_pid,                   // proc_t::p_pid
    offsetof_p_ucred,                 // proc_t::p_ucred
};

extern uint32_t* offsets;
uint32_t koffset(enum koffsets offset);
void offsets_init(void);

extern int isA6;
extern int isIOS9;

#endif
