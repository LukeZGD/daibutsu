#include "offsets.h"

/*
 * task_for_pid: 10460BB0B0BD00BFF0B503AF2DE9000D A5
 * task_for_pid: 96700BB0B0BD00BFF0B503AF2DE9000D A6 (or A5 9.0.x)
 * select f0
 *
 * flush_dcache: 0000A0E35E0F07EE
 * select first 00
 *
 * invalidate_tlb: 0000A0E3170F08EE
 * select first 00
 */

uint32_t koffsets_S5L895xX_902[] = {
    0x31e7bc,   // OSSerializer::serialize
    0x320f00,   // OSSymbol::getMetaClass
    0x1e718,    // calend_gettime
    0xde9fc,    // _bufattr_cpx
    0x40a3cc,   // clock_ops
    0xcb87c,    // _copyin
    0xde9fe,    // BX LR
    0xcb5a8,    // write_gadget: str r1, [r0, #0xc] , bx lr
    0x45c0c4,   // vm_kernel_addrperm
    0x3fd444,   // kernel_pmap
    0xbf5ac,    // flush_dcache
    0xcb600,    // invalidate_tlb
    0x302bdc,   // task_for_pid
    0x18+2,     // pid_check_addr offset
    0x40,       // posix_check_ret_addr offset
    0x224,      // mac_proc_check_ret_addr offset
    0x45d9b0,   // allproc
    0x8,        // proc_t::p_pid
    0x8c,       // proc_t::p_ucred
};

uint32_t koffsets_S5L894xX_902[] = {
    0x317de4,   // OSSerializer::serialize
    0x31a5d0,   // OSSymbol::getMetaClass
    0x1daec,    // calend_gettime
    0xd97d0,    // _bufattr_cpx
    0x40a3cc,   // clock_ops
    0xcc754,    // _copyin
    0xd97d2,    // BX LR
    0xc7488,    // write_gadget: str r1, [r0, #0xc] , bx lr
    0x455fa0,   // vm_kernel_addrperm
    0x3f7444,   // kernel_pmap
    0xbc9b8,    // flush_dcache
    0xc74e0,    // invalidate_tlb
    0x2fca70,   // task_for_pid
    0x18+2,     // pid_check_addr offset
    0x40,       // posix_check_ret_addr offset
    0x224,      // mac_proc_check_ret_addr offset
    0x403c34,   // allproc
    0x8,        // proc_t::p_pid
    0x8c,       // proc_t::p_ucred
};

uint32_t koffsets_S5L895xX_841[] = { // 8.4.1 A6
    0x2d9864,   // OSSerializer::serialize
    0x2db984,   // OSSymbol::getMetaClass
    0x1d300,    // calend_gettime
    0xc65f4,    // _bufattr_cpx
    0x3b1cdc,   // clock_ops
    0xb386c,    // _copyin
    0xc65f6,    // BX LR
    0xb35a8,    // write_gadget: str r1, [r0, #0xc] , bx lr
    0x3f8258,   // vm_kernel_addrperm
    0x3a711c,   // kernel_pmap
    0xa7758,    // flush_dcache
    0xb3600,    // invalidate_tlb
    0x2c05c8,   // task_for_pid
    0x16+2,     // pid_check_addr offset
    0x3e,       // posix_check_ret_addr offset
    0x222,      // mac_proc_check_ret_addr offset
    0x3f9970,   // allproc
    0x8,        // proc_t::p_pid
    0x8c,       // proc_t::p_ucred
};

uint32_t koffsets_S5L895xX_840[] = { // 8.4 A6
    0x2d9758,   // OSSerializer::serialize
    0x2db878,   // OSSymbol::getMetaClass
    0x1d300,    // calend_gettime
    0xc65f4,    // _bufattr_cpx
    0x3b1cdc,   // clock_ops
    0xb386c,    // _copyin
    0xc65f6,    // BX LR
    0xb35a8,    // write_gadget: str r1, [r0, #0xc] , bx lr
    0x3f8258,   // vm_kernel_addrperm
    0x3a711c,   // kernel_pmap
    0xa7610,    // flush_dcache
    0xb3600,    // invalidate_tlb
    0x2c04d4,   // task_for_pid
    0x16+2,     // pid_check_addr offset
    0x3e,       // posix_check_ret_addr offset
    0x224,      // mac_proc_check_ret_addr offset
    0x3f9970,   // allproc
    0x8,        // proc_t::p_pid
    0x8c,       // proc_t::p_ucred
};

uint32_t koffsets_S5L895xX_830[] = { // 8.3 A6
    0x2d96e4,   // OSSerializer::serialize
    0x2db804,   // OSSymbol::getMetaClass
    0x1d2e0,    // calend_gettime 0x1d300?
    0xc65f4,    // _bufattr_cpx
    0x3b1cdc,   // clock_ops
    0xb384c,    // _copyin
    0xc65f6,    // BX LR
    0xb3588,    // write_gadget: str r1, [r0, #0xc] , bx lr // search _clock_get_calendar_nanotime - 0x18
    0x3f8258,   // vm_kernel_addrperm
    0x3a711c,   // kernel_pmap
    0xa7400,    // flush_dcache
    0xb35e0,    // invalidate_tlb
    0x2c0450,   // task_for_pid
    0x16+2,     // pid_check_addr offset
    0x3e,       // posix_check_ret_addr offset
    0x224,      // mac_proc_check_ret_addr offset
    0x3f9970,   // allproc
    0x8,        // proc_t::p_pid
    0x8c,       // proc_t::p_ucred
};

uint32_t koffsets_S5L895xX_820[] = { // 8.2 A6
    0x2cd790,   // OSSerializer::serialize
    0x2cf8b0,   // OSSymbol::getMetaClass
    0x1c21c,    // calend_gettime 0x1d300?
    0xc3824,    // _bufattr_cpx
    0x3a4ce0,   // clock_ops
    0xb086c,    // _copyin
    0xc3826,    // BX LR
    0xb05a8,    // write_gadget: str r1, [r0, #0xc] , bx lr // search _clock_get_calendar_nanotime - 0x18
    0x3eb200,   // vm_kernel_addrperm
    0x39a11c,   // kernel_pmap
    0xa4894,    // flush_dcache
    0xb0600,    // invalidate_tlb
    0x2b4888,   // task_for_pid
    0x16+2,     // pid_check_addr offset
    0x3e,       // posix_check_ret_addr offset
    0x224,      // mac_proc_check_ret_addr offset
    0x3ec8f0,   // allproc
    0x8,        // proc_t::p_pid
    0x8c,       // proc_t::p_ucred
};

uint32_t koffsets_S5L895xX_813[] = { // 8.1.3 A6
    0x2ca9a0,   // OSSerializer::serialize
    0x2ccac0,   // OSSymbol::getMetaClass
    0x1bf5c,    // calend_gettime 0x1d300?
    0xc04c4,    // _bufattr_cpx
    0x3a1ce0,   // clock_ops
    0xad86c,    // _copyin
    0xc04c6,    // BX LR
    0xad5a8,    // write_gadget: str r1, [r0, #0xc] , bx lr // search _clock_get_calendar_nanotime - 0x18
    0x3e8208,   // vm_kernel_addrperm
    0x39711c,   // kernel_pmap
    0xa1d14,    // flush_dcache
    0xad600,    // invalidate_tlb
    0x2b1b8c,   // task_for_pid
    0x16+2,     // pid_check_addr offset
    0x3e,       // posix_check_ret_addr offset
    0x224,      // mac_proc_check_ret_addr offset
    0x3e98e8,   // allproc
    0x8,        // proc_t::p_pid
    0x8c,       // proc_t::p_ucred
};

uint32_t koffsets_S5L895xX_812[] = { // 8.1.2 A6
    0x2ca860,   // OSSerializer::serialize
    0x2cc980,   // OSSymbol::getMetaClass
    0x1be84,    // calend_gettime 0x1d300?
    0xc0304,    // _bufattr_cpx
    0x3a1ce0,   // clock_ops
    0xad86c,    // _copyin
    0xc0306,    // BX LR
    0xad5a8,    // write_gadget: str r1, [r0, #0xc] , bx lr // search _clock_get_calendar_nanotime - 0x18
    0x3e8208,   // vm_kernel_addrperm
    0x39711c,   // kernel_pmap
    0xa1ca4,    // flush_dcache
    0xad600,    // invalidate_tlb
    0x2b1968,   // task_for_pid
    0x16+2,     // pid_check_addr offset
    0x3e,       // posix_check_ret_addr offset
    0x224,      // mac_proc_check_ret_addr offset
    0x3e98c4,   // allproc
    0x8,        // proc_t::p_pid
    0x8c,       // proc_t::p_ucred
};

uint32_t koffsets_S5L895xX_810[] = { // 8.1 A6
    0x2ca3e0,   // OSSerializer::serialize
    0x2cc500,   // OSSymbol::getMetaClass
    0x1be60,    // calend_gettime 0x1d300?
    0xc02f4,    // _bufattr_cpx
    0x3a1ce0,   // clock_ops
    0xad86c,    // _copyin
    0xc02f6,    // BX LR
    0xad5a8,    // write_gadget: str r1, [r0, #0xc] , bx lr // search _clock_get_calendar_nanotime - 0x18
    0x3e81f8,   // vm_kernel_addrperm
    0x39711c,   // kernel_pmap
    0xa1ca0,    // flush_dcache
    0xad600,    // invalidate_tlb
    0x2b14e8,   // task_for_pid
    0x16+2,     // pid_check_addr offset
    0x3e,       // posix_check_ret_addr offset
    0x224,      // mac_proc_check_ret_addr offset
    0x3e98b4,   // allproc
    0x8,        // proc_t::p_pid
    0x8c,       // proc_t::p_ucred
};

uint32_t koffsets_S5L895xX_802[] = { // 8.0.2 A6
    0x2ca380,   // OSSerializer::serialize
    0x2cc4a0,   // OSSymbol::getMetaClass
    0x1be5c,    // calend_gettime 0x1d300?
    0xc02f4,    // _bufattr_cpx
    0x3a1ce0,   // clock_ops
    0xad86c,    // _copyin
    0xc02f6,    // BX LR
    0xad5a8,    // write_gadget: str r1, [r0, #0xc] , bx lr // search _clock_get_calendar_nanotime - 0x18
    0x3e81f8,   // vm_kernel_addrperm
    0x39711c,   // kernel_pmap
    0xa1c60,    // flush_dcache
    0xad600,    // invalidate_tlb
    0x2b1488,   // task_for_pid
    0x16+2,     // pid_check_addr offset
    0x3e,       // posix_check_ret_addr offset
    0x224,      // mac_proc_check_ret_addr offset
    0x3e98b4,   // allproc
    0x8,        // proc_t::p_pid
    0x8c,       // proc_t::p_ucred
};

uint32_t koffsets_S5L894xX_841[] = { // 8.4.1 A5
    0x2D4A1C,   // OSSerializer::serialize
    0x2D6AFC,   // OSSymbol::getMetaClass
    0x1d0a0,    // calend_gettime
    0xC3718,    // _bufattr_cpx
    0x3ACCDC,   // clock_ops
    0xB1744,    // _copyin
    0xC371A,    // BX LR
    0xB1488,    // write_gadget: str r1, [r0, #0xc] , bx lr
    0x3F3128,   // vm_kernel_addrperm
    0x3A211C,   // kernel_pmap
    0xA6D10,    // flush_dcache
    0xB14E0,    // invalidate_tlb
    0x2BBDD0,   // task_for_pid
    0x16+2,     // pid_check_addr offset
    0x3e,       // posix_check_ret_addr offset
    0x222,      // mac_proc_check_ret_addr offset
    0x3F4810,   // allproc
    0x8,        // proc_t::p_pid
    0x8c,       // proc_t::p_ucred
};

uint32_t koffsets_S5L894xX_840[] = { // 8.4 A5
    0x2d49b8,   // OSSerializer::serialize
    0x2d6a98,   // OSSymbol::getMetaClass
    0x1d0a0,    // calend_gettime
    0xc36f8,    // _bufattr_cpx
    0x3accdc,   // clock_ops
    0xb1724,    // _copyin
    0xc36fa,    // BX LR
    0xb1468,    // write_gadget: str r1, [r0, #0xc] , bx lr
    0x3f3128,   // vm_kernel_addrperm
    0x3a211c,   // kernel_pmap
    0xa6bc4,    // flush_dcache
    0xb14c0,    // invalidate_tlb
    0x2bbd78,   // task_for_pid
    0x16+2,     // pid_check_addr offset
    0x3e,       // posix_check_ret_addr offset
    0x224,      // mac_proc_check_ret_addr offset
    0x3f4810,   // allproc
    0x8,        // proc_t::p_pid
    0x8c,       // proc_t::p_ucred
};

uint32_t koffsets_S5L894xX_830[] = { // 8.3 A5
    0x2d4938,   // OSSerializer::serialize
    0x2d6a18,   // OSSymbol::getMetaClass
    0x1d060,    // calend_gettime
    0xc36f8,    // _bufattr_cpx
    0x3accdc,   // clock_ops
    0xb1724,    // _copyin
    0xc36fa,    // BX LR
    0xb1468,    // write_gadget: str r1, [r0, #0xc] , bx lr
    0x3f3124,   // vm_kernel_addrperm
    0x3a211c,   // kernel_pmap
    0xa6940,    // flush_dcache
    0xb14c0,    // invalidate_tlb
    0x2bbce8,   // task_for_pid
    0x16+2,     // pid_check_addr offset
    0x3e,       // posix_check_ret_addr offset
    0x224,      // mac_proc_check_ret_addr offset
    0x3f480c,   // allproc
    0x8,        // proc_t::p_pid
    0x8c,       // proc_t::p_ucred
};

uint32_t koffsets_S5L894xX_820[] = { // 8.2 A5
    0x2c8a1c,   // OSSerializer::serialize
    0x2caafc,   // OSSymbol::getMetaClass
    0x1bf38,    // calend_gettime
    0xc08f8,    // _bufattr_cpx
    0x39ece0,   // clock_ops
    0xae744,    // _copyin
    0xc08fa,    // BX LR
    0xae488,    // write_gadget: str r1, [r0, #0xc] , bx lr
    0x3e50d0,   // vm_kernel_addrperm
    0x39411c,   // kernel_pmap
    0xa3b34,    // flush_dcache
    0xae4e0,    // invalidate_tlb
    0x2b0150,   // task_for_pid
    0x16+2,     // pid_check_addr offset
    0x3e,       // posix_check_ret_addr offset
    0x224,      // mac_proc_check_ret_addr offset
    0x3e6790,   // allproc
    0x8,        // proc_t::p_pid
    0x8c,       // proc_t::p_ucred
};

uint32_t koffsets_S5L894xX_813[] = { // 8.1.3 A5
    0x2c5bd0,   // OSSerializer::serialize
    0x2c7cb0,   // OSSymbol::getMetaClass
    0x1bb98,    // calend_gettime
    0xbd588,    // _bufattr_cpx
    0x39cce0,   // clock_ops
    0xab724,    // _copyin
    0xbd58a,    // BX LR
    0xab468,    // write_gadget: str r1, [r0, #0xc] , bx lr
    0x3e30d8,   // vm_kernel_addrperm
    0x39211c,   // kernel_pmap
    0xa06c8,    // flush_dcache
    0xab4c0,    // invalidate_tlb
    0x2ad404,   // task_for_pid
    0x16+2,     // pid_check_addr offset
    0x3e,       // posix_check_ret_addr offset
    0x224,      // mac_proc_check_ret_addr offset
    0x3e4788,   // allproc
    0x8,        // proc_t::p_pid
    0x8c,       // proc_t::p_ucred
};

uint32_t koffsets_S5L894xX_812[] = { // 8.1.2 A5
    0x2c5808,   // OSSerializer::serialize
    0x2c78e8,   // OSSymbol::getMetaClass
    0x1baa8,    // calend_gettime
    0xbd338,    // _bufattr_cpx
    0x39bce0,   // clock_ops
    0xab744,    // _copyin
    0xbd33a,    // BX LR
    0xab488,    // write_gadget: str r1, [r0, #0xc] , bx lr
    0x3e20d8,   // vm_kernel_addrperm
    0x39111c,   // kernel_pmap
    0xa0544,    // flush_dcache
    0xab4e0,    // invalidate_tlb
    0x2acf84,   // task_for_pid
    0x16+2,     // pid_check_addr offset
    0x3e,       // posix_check_ret_addr offset
    0x224,      // mac_proc_check_ret_addr offset
    0x3e3764,   // allproc
    0x8,        // proc_t::p_pid
    0x8c,       // proc_t::p_ucred
};

uint32_t koffsets_S5L894xX_810[] = { // 8.1 A5
    0x2c5388,   // OSSerializer::serialize
    0x2c7468,   // OSSymbol::getMetaClass
    0x1ba84,    // calend_gettime
    0xbd318,    // _bufattr_cpx
    0x39bce0,   // clock_ops
    0xab724,    // _copyin
    0xbd31a,    // BX LR
    0xab468,    // write_gadget: str r1, [r0, #0xc] , bx lr
    0x3e20c8,   // vm_kernel_addrperm
    0x39111c,   // kernel_pmap
    0xa04f8,    // flush_dcache
    0xab4c0,    // invalidate_tlb
    0x2acb04,   // task_for_pid
    0x16+2,     // pid_check_addr offset
    0x3e,       // posix_check_ret_addr offset
    0x224,      // mac_proc_check_ret_addr offset
    0x3e3754,   // allproc
    0x8,        // proc_t::p_pid
    0x8c,       // proc_t::p_ucred
};

uint32_t koffsets_S5L894xX_802[] = { // 8.0.2 A5
    0x2c5308,   // OSSerializer::serialize
    0x2c73e8,   // OSSymbol::getMetaClass
    0x1ba80,    // calend_gettime
    0xbd318,    // _bufattr_cpx
    0x39bce0,   // clock_ops
    0xab724,    // _copyin
    0xbd31a,    // BX LR
    0xab468,    // write_gadget: str r1, [r0, #0xc] , bx lr
    0x3e20c8,   // vm_kernel_addrperm
    0x39111c,   // kernel_pmap
    0xa04b8,    // flush_dcache
    0xab4c0,    // invalidate_tlb
    0x2aca94,   // task_for_pid
    0x16+2,     // pid_check_addr offset
    0x3e,       // posix_check_ret_addr offset
    0x224,      // mac_proc_check_ret_addr offset
    0x3e3754,   // allproc
    0x8,        // proc_t::p_pid
    0x8c,       // proc_t::p_ucred
};


uint32_t koffset(enum koffsets offset){
    if (offsets == NULL) {
        return 0;
    }
    return offsets[offset];
}

void offsets_init(void){
    struct utsname u = { 0 };
    uname(&u);

    printf("kern.version: %s\n", u.version);

    if (strstr(u.version, "S5L895")) {
        isA6 = 1;
        printf("A6(X): ");
        if (strstr(u.version, "3248.1.3~1")) {
            isIOS9 = 1;
            offsets = koffsets_S5L895xX_902;
            printf("We're using 9.0.2 offsets...\n");
        }
        if (strstr(u.version, "2784.40.6~1")) {
            offsets = koffsets_S5L895xX_841;
            printf("We're using 8.4.1 offsets...\n");
        }
        if (strstr(u.version, "2784.30.7~3") || strstr(u.version, "2784.30.7~1") || strstr(u.version, "2784.30.5~7")) {
            offsets = koffsets_S5L895xX_840;
            printf("We're using 8.4 offsets...\n");
        }
        if (strstr(u.version, "2784.20.34~2")) {
            offsets = koffsets_S5L895xX_830;
            printf("We're using 8.3 offsets...\n");
        }
        if (strstr(u.version, "2783.5.38~5")) {
            offsets = koffsets_S5L895xX_820;
            printf("We're using 8.2 offsets...\n");
        }
        if (strstr(u.version, "2783.3.26~3")) {
            offsets = koffsets_S5L895xX_813;
            printf("We're using 8.1.3 offsets...\n");
        }
        if (strstr(u.version, "2783.3.22~1")) {
            offsets = koffsets_S5L895xX_812;
            printf("We're using 8.1.2 offsets...\n");
        }
        if (strstr(u.version, "2783.3.13~4")) {
            offsets = koffsets_S5L895xX_810;
            printf("We're using 8.1 offsets...\n");
        }
        if (strstr(u.version, "2783.1.72~23") || strstr(u.version, "2783.1.72~8")) {
            offsets = koffsets_S5L895xX_802;
            printf("We're using 8.0.2 offsets...\n");
        }
    } else {
        printf("A5(X): ");
        if (strstr(u.version, "3248.1.3~1")) {
            isIOS9 = 1;
            offsets = koffsets_S5L894xX_902;
            printf("We're using 9.0.2 offsets...\n");
        }
        if (strstr(u.version, "2784.40.6~1")) {
            offsets = koffsets_S5L894xX_841;
            printf("We're using 8.4.1 offsets...\n");
        }
        if (strstr(u.version, "2784.30.7~3") || strstr(u.version, "2784.30.7~1") || strstr(u.version, "2784.30.5~7")) {
            offsets = koffsets_S5L894xX_840;
            printf("We're using 8.4 offsets...\n");
        }
        if (strstr(u.version, "2784.20.34~2")) {
            offsets = koffsets_S5L894xX_830;
            printf("We're using 8.3 offsets...\n");
        }
        if (strstr(u.version, "2783.5.38~5")) {
            offsets = koffsets_S5L894xX_820;
            printf("We're using 8.2 offsets...\n");
        }
        if (strstr(u.version, "2783.3.26~3")) {
            offsets = koffsets_S5L894xX_813;
            printf("We're using 8.1.3 offsets...\n");
        }
        if (strstr(u.version, "2783.3.22~1")) {
            offsets = koffsets_S5L894xX_812;
            printf("We're using 8.1.2 offsets...\n");
        }
        if (strstr(u.version, "2783.3.13~4")) {
            offsets = koffsets_S5L894xX_810;
            printf("We're using 8.1 offsets...\n");
        }
        if (strstr(u.version, "2783.1.72~23") || strstr(u.version, "2783.1.72~8")) {
            offsets = koffsets_S5L894xX_802;
            printf("We're using 8.0.2 offsets...\n");
        }
    }

}
