#include <stdio.h>
#include <stdlib.h>

#include "sock_port_2_legacy/sockpuppet.h"

int main(void){
    mach_port_t tfp0;
    uint32_t kernel_base;
    tfp0 = exploit(&kernel_base);

    return 0;
}
