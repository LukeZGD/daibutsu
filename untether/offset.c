// for untether

#include <string.h>
#include <sys/utsname.h>

#include "sock_port_2_legacy/common.h"
#include "sock_port_2_legacy/offset.h"
#include "sock_port_2_legacy/offsets.h"

int* offsets = NULL;
bool is_ios9 = false;
char* kernv;

int koffset(enum kstruct_offset offset) {
    if (offsets == NULL) {
        printf("need to call offsets_init() prior to querying offsets\n");
        return 0;
    }
    return offsets[offset];
}

void offsets_init(void) {
    struct utsname u = { 0 };
    uname(&u);

    printf("kern.version: %s\n", u.version);
    kernv = u.version;

    if (strstr(kernv, "3248.6") || strstr(kernv, "3248.5") || strstr(kernv, "3248.4")) {
        printf("[i] offsets selected for iOS 9.3.x\n");
        offsets = kstruct_offsets_9_3;
        is_ios9 = true;
    } else if (strstr(kernv, "3248.3") || strstr(kernv, "3248.2") || strstr(kernv, "3248.10")) {
        printf("[i] offsets selected for iOS 9.1-9.2.1\n");
        offsets = kstruct_offsets_9_2;
        is_ios9 = true;
    } else if (strstr(kernv, "3248.1.") || strstr(kernv, "3247")) {
        is_ios9 = true;
        printf("[i] offsets selected for iOS 9.0.x\n");
        offsets = kstruct_offsets_9_0;
    } else if (strstr(kernv, "2784") || strstr(kernv, "2783")) {
        printf("[i] offsets selected for iOS 8.x\n");
        offsets = kstruct_offsets_8;
    } else { // 2423
        printf("[i] offsets selected for iOS 7.x\n");
        offsets = kstruct_offsets_7;
    }
}
