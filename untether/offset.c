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

    if (strstr(kernv, "3248") || strstr(kernv, "3247") || strstr(kernv, "3216")) {
        is_ios9 = true;
        printf("[i] offsets selected for iOS 9.0.x\n");
        offsets = kstruct_offsets_9_0;
    } else {
        printf("[i] offsets selected for iOS 8.x\n");
        offsets = kstruct_offsets_8;
    }
}
