int kstruct_offsets_9_0[] = {
    0x18,  // TASK_VM_MAP
    0x1c,  // TASK_NEXT
    0x20,  // TASK_PREV
    0xa4,  // TASK_ITK_SELF
    0x1b8, // TASK_ITK_SPACE
    0x200, // TASK_BSDINFO

    0x4c,  // IPC_PORT_IP_RECEIVER
    0x50,  // IPC_PORT_IP_KOBJECT
    0x70,  // IPC_PORT_IP_SRIGHTS

    0x8,   // BSDINFO_PID
    0x90,  // PROC_P_FD
    0x8c,  // BSDINFO_KAUTH_CRED

    0x0,   // FILEDESC_FD_OFILES

    0x8,   // FILEPROC_F_FGLOB

    0x28,  // FILEGLOB_FG_DATA

    0x10,  // PIPE_BUFFER

    0x18,  // IPC_SPACE_IS_TABLE
    0x10,  // IPC_ENTRY_SIZE
};

// 32-bit 8.x offsets
int kstruct_offsets_8[] = {
    0x18,  // TASK_VM_MAP
    0x1c,  // TASK_NEXT
    0x20,  // TASK_PREV
    0xa4,  // TASK_ITK_SELF
    0x1a8, // TASK_ITK_SPACE
    0x1f0, // TASK_BSDINFO

    0x40,  // IPC_PORT_IP_RECEIVER
    0x44,  // IPC_PORT_IP_KOBJECT
    0x5c,  // IPC_PORT_IP_SRIGHTS

    0x8,   // BSDINFO_PID
    0x90,  // PROC_P_FD
    0x8c,  // BSDINFO_KAUTH_CRED

    0x0,   // FILEDESC_FD_OFILES

    0x8,   // FILEPROC_F_FGLOB

    0x28,  // FILEGLOB_FG_DATA

    0x10,  // PIPE_BUFFER

    0x18,  // IPC_SPACE_IS_TABLE
    0x10,  // IPC_ENTRY_SIZE
};
