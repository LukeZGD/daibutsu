// offsets.h from wtfis

#include <stdbool.h>

enum kstruct_offset {
    /* struct task */
    TASK_VM_MAP,
    TASK_NEXT,
    TASK_PREV,
    TASK_ITK_SELF,
    TASK_ITK_SPACE,
    TASK_BSDINFO,

    /* struct ipc_port */
    IPC_PORT_IP_RECEIVER,
    IPC_PORT_IP_KOBJECT,
    IPC_PORT_IP_SRIGHTS,

    /* struct proc */
    BSDINFO_PID,
    PROC_P_FD,
    BSDINFO_KAUTH_CRED,

    /* struct filedesc */
    FILEDESC_FD_OFILES,

    /* struct fileproc */
    FILEPROC_F_FGLOB,

    /* struct fileglob */
    FILEGLOB_FG_DATA,

    /* struct pipe */
    PIPE_BUFFER,

    /* struct ipc_space */
    IPC_SPACE_IS_TABLE,
    IPC_ENTRY_SIZE,
};

int koffset(enum kstruct_offset offset);
void offsets_init(void);

extern bool is_ios9;
