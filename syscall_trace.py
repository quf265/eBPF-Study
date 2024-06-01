from time import sleep, strftime
from bcc import BPF
from bcc.syscall import syscall_name, syscalls


text = """
#include <linux/cred.h>
struct process_syscall{
    u32 count;
    u32 first;
    char task_name[TASK_COMM_LEN];   
};
struct key_process_syscall{
    u32 pid;
    u32 syscall_number;
};
BPF_HASH(data_process_syscall, struct key_process_syscall, struct process_syscall);
TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 syscall_number = args->id;

    struct key_process_syscall val_key_process_syscall = {};
    val_key_process_syscall.pid = pid;
    val_key_process_syscall.syscall_number = syscall_number;

    struct process_syscall * val_process_syscall, zero_val_process_syscall = {};
    val_process_syscall = data_process_syscall.lookup_or_try_init(&val_key_process_syscall, &zero_val_process_syscall);
    if(val_process_syscall)
    {
        lock_xadd(&(val_process_syscall->count), 1);
        if(val_process_syscall->first == 0)
        {
            char name[TASK_COMM_LEN];
            bpf_get_current_comm(&name, sizeof(name));
            bpf_probe_read_str((char*)val_process_syscall->task_name,sizeof(name),name);
            val_process_syscall->first = 1;
        }
    }
    return 0;
}
"""
bpf = BPF(text=text)
def print_syscall_info():
    print_data_process_syscall = bpf['data_process_syscall']
    collect_print_data_process_syscall = print_data_process_syscall.items_lookup_and_delete_batch()
    collect_print_data_process_syscall = sorted(collect_print_data_process_syscall, key=lambda x: x[0].pid)
    print('---------------------------------------------')
    print('pid | task_name | syscall_name | syscall_number | syscall_count')
    for k, v in collect_print_data_process_syscall:
        print(k.pid,(v.task_name).decode('utf-8'),syscall_name(k.syscall_number).decode('utf-8'),k.syscall_number,v.count)
    print('---------------------------------------------')
exiting = 0
while True:
    try:
        sleep(1)
    except KeyboardInterrupt:
        exiting = 1
    print_syscall_info()
    if exiting:
        exit()


        
