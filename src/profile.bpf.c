#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf_helpers.h>

//#define DEBUG

#define bpf_debug_force(fmt, ...)                                             \
                ({                                                      \
                        char ____fmt[] = "(profile) " fmt;			\
                        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                                     ##__VA_ARGS__);                    \
                })
#ifdef  DEBUG
#define bpf_debug(fmt, ...) bpf_debug_force(fmt, ##__VA_ARGS__)
#else
#define bpf_debug(fmt, ...) { } while (0)\
;
#endif

#define SIGSTKFLT 16

struct pt_regs {
	long unsigned int r15;
	long unsigned int r14;
	long unsigned int r13;
	long unsigned int r12;
	long unsigned int bp;
	long unsigned int bx;
	long unsigned int r11;
	long unsigned int r10;
	long unsigned int r9;
	long unsigned int r8;
	long unsigned int ax;
	long unsigned int cx;
	long unsigned int dx;
	long unsigned int si;
	long unsigned int di;
	long unsigned int orig_ax;
	long unsigned int ip;
	long unsigned int cs;
	long unsigned int flags;
	long unsigned int sp;
	long unsigned int ss;
};

typedef struct pt_regs bpf_user_pt_regs_t;

struct task_struct {
    int pid;
	int tgid;
	unsigned int			policy;
} __attribute__((preserve_access_index));

struct bpf_perf_event_data {
	bpf_user_pt_regs_t regs;
	__u64 sample_period;
	__u64 addr;
};

// key: process id 
BPF_MAP(java_processes, HASH, __u32, __u32, 1024);

#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define __array(name, val) typeof(val) *name[]

#define N_PIDS 262144
#define STACK_TABLE_SIZE N_PIDS
#define STACK_ELEMENTS 128
#define MAX_STACK_DEPTH 127 //PERF_MAX_STACK_DEPTH
struct stacktrace {
  __u32 tgid; 
  __u32 pid; 
  __u64 counter; 
  __u16 event_type;
  __u16 sched_policy;
  __u32 len; 
  __u64 ip[MAX_STACK_DEPTH];
};

struct stacks {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, STACK_TABLE_SIZE);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(struct stacktrace));
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} stacks SEC(".maps");

// pid => dev+ino+salt
struct proc_info {
    __u64 dev;
    __u64 ino;
    __u32 salt;
    __u32 version;
    __u64 __reserved;
};
struct processes {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(struct proc_info));
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} processes SEC(".maps");

struct times {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(long));
	__uint(max_entries, 1);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} times SEC(".maps");

static __attribute__((always_inline))
int get_user_stack(struct bpf_perf_event_data *ctx, struct stacktrace* stack, __u32 len, __u32 pid) {
    if (len >= MAX_STACK_DEPTH) {
        return len;
    }
    __u32 bytelen = sizeof(__u64)*(MAX_STACK_DEPTH-len);
    __s64 res = bpf_get_stack(ctx, &(stack->ip[len]), bytelen, BPF_F_USER_STACK);
    if (res >= 0 && !(res % 8)) {
        bpf_debug("user stack for pid %d len %d", pid, res);
        bpf_debug("user stack first item: %x", stack->ip[len]);
        return len + res / 8;
    } else {
        bpf_debug_force("stack getting error for pid %d: %d", pid, res);
    }
    return len;
}
static __attribute__((always_inline))
int get_user_stack2(struct bpf_perf_event_data *ctx, struct stacktrace* stack, __u32 len, __u32 pid) {
// make verifier happy by inlining all possible values of len
#define GET_STACK(__LEN) case __LEN: return get_user_stack(ctx,stack,__LEN,pid); 
#define GET_STACK2(L) GET_STACK(L ## 0)\
    GET_STACK(L ## 1)\
    GET_STACK(L ## 2)\
    GET_STACK(L ## 3)\
    GET_STACK(L ## 4)\
    GET_STACK(L ## 5)\
    GET_STACK(L ## 6)\
    GET_STACK(L ## 7)\
    GET_STACK(L ## 8)\
    GET_STACK(L ## 9)\
    GET_STACK(L ## a)\
    GET_STACK(L ## b)\
    GET_STACK(L ## c)\
    GET_STACK(L ## d)\
    GET_STACK(L ## e)\
    GET_STACK(L ## f) 
    switch(len) {
        GET_STACK2(0x0) 
        GET_STACK2(0x1) 
        GET_STACK2(0x2) 
        GET_STACK2(0x3) 
        GET_STACK2(0x4) 
        GET_STACK2(0x5) 
        GET_STACK2(0x6) 
        GET_STACK2(0x7) 
        GET_STACK2(0x8) 
    }
    bpf_debug_force("got unexpected len value for pid %d: %d", pid, len);
    return len;
}

int do_perf_event(struct bpf_perf_event_data *ctx) {
    __u32 sched_policy;
    __u32 tgid;
    __u32 pid;
    __s64 res;

    __u64 i0 = 0;
    __u64* t = bpf_map_lookup_elem(&times, &i0);
    if (t) {
    	__u64 now = bpf_ktime_get_ns();
        bpf_debug_force("time: %dms", (now-*t)/1000000);
        *t = now;        
    }
    struct task_struct* task = (struct task_struct*)bpf_get_current_task();
    res = bpf_probe_read(&tgid, sizeof(tgid), __builtin_preserve_access_index(&task->tgid));
    if (res) {
        bpf_debug_force("bpf_probe_read task->tgid failed: %d", res);
        return 0;
    }
    
    if (!tgid) return 0;

    struct proc_info* ni = bpf_map_lookup_elem(&processes, &tgid);
    if (!ni) {
        return 0;
    }

    res = bpf_probe_read(&sched_policy, sizeof(sched_policy), __builtin_preserve_access_index(&task->policy));
    if (res) {
        bpf_debug_force("bpf_probe_read task->policy failed: %d", res);
        return 0;
    }

    res = bpf_probe_read(&pid, sizeof(pid), __builtin_preserve_access_index(&task->pid));
    if (res) {
        bpf_debug_force("bpf_probe_read task->pid failed: %d", res);
        return 0;
    }
    
    bpf_debug("tgid %d dev: %lld ino: %lld", tgid, ni->dev, ni->ino);
    bpf_debug("tgid %d salt: %ld", tgid, ni->salt);
    
    struct bpf_pidns_info nsdata = {};
    res = bpf_get_ns_current_pid_tgid(ni->dev, ni->ino, &nsdata, sizeof(struct bpf_pidns_info));
    if (res) {
        bpf_debug_force("bpf_get_ns_current_pid_tgid failed: %d", res);
        return 0;
    }

    __u32 index = (ni->salt + nsdata.pid) & (STACK_TABLE_SIZE-1);
    bpf_debug("ns pid:%d tgid: %d index:%lld", nsdata.pid, nsdata.tgid, index);
    
    struct stacktrace* stack = bpf_map_lookup_elem(&stacks, &index);
    if (!stack) {
        bpf_debug_force("unexpectedly failed to get stack map data by index: %d", index);
        return 0;
    }
    
    stack->tgid = nsdata.tgid;
    stack->pid = nsdata.pid;
    stack->counter = 1;
    stack->event_type = 0;
    stack->sched_policy=sched_policy;
    
    __u8 len = 0;
    res = bpf_get_stack(ctx, &(stack->ip[len]), sizeof(__u64) * (MAX_STACK_DEPTH-len), 0);
    if (res >= 0 && !(res % 8)) {
        len += res / 8;
        bpf_debug("kernel stack for pid %d len %d", pid, res / 8);
        if (res > 0) {
            bpf_debug("kernel stack first items: %x %x %x", stack->ip[0], stack->ip[1], stack->ip[2]);
            if (stack->ip[0] != ctx->regs.ip) {
                bpf_debug_force("kernel stack reg.ip and top frame not matches for pid %d ip: %x top frame: %x", pid, ctx->regs.ip, stack->ip[0]);
            }
        }
    } else {
        bpf_debug_force("stack getting error for pid %d: %d", pid, len);
    }
    
    if (len < MAX_STACK_DEPTH) {
        len = get_user_stack2(ctx, stack, len, pid);
    }
    
    stack->len = len;

    bpf_debug("SIGSTKFLT tgid:%d pid:%d sched:%d", tgid, pid, sched_policy);
    bpf_send_signal_thread(SIGSTKFLT);
    
    return 0;
}
char _license[] SEC("license") = "GPL";
