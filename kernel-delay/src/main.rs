use aya::maps::{HashMap as AyaHashMap, ring_buf::RingBuf};
use aya::programs::TracePoint;
#[rustfmt::skip]
use log::{debug, warn, info};
use clap::Parser;
use std::collections::HashMap as StdHashMap;
use std::convert::TryFrom;
use std::thread;
use std::time::Duration;
use tokio::signal;

// Import the Event structure from the common crate
use kernel_delay_common::{Event, EventType, SyscallStat, ThreadReadyStat, ThreadRunStat};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// PID of the process to monitor
    #[clap(short, long)]
    pid: u32,
    #[clap(short, long, default_value = "10")] // default
    /// Duration for which to monitor the process
    duration: u64,
}

fn get_thread_name(thread_name_bytes: &[u8; 16], tid: u32, pid: u32) -> String {
    // First, try to get the real thread name from the system
    let comm_path = format!("/proc/{}/task/{}/comm", pid, tid);
    if let Ok(name) = std::fs::read_to_string(&comm_path) {
        let trimmed = name.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    
    // Fallback to the original method
    // Convert bytes to string, trimming null bytes
    let name_str = String::from_utf8_lossy(thread_name_bytes);
    let trimmed = name_str.trim_end_matches('\0');
    
    // If the name is empty or generic, use a default
    if trimmed.is_empty() || trimmed == "thread" {
        "unnamed-thread".to_string()
    } else {
        trimmed.to_string()
    }
}

fn print_thread_statistics(thread_events: &StdHashMap<u32, Vec<Event>>, target_pid: u32) {
    if thread_events.is_empty() {
        println!("No events captured during monitoring period.");
        println!("This could be because:");
        println!("  1. The target process was idle during monitoring");
        println!("  2. The target process did not perform traced syscalls");
        println!("  3. The monitoring duration was too short");
        println!("  4. The target process has exited");
        return;
    }
    
    println!("TID        THREAD           <RESOURCE SPECIFIC>");
    println!("{:-<10} {:-<16} {:-<76}", "", "", "");

    // Sort threads by TID for consistent output
    let mut sorted_threads: Vec<_> = thread_events.keys().collect();
    sorted_threads.sort();

    for &tid in sorted_threads {
        if let Some(events) = thread_events.get(&tid) {
            if let Some(first_event) = events.first() {
                // Get thread name from the event or system
                let thread_name = get_thread_name(&first_event.thread_name, tid, target_pid);
                
                // Print thread header
                println!("{:<10} {:<16} [SYSCALL STATISTICS]", tid, thread_name);

                // Collect and aggregate statistics
                let mut syscall_stats: StdHashMap<u32, SyscallStat> = StdHashMap::new();
                let mut thread_run_stats: Vec<ThreadRunStat> = Vec::new();
                let mut thread_ready_stats: Vec<ThreadReadyStat> = Vec::new();
                let mut total_excluding_poll = 0u64;
                let mut softirq_stats: StdHashMap<u32, kernel_delay_common::IrqStat> = StdHashMap::new();

                for event in events {
                    match event.event_type {
                        x if x == EventType::SyscallStats as u32 => {
                            // Aggregate syscall statistics by syscall number
                            let syscall_number = event.syscall_stat.number;
                            syscall_stats.entry(syscall_number)
                                .and_modify(|stat| {
                                    stat.count += event.syscall_stat.count;
                                    stat.total_ns += event.syscall_stat.total_ns;
                                    if event.syscall_stat.max_ns > stat.max_ns {
                                        stat.max_ns = event.syscall_stat.max_ns;
                                    }
                                })
                                .or_insert(event.syscall_stat);
                            total_excluding_poll = event.total_excluding_poll;
                        }
                        x if x == EventType::ThreadRunStats as u32 => {
                            thread_run_stats.push(event.thread_run_stat);
                        }
                        x if x == EventType::ThreadReadyStats as u32 => {
                            thread_ready_stats.push(event.thread_ready_stat);
                        }
                        x if x == EventType::SoftIrqStats as u32 => {
                            // Aggregate softirq statistics by vector
                            let vector = event.irq_stat.vector;
                            softirq_stats.entry(vector)
                                .and_modify(|stat| {
                                    stat.count += event.irq_stat.count;
                                    stat.total_ns += event.irq_stat.total_ns;
                                    if event.irq_stat.max_ns > stat.max_ns {
                                        stat.max_ns = event.irq_stat.max_ns;
                                    }
                                })
                                .or_insert(event.irq_stat);
                        }
                        _ => {}
                    }
                }

                // Print syscall statistics header
                if !syscall_stats.is_empty() {
                    println!(
                        "           {:<20} {:<11} {:<13} {:<17} {:<13}",
                        "NAME", "NUMBER", "COUNT", "TOTAL ns", "MAX ns"
                    );
                    
                    // Sort syscall stats by total time (descending) for better readability
                    let mut sorted_syscall_stats: Vec<_> = syscall_stats.values().collect();
                    sorted_syscall_stats.sort_by(|a, b| b.total_ns.cmp(&a.total_ns));
                    
                    for stat in sorted_syscall_stats {
                        let name = get_syscall_name(stat.number);
                        println!(
                            "           {:<20} {:<11} {:<13} {:<17} {:<13}",
                            name,
                            stat.number,
                            stat.count,
                            format_number(stat.total_ns),
                            format_number(stat.max_ns)
                        );
                    }
                    println!(
                        "           TOTAL( - poll): {:<37} {:<13}",
                        "",
                        format_number(total_excluding_poll)
                    );
                    println!("");
                }

                // Print thread run statistics
                if !thread_run_stats.is_empty() {
                    println!("           [THREAD RUN STATISTICS]");
                    println!(
                        "           {:<19} {:<17} {:<17} {:<13}",
                        "SCHED_CNT", "TOTAL ns", "MIN ns", "MAX ns"
                    );
                    
                    // Aggregate thread run statistics
                    if let Some(first_stat) = thread_run_stats.first() {
                        let mut aggregated_stat = ThreadRunStat {
                            sched_cnt: 0,
                            total_ns: 0,
                            min_ns: first_stat.min_ns,
                            max_ns: 0,
                        };
                        
                        for stat in &thread_run_stats {
                            aggregated_stat.sched_cnt += stat.sched_cnt;
                            aggregated_stat.total_ns += stat.total_ns;
                            if stat.min_ns < aggregated_stat.min_ns {
                                aggregated_stat.min_ns = stat.min_ns;
                            }
                            if stat.max_ns > aggregated_stat.max_ns {
                                aggregated_stat.max_ns = stat.max_ns;
                            }
                        }
                        
                        println!(
                            "           {:<19} {:<17} {:<17} {:<13}",
                            aggregated_stat.sched_cnt,
                            format_number(aggregated_stat.total_ns),
                            format_number(aggregated_stat.min_ns),
                            format_number(aggregated_stat.max_ns)
                        );
                    }
                    println!("");
                }

                // Print thread ready statistics
                if !thread_ready_stats.is_empty() {
                    println!("           [THREAD READY STATISTICS]");
                    println!(
                        "           {:<19} {:<17} {:<13}",
                        "SCHED_CNT", "TOTAL ns", "MAX ns"
                    );
                    
                    // Aggregate thread ready statistics
                    let mut aggregated_ready_stat = ThreadReadyStat {
                        sched_cnt: 0,
                        total_ns: 0,
                        max_ns: 0,
                    };
                    
                    for stat in &thread_ready_stats {
                        aggregated_ready_stat.sched_cnt += stat.sched_cnt;
                        aggregated_ready_stat.total_ns += stat.total_ns;
                        if stat.max_ns > aggregated_ready_stat.max_ns {
                            aggregated_ready_stat.max_ns = stat.max_ns;
                        }
                    }
                    
                    println!(
                        "           {:<19} {:<17} {:<13}",
                        aggregated_ready_stat.sched_cnt,
                        format_number(aggregated_ready_stat.total_ns),
                        format_number(aggregated_ready_stat.max_ns)
                    );
                    println!("");
                }

                // Print IRQ statistics (soft interrupts only, no network card info)
                if !softirq_stats.is_empty() {
                    println!("           [SOFT IRQ STATISTICS]");
                    println!(
                        "           {:<20} {:<11} {:<13} {:<17} {:<13}",
                        "NAME", "VECT_NR", "COUNT", "TOTAL ns", "MAX ns"
                    );
                    
                    // Sort softirq stats by total time (descending) for better readability
                    let mut sorted_softirq_stats: Vec<_> = softirq_stats.values().collect();
                    sorted_softirq_stats.sort_by(|a, b| b.total_ns.cmp(&a.total_ns));
                    
                    for stat in sorted_softirq_stats {
                        let name = get_softirq_name(stat.vector);
                        println!(
                            "           {:<20} {:<11} {:<13} {:<17} {:<13}",
                            name,
                            stat.vector,
                            stat.count,
                            format_number(stat.total_ns),
                            format_number(stat.max_ns)
                        );
                    }
                    
                    // Calculate total
                    let total_count: u32 = softirq_stats.values().map(|s| s.count).sum();
                    let total_ns: u64 = softirq_stats.values().map(|s| s.total_ns).sum();
                    println!(
                        "           TOTAL: {:<32} {:<13} {:<17} {:<13}",
                        "",
                        "",
                        total_count,
                        format_number(total_ns)
                    );
                }
            }
        }
    }
}

fn get_syscall_name(syscall_number: u32) -> String {
    // Map syscall numbers to names
    match syscall_number {
        0 => "read".to_string(),
        1 => "write".to_string(),
        2 => "open".to_string(),
        3 => "close".to_string(),
        4 => "stat".to_string(),
        5 => "fstat".to_string(),
        6 => "lstat".to_string(),
        7 => "poll".to_string(),
        8 => "lseek".to_string(),
        9 => "mmap".to_string(),
        10 => "mprotect".to_string(),
        11 => "munmap".to_string(),
        12 => "brk".to_string(),
        13 => "rt_sigaction".to_string(),
        14 => "rt_sigprocmask".to_string(),
        15 => "rt_sigreturn".to_string(),
        16 => "ioctl".to_string(),
        17 => "pread64".to_string(),
        18 => "pwrite64".to_string(),
        19 => "readv".to_string(),
        20 => "writev".to_string(),
        21 => "access".to_string(),
        22 => "pipe".to_string(),
        23 => "select".to_string(),
        24 => "sched_yield".to_string(),
        25 => "mremap".to_string(),
        26 => "msync".to_string(),
        27 => "mincore".to_string(),
        28 => "madvise".to_string(),
        29 => "shmget".to_string(),
        30 => "shmat".to_string(),
        31 => "shmctl".to_string(),
        32 => "dup".to_string(),
        33 => "dup2".to_string(),
        34 => "pause".to_string(),
        35 => "nanosleep".to_string(),
        36 => "getitimer".to_string(),
        37 => "alarm".to_string(),
        38 => "setitimer".to_string(),
        39 => "getpid".to_string(),
        40 => "sendfile".to_string(),
        41 => "socket".to_string(),
        42 => "connect".to_string(),
        43 => "accept".to_string(),
        44 => "sendto".to_string(),
        45 => "recvfrom".to_string(),
        46 => "sendmsg".to_string(),
        47 => "recvmsg".to_string(),
        48 => "shutdown".to_string(),
        49 => "bind".to_string(),
        50 => "listen".to_string(),
        51 => "getsockname".to_string(),
        52 => "getpeername".to_string(),
        53 => "socketpair".to_string(),
        54 => "setsockopt".to_string(),
        55 => "getsockopt".to_string(),
        56 => "clone".to_string(),
        57 => "fork".to_string(),
        58 => "vfork".to_string(),
        59 => "execve".to_string(),
        60 => "exit".to_string(),
        61 => "wait4".to_string(),
        62 => "kill".to_string(),
        63 => "uname".to_string(),
        64 => "semget".to_string(),
        65 => "semop".to_string(),
        66 => "semctl".to_string(),
        67 => "shmdt".to_string(),
        68 => "msgget".to_string(),
        69 => "msgsnd".to_string(),
        70 => "msgrcv".to_string(),
        71 => "msgctl".to_string(),
        72 => "fcntl".to_string(),
        73 => "flock".to_string(),
        74 => "fsync".to_string(),
        75 => "fdatasync".to_string(),
        76 => "truncate".to_string(),
        77 => "ftruncate".to_string(),
        78 => "getdents".to_string(),
        79 => "getcwd".to_string(),
        80 => "chdir".to_string(),
        81 => "fchdir".to_string(),
        82 => "rename".to_string(),
        83 => "mkdir".to_string(),
        84 => "rmdir".to_string(),
        85 => "creat".to_string(),
        86 => "link".to_string(),
        87 => "unlink".to_string(),
        88 => "symlink".to_string(),
        89 => "readlink".to_string(),
        90 => "chmod".to_string(),
        91 => "fchmod".to_string(),
        92 => "chown".to_string(),
        93 => "fchown".to_string(),
        94 => "lchown".to_string(),
        95 => "umask".to_string(),
        96 => "gettimeofday".to_string(),
        97 => "getrlimit".to_string(),
        98 => "getrusage".to_string(),
        99 => "sysinfo".to_string(),
        100 => "times".to_string(),
        101 => "ptrace".to_string(),
        102 => "getuid".to_string(),
        103 => "syslog".to_string(),
        104 => "getgid".to_string(),
        105 => "setuid".to_string(),
        106 => "setgid".to_string(),
        107 => "geteuid".to_string(),
        108 => "getegid".to_string(),
        109 => "setpgid".to_string(),
        110 => "getppid".to_string(),
        111 => "getpgrp".to_string(),
        112 => "setsid".to_string(),
        113 => "setreuid".to_string(),
        114 => "setregid".to_string(),
        115 => "getgroups".to_string(),
        116 => "setgroups".to_string(),
        117 => "setresuid".to_string(),
        118 => "getresuid".to_string(),
        119 => "setresgid".to_string(),
        120 => "getresgid".to_string(),
        121 => "getpgid".to_string(),
        122 => "setfsuid".to_string(),
        123 => "setfsgid".to_string(),
        124 => "getsid".to_string(),
        125 => "capget".to_string(),
        126 => "capset".to_string(),
        127 => "rt_sigpending".to_string(),
        128 => "rt_sigtimedwait".to_string(),
        129 => "rt_sigqueueinfo".to_string(),
        130 => "rt_sigsuspend".to_string(),
        131 => "sigaltstack".to_string(),
        132 => "utime".to_string(),
        133 => "mknod".to_string(),
        134 => "uselib".to_string(),
        135 => "personality".to_string(),
        136 => "ustat".to_string(),
        137 => "statfs".to_string(),
        138 => "fstatfs".to_string(),
        139 => "sysfs".to_string(),
        140 => "getpriority".to_string(),
        141 => "setpriority".to_string(),
        142 => "sched_setparam".to_string(),
        143 => "sched_getparam".to_string(),
        144 => "sched_setscheduler".to_string(),
        145 => "sched_getscheduler".to_string(),
        146 => "sched_get_priority_max".to_string(),
        147 => "sched_get_priority_min".to_string(),
        148 => "sched_rr_get_interval".to_string(),
        149 => "mlock".to_string(),
        150 => "munlock".to_string(),
        151 => "mlockall".to_string(),
        152 => "munlockall".to_string(),
        153 => "vhangup".to_string(),
        154 => "modify_ldt".to_string(),
        155 => "pivot_root".to_string(),
        156 => "_sysctl".to_string(),
        157 => "prctl".to_string(),
        158 => "arch_prctl".to_string(),
        159 => "adjtimex".to_string(),
        160 => "setrlimit".to_string(),
        161 => "chroot".to_string(),
        162 => "sync".to_string(),
        163 => "acct".to_string(),
        164 => "settimeofday".to_string(),
        165 => "mount".to_string(),
        166 => "umount2".to_string(),
        167 => "swapon".to_string(),
        168 => "swapoff".to_string(),
        169 => "reboot".to_string(),
        170 => "sethostname".to_string(),
        171 => "setdomainname".to_string(),
        172 => "iopl".to_string(),
        173 => "ioperm".to_string(),
        174 => "create_module".to_string(),
        175 => "init_module".to_string(),
        176 => "delete_module".to_string(),
        177 => "get_kernel_syms".to_string(),
        178 => "query_module".to_string(),
        179 => "quotactl".to_string(),
        180 => "nfsservctl".to_string(),
        181 => "getpmsg".to_string(),
        182 => "putpmsg".to_string(),
        183 => "afs_syscall".to_string(),
        184 => "tuxcall".to_string(),
        185 => "security".to_string(),
        186 => "gettid".to_string(),
        187 => "readahead".to_string(),
        188 => "setxattr".to_string(),
        189 => "lsetxattr".to_string(),
        190 => "fsetxattr".to_string(),
        191 => "getxattr".to_string(),
        192 => "lgetxattr".to_string(),
        193 => "fgetxattr".to_string(),
        194 => "listxattr".to_string(),
        195 => "llistxattr".to_string(),
        196 => "flistxattr".to_string(),
        197 => "removexattr".to_string(),
        198 => "lremovexattr".to_string(),
        199 => "fremovexattr".to_string(),
        200 => "tkill".to_string(),
        201 => "time".to_string(),
        202 => "futex".to_string(),
        203 => "sched_setaffinity".to_string(),
        204 => "sched_getaffinity".to_string(),
        205 => "set_thread_area".to_string(),
        206 => "io_setup".to_string(),
        207 => "io_destroy".to_string(),
        208 => "io_getevents".to_string(),
        209 => "io_submit".to_string(),
        210 => "io_cancel".to_string(),
        211 => "get_thread_area".to_string(),
        212 => "lookup_dcookie".to_string(),
        213 => "epoll_create".to_string(),
        214 => "epoll_ctl_old".to_string(),
        215 => "epoll_wait_old".to_string(),
        216 => "remap_file_pages".to_string(),
        217 => "getdents64".to_string(),
        218 => "set_tid_address".to_string(),
        219 => "restart_syscall".to_string(),
        220 => "semtimedop".to_string(),
        221 => "fadvise64".to_string(),
        222 => "timer_create".to_string(),
        223 => "timer_settime".to_string(),
        224 => "timer_gettime".to_string(),
        225 => "timer_getoverrun".to_string(),
        226 => "timer_delete".to_string(),
        227 => "clock_settime".to_string(),
        228 => "clock_gettime".to_string(),
        229 => "clock_getres".to_string(),
        230 => "clock_nanosleep".to_string(),
        231 => "exit_group".to_string(),
        232 => "epoll_wait".to_string(),
        233 => "epoll_ctl".to_string(),
        234 => "tgkill".to_string(),
        235 => "utimes".to_string(),
        236 => "vserver".to_string(),
        237 => "mbind".to_string(),
        238 => "set_mempolicy".to_string(),
        239 => "get_mempolicy".to_string(),
        240 => "mq_open".to_string(),
        241 => "mq_unlink".to_string(),
        242 => "mq_timedsend".to_string(),
        243 => "mq_timedreceive".to_string(),
        244 => "mq_notify".to_string(),
        245 => "mq_getsetattr".to_string(),
        246 => "kexec_load".to_string(),
        247 => "waitid".to_string(),
        248 => "add_key".to_string(),
        249 => "request_key".to_string(),
        250 => "keyctl".to_string(),
        251 => "ioprio_set".to_string(),
        252 => "ioprio_get".to_string(),
        253 => "inotify_init".to_string(),
        254 => "inotify_add_watch".to_string(),
        255 => "inotify_rm_watch".to_string(),
        256 => "migrate_pages".to_string(),
        257 => "openat".to_string(),
        258 => "mkdirat".to_string(),
        259 => "mknodat".to_string(),
        260 => "fchownat".to_string(),
        261 => "futimesat".to_string(),
        262 => "newfstatat".to_string(),
        263 => "unlinkat".to_string(),
        264 => "renameat".to_string(),
        265 => "linkat".to_string(),
        266 => "symlinkat".to_string(),
        267 => "readlinkat".to_string(),
        268 => "fchmodat".to_string(),
        269 => "faccessat".to_string(),
        270 => "pselect6".to_string(),
        271 => "ppoll".to_string(),
        272 => "unshare".to_string(),
        273 => "set_robust_list".to_string(),
        274 => "get_robust_list".to_string(),
        275 => "splice".to_string(),
        276 => "tee".to_string(),
        277 => "sync_file_range".to_string(),
        278 => "vmsplice".to_string(),
        279 => "move_pages".to_string(),
        280 => "utimensat".to_string(),
        281 => "epoll_pwait".to_string(),
        282 => "signalfd".to_string(),
        283 => "timerfd_create".to_string(),
        284 => "eventfd".to_string(),
        285 => "fallocate".to_string(),
        286 => "timerfd_settime".to_string(),
        287 => "timerfd_gettime".to_string(),
        288 => "accept4".to_string(),
        289 => "signalfd4".to_string(),
        290 => "eventfd2".to_string(),
        291 => "epoll_create1".to_string(),
        292 => "dup3".to_string(),
        293 => "pipe2".to_string(),
        294 => "inotify_init1".to_string(),
        295 => "preadv".to_string(),
        296 => "pwritev".to_string(),
        297 => "rt_tgsigqueueinfo".to_string(),
        298 => "perf_event_open".to_string(),
        299 => "recvmmsg".to_string(),
        300 => "fanotify_init".to_string(),
        301 => "fanotify_mark".to_string(),
        302 => "prlimit64".to_string(),
        303 => "name_to_handle_at".to_string(),
        304 => "open_by_handle_at".to_string(),
        305 => "clock_adjtime".to_string(),
        306 => "syncfs".to_string(),
        307 => "sendmmsg".to_string(),
        308 => "setns".to_string(),
        309 => "getcpu".to_string(),
        310 => "process_vm_readv".to_string(),
        311 => "process_vm_writev".to_string(),
        312 => "kcmp".to_string(),
        313 => "finit_module".to_string(),
        314 => "sched_setattr".to_string(),
        315 => "sched_getattr".to_string(),
        316 => "renameat2".to_string(),
        317 => "seccomp".to_string(),
        318 => "getrandom".to_string(),
        319 => "memfd_create".to_string(),
        320 => "kexec_file_load".to_string(),
        321 => "bpf".to_string(),
        322 => "execveat".to_string(),
        323 => "userfaultfd".to_string(),
        324 => "membarrier".to_string(),
        325 => "mlock2".to_string(),
        326 => "copy_file_range".to_string(),
        327 => "preadv2".to_string(),
        328 => "pwritev2".to_string(),
        329 => "pkey_mprotect".to_string(),
        330 => "pkey_alloc".to_string(),
        331 => "pkey_free".to_string(),
        332 => "statx".to_string(),
        333 => "io_pgetevents".to_string(),
        334 => "rseq".to_string(),
        _ => format!("syscall_{}", syscall_number),
    }
}

fn get_softirq_name(vector: u32) -> String {
    // Map softirq vectors to names
    match vector {
        0 => "HI".to_string(),
        1 => "TIMER".to_string(),
        2 => "NET_TX".to_string(),
        3 => "NET_RX".to_string(),
        4 => "BLOCK".to_string(),
        5 => "BLOCK_IOPOLL".to_string(),
        6 => "TASKLET".to_string(),
        7 => "SCHED".to_string(),
        8 => "HRTIMER".to_string(),
        9 => "RCU".to_string(),
        _ => format!("IRQ_{}", vector),
    }
}

fn format_number(num: u64) -> String {
    // Format number with commas for thousands
    let num_str = num.to_string();
    let mut result = String::new();
    let chars: Vec<char> = num_str.chars().collect();
    let len = chars.len();

    for (i, ch) in chars.iter().enumerate() {
        if i > 0 && (len - i) % 3 == 0 {
            result.push(',');
        }
        result.push(*ch);
    }

    result
}

fn parse_event(data: &[u8]) -> Option<Event> {
    if data.len() >= std::mem::size_of::<Event>() {
        let event = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const Event) };
        Some(event)
    } else {
        None
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let args = Args::parse();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/kernel-delay"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    // Set the target PID in the eBPF map (using key 0 to store the PID)
    let mut pid_map = AyaHashMap::try_from(ebpf.take_map("TARGET_PID").unwrap())?;
    pid_map.insert(0u64, args.pid as u64, 0)?;

    // Attach to syscall tracepoints (only attach to ones that exist)
    let program: &mut TracePoint = ebpf.program_mut("syscall_enter").unwrap().try_into()?;
    program.load()?;
    
    // Try to attach to common syscall tracepoints that exist on this system
    let syscalls_to_attach = vec![
        ("syscalls", "sys_enter_read"),
        ("syscalls", "sys_enter_write"),
        ("syscalls", "sys_enter_openat"),
        ("syscalls", "sys_enter_close"),
        ("syscalls", "sys_enter_poll"),
        ("syscalls", "sys_enter_lseek"),
        ("syscalls", "sys_enter_mmap"),
        ("syscalls", "sys_enter_mprotect"),
        ("syscalls", "sys_enter_munmap"),
    ];
    
    for (category, name) in syscalls_to_attach {
        match program.attach(category, name) {
            Ok(_) => debug!("Successfully attached to {}:{}", category, name),
            Err(e) => debug!("Failed to attach to {}:{}: {}", category, name, e),
        }
    }

    let program: &mut TracePoint = ebpf.program_mut("syscall_exit").unwrap().try_into()?;
    program.load()?;
    
    // new kernel syscall is openat , not open , check "mount | grep tracefs"
    // kernel 6.1.0-38-arm64, 在旧的内核中叫 sys_enter_open 新的内核里 sys_enter_openat.
    // ls /sys/kernel/tracing/events/syscalls| grep open
    // sys_enter_fsopen
    // sys_enter_mq_open
    // sys_enter_openat
    // sys_enter_openat2
    // ...

    let syscalls_to_attach = vec![
        ("syscalls", "sys_exit_read"),
        ("syscalls", "sys_exit_write"),
        ("syscalls", "sys_exit_openat"),
        ("syscalls", "sys_exit_close"),
        ("syscalls", "sys_exit_poll"),
        ("syscalls", "sys_exit_lseek"),
        ("syscalls", "sys_exit_mmap"),
        ("syscalls", "sys_exit_mprotect"),
        ("syscalls", "sys_exit_munmap"),
    ];
    
    for (category, name) in syscalls_to_attach {
        match program.attach(category, name) {
            Ok(_) => debug!("Successfully attached to {}:{}", category, name),
            Err(e) => debug!("Failed to attach to {}:{}: {}", category, name, e),
        }
    }

    // Attach to softirq tracepoints
    let program: &mut TracePoint = ebpf.program_mut("softirq_entry").unwrap().try_into()?;
    program.load()?;
    match program.attach("irq", "softirq_entry") {
        Ok(_) => debug!("Successfully attached to irq:softirq_entry"),
        Err(e) => debug!("Failed to attach to irq:softirq_entry: {}", e),
    }

    let program: &mut TracePoint = ebpf.program_mut("softirq_exit").unwrap().try_into()?;
    program.load()?;
    match program.attach("irq", "softirq_exit") {
        Ok(_) => debug!("Successfully attached to irq:softirq_exit"),
        Err(e) => debug!("Failed to attach to irq:softirq_exit: {}", e),
    }

    // Get reference to the ring buffer
    let ring_buf_map = ebpf.take_map("RING_BUF").unwrap();
    let mut ring_buf = RingBuf::try_from(ring_buf_map)?;

    // Print header
    let start_time = chrono::Utc::now();
    println!(
        "# Start sampling @{} ({} UTC)",
        start_time.to_rfc3339(),
        start_time.format("%H:%M:%S")
    );
    println!("# Monitoring PID: {}, Duration: {} seconds", args.pid, args.duration);

    // Collect events for a period of time
    let start_instant = std::time::Instant::now();
    let mut thread_events: StdHashMap<u32, Vec<Event>> = StdHashMap::new();
    let mut event_count = 0;

    while start_instant.elapsed().as_secs() < args.duration {
        // Try to read events from the ring buffer
        while let Some(item) = ring_buf.next() {
            // Parse the event
            if let Some(event) = parse_event(&item) {
                event_count += 1;
                // Group events by thread ID
                thread_events
                    .entry(event.tid)
                    .or_insert_with(Vec::new)
                    .push(event);
            }
        }

        // Small delay to avoid busy looping
        thread::sleep(Duration::from_millis(100));
    }

    let stop_time = chrono::Utc::now();
    println!(
        "# Stop sampling @{} ({} UTC)",
        stop_time.to_rfc3339(),
        stop_time.format("%H:%M:%S")
    );

    let dump_time = chrono::Utc::now();
    println!(
        "# Sample dump @{} ({} UTC)",
        dump_time.to_rfc3339(),
        dump_time.format("%H:%M:%S")
    );

    // Print summary
    println!("# Total events captured: {}", event_count);
    
    // Print the collected events in the requested format
    print_thread_statistics(&thread_events, args.pid);

    info!("Exiting...");
    std::process::exit(0);
}
