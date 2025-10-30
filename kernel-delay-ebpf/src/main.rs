#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::{map, tracepoint},
    maps::{HashMap, RingBuf},
    programs::TracePointContext,
};
use aya_log_ebpf::debug;
use kernel_delay_common::{Event, EventType, IrqStat, SyscallStat, ThreadReadyStat, ThreadRunStat};

// Ring buffer for sending events to userspace
#[map]
static RING_BUF: RingBuf = RingBuf::with_byte_size(1024 * 1024, 0);

// Map to store the target PID
#[map]
static TARGET_PID: HashMap<u64, u64> = HashMap::with_max_entries(1, 0);

// Maps to track syscall timing
#[map]
static SYSCALL_START_TIME: HashMap<u64, u64> = HashMap::with_max_entries(10240, 0);

// Maps to track softirq timing
#[map]
static SOFTIRQ_START_TIME: HashMap<u64, u64> = HashMap::with_max_entries(10240, 0);

// Separate tracepoint handlers for different tracepoint types
#[tracepoint]
pub fn syscall_enter(ctx: TracePointContext) -> u32 {
    match unsafe { try_syscall_enter(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn syscall_exit(ctx: TracePointContext) -> u32 {
    match unsafe { try_syscall_exit(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn softirq_entry(ctx: TracePointContext) -> u32 {
    match unsafe { try_softirq_entry(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn softirq_exit(ctx: TracePointContext) -> u32 {
    match unsafe { try_softirq_exit(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

unsafe fn try_syscall_enter(ctx: TracePointContext) -> Result<u32, i64> {
    // Get current process PID and TID
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = (pid_tgid & 0xFFFFFFFF) as u32;
    
    // Get target PID from the map (stored as a single entry with key 0)
    let target_pid_ptr = TARGET_PID.get(&0u64).ok_or(1i64)?;
    let target_pid = *target_pid_ptr as u32;
    
    // If current process is not the target PID, skip
    if pid != target_pid {
        return Ok(0);
    }
    
    // Extract syscall ID
    if let Ok(_syscall_id) = ctx.read_at::<u64>(16) {
        let current_time = bpf_ktime_get_ns();
        let key = ((pid as u64) << 32) | (tid as u64);
        SYSCALL_START_TIME.insert(&key, &current_time, 0)?;
    }
    
    Ok(0)
}

unsafe fn try_syscall_exit(ctx: TracePointContext) -> Result<u32, i64> {
    // Get current process PID and TID
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = (pid_tgid & 0xFFFFFFFF) as u32;
    
    // Get target PID from the map (stored as a single entry with key 0)
    let target_pid_ptr = TARGET_PID.get(&0u64).ok_or(1i64)?;
    let target_pid = *target_pid_ptr as u32;
    
    // If current process is not the target PID, skip
    if pid != target_pid {
        return Ok(0);
    }
    
    // Extract syscall ID
    if let Ok(syscall_id) = ctx.read_at::<u64>(16) {
        let current_time = bpf_ktime_get_ns();
        let key = ((pid as u64) << 32) | (tid as u64);
        if let Some(start_time) = SYSCALL_START_TIME.get(&key) {
            let latency = current_time - *start_time;
            
            // Remove the start time entry
            SYSCALL_START_TIME.remove(&key)?;
            
            // Create and send syscall event
            send_syscall_event(pid, tid, syscall_id as u32, latency, current_time)?;
        }
    }
    
    Ok(0)
}

unsafe fn try_softirq_entry(ctx: TracePointContext) -> Result<u32, i64> {
    // Get current process PID and TID
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = (pid_tgid & 0xFFFFFFFF) as u32;
    
    // Get target PID from the map (stored as a single entry with key 0)
    let target_pid_ptr = TARGET_PID.get(&0u64).ok_or(1i64)?;
    let target_pid = *target_pid_ptr as u32;
    
    // If current process is not the target PID, skip
    if pid != target_pid {
        return Ok(0);
    }
    
    // Extract vector (softirq type)
    if let Ok(vector) = ctx.read_at::<u32>(8) {
        let current_time = bpf_ktime_get_ns();
        let key = ((pid as u64) << 32) | ((tid as u64) << 16) | (vector as u64);
        SOFTIRQ_START_TIME.insert(&key, &current_time, 0)?;
    }
    
    Ok(0)
}

unsafe fn try_softirq_exit(ctx: TracePointContext) -> Result<u32, i64> {
    // Get current process PID and TID
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = (pid_tgid & 0xFFFFFFFF) as u32;
    
    // Get target PID from the map (stored as a single entry with key 0)
    let target_pid_ptr = TARGET_PID.get(&0u64).ok_or(1i64)?;
    let target_pid = *target_pid_ptr as u32;
    
    // If current process is not the target PID, skip
    if pid != target_pid {
        return Ok(0);
    }
    
    // Extract vector (softirq type)
    if let Ok(vector) = ctx.read_at::<u32>(8) {
        let current_time = bpf_ktime_get_ns();
        let key = ((pid as u64) << 32) | ((tid as u64) << 16) | (vector as u64);
        if let Some(start_time) = SOFTIRQ_START_TIME.get(&key) {
            let latency = current_time - *start_time;
            
            // Remove the start time entry
            SOFTIRQ_START_TIME.remove(&key)?;
            
            // Create and send softirq event
            send_softirq_event(pid, tid, vector, latency, current_time)?;
        }
    }
    
    Ok(0)
}

fn send_syscall_event(_pid: u32, tid: u32, syscall_id: u32, latency: u64, timestamp: u64) -> Result<u32, i64> {
    // Reserve space in the ring buffer for our event
    if let Some(mut entry) = RING_BUF.reserve::<Event>(0) {
        // Create syscall name based on ID
        let mut name = [0u8; 16];
        let syscall_name = get_syscall_name(syscall_id);
        
        // Copy the syscall name
        for i in 0..syscall_name.len().min(name.len()) {
            name[i] = syscall_name[i];
        }
        
        let syscall_stat = SyscallStat {
            name,
            number: syscall_id,
            count: 1,
            total_ns: latency,
            max_ns: latency,
        };
        
        // Create a simple thread name using the TID
        let mut thread_name = [0u8; 16];
        let simple_name = b"thread";
        for i in 0..simple_name.len().min(thread_name.len()) {
            thread_name[i] = simple_name[i];
        }
        
        let mut resource_type = [0u8; 32];
        resource_type[0] = b'[';
        resource_type[1] = b'S';
        resource_type[2] = b'Y';
        resource_type[3] = b'S';
        resource_type[4] = b'C';
        resource_type[5] = b'A';
        resource_type[6] = b'L';
        resource_type[7] = b'L';
        resource_type[8] = b' ';
        resource_type[9] = b'S';
        resource_type[10] = b'T';
        resource_type[11] = b'A';
        resource_type[12] = b'T';
        resource_type[13] = b'I';
        resource_type[14] = b'S';
        resource_type[15] = b'T';
        resource_type[16] = b'I';
        resource_type[17] = b'C';
        resource_type[18] = b'S';
        resource_type[19] = b']';
        
        let event = Event {
            timestamp,
            tid,
            thread_name,
            resource_type,
            event_type: EventType::SyscallStats as u32,
            syscall_stat,
            thread_run_stat: ThreadRunStat {
                sched_cnt: 0,
                total_ns: 0,
                min_ns: 0,
                max_ns: 0,
            },
            thread_ready_stat: ThreadReadyStat {
                sched_cnt: 0,
                total_ns: 0,
                max_ns: 0,
            },
            irq_stat: IrqStat {
                name: [0; 16],
                count: 0,
                total_ns: 0,
                max_ns: 0,
                vector: 0,
            },
            total_excluding_poll: latency,
        };
        
        // Write the event to the ring buffer entry
        entry.write(event);
        
        // Submit the entry to make it visible to userspace
        entry.submit(0);
        
        // Log the event
        debug!(&event, "Syscall event recorded for TID {}", tid);
    }
    
    Ok(0)
}

fn send_softirq_event(_pid: u32, tid: u32, vector: u32, latency: u64, timestamp: u64) -> Result<u32, i64> {
    // Reserve space in the ring buffer for our event
    if let Some(mut entry) = RING_BUF.reserve::<Event>(0) {
        // Create softirq name based on vector
        let mut name = [0u8; 16];
        let irq_name = get_softirq_name(vector);
        
        // Copy the softirq name
        for i in 0..irq_name.len().min(name.len()) {
            name[i] = irq_name[i];
        }
        
        let irq_stat = IrqStat {
            name,
            count: 1,
            total_ns: latency,
            max_ns: latency,
            vector,
        };
        
        // Create a simple thread name using the TID
        let mut thread_name = [0u8; 16];
        let simple_name = b"thread";
        for i in 0..simple_name.len().min(thread_name.len()) {
            thread_name[i] = simple_name[i];
        }
        
        let mut resource_type = [0u8; 32];
        resource_type[0] = b'[';
        resource_type[1] = b'S';
        resource_type[2] = b'O';
        resource_type[3] = b'F';
        resource_type[4] = b'T';
        resource_type[5] = b' ';
        resource_type[6] = b'I';
        resource_type[7] = b'R';
        resource_type[8] = b'Q';
        resource_type[9] = b' ';
        resource_type[10] = b'S';
        resource_type[11] = b'T';
        resource_type[12] = b'A';
        resource_type[13] = b'T';
        resource_type[14] = b'I';
        resource_type[15] = b'S';
        resource_type[16] = b'T';
        resource_type[17] = b'I';
        resource_type[18] = b'C';
        resource_type[19] = b'S';
        resource_type[20] = b']';
        
        let event = Event {
            timestamp,
            tid,
            thread_name,
            resource_type,
            event_type: EventType::SoftIrqStats as u32,
            syscall_stat: SyscallStat {
                name: [0; 16],
                number: 0,
                count: 0,
                total_ns: 0,
                max_ns: 0,
            },
            thread_run_stat: ThreadRunStat {
                sched_cnt: 0,
                total_ns: 0,
                min_ns: 0,
                max_ns: 0,
            },
            thread_ready_stat: ThreadReadyStat {
                sched_cnt: 0,
                total_ns: 0,
                max_ns: 0,
            },
            irq_stat,
            total_excluding_poll: 0,
        };
        
        // Write the event to the ring buffer entry
        entry.write(event);
        
        // Submit the entry to make it visible to userspace
        entry.submit(0);
        
        // Log the event
        debug!(&event, "SoftIRQ event recorded for TID {}", tid);
    }
    
    Ok(0)
}

fn get_syscall_name(id: u32) -> &'static [u8] {
    match id {
        0 => b"read",
        1 => b"write",
        2 => b"open",
        3 => b"close",
        4 => b"stat",
        5 => b"fstat",
        6 => b"lstat",
        7 => b"poll",
        8 => b"lseek",
        9 => b"mmap",
        10 => b"mprotect",
        11 => b"munmap",
        12 => b"brk",
        13 => b"rt_sigaction",
        14 => b"rt_sigprocmask",
        15 => b"rt_sigreturn",
        16 => b"ioctl",
        17 => b"pread64",
        18 => b"pwrite64",
        19 => b"readv",
        20 => b"writev",
        56 => b"clone",
        57 => b"fork",
        58 => b"vfork",
        59 => b"execve",
        60 => b"exit",
        61 => b"wait4",
        62 => b"kill",
        158 => b"arch_prctl",
        231 => b"exit_group",
        _ => b"unknown",
    }
}

fn get_softirq_name(vector: u32) -> &'static [u8] {
    match vector {
        0 => b"HI",
        1 => b"TIMER",
        2 => b"NET_TX",
        3 => b"NET_RX",
        4 => b"BLOCK",
        5 => b"BLOCK_IOPOLL",
        6 => b"TASKLET",
        7 => b"SCHED",
        8 => b"HRTIMER",
        9 => b"RCU",
        _ => b"UNKNOWN",
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";