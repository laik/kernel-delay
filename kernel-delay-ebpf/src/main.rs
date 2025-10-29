#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_get_current_pid_tgid,
    macros::map,
    macros::tracepoint,
    maps::RingBuf,
    programs::TracePointContext,
};
use aya_log_ebpf::{debug, info};
use kernel_delay_common::{Event, EventType, IrqStat, SyscallStat, ThreadReadyStat, ThreadRunStat};

// Ring buffer for sending events to userspace
#[map]
static RING_BUF: RingBuf = RingBuf::with_byte_size(1024 * 1024, 0);

// Map to store the target PID
#[map]
static TARGET_PID: aya_ebpf::maps::HashMap<u64, u64> = aya_ebpf::maps::HashMap::with_max_entries(1, 0);

#[tracepoint]
pub fn kernel_delay(ctx: TracePointContext) -> u32 {
    match try_kernel_delay(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_kernel_delay(ctx: TracePointContext) -> Result<u32, u32> {
    // Get current process PID and TID
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = (pid_tgid & 0xFFFFFFFF) as u32;
    
    // Get target PID from the map (stored as a single entry with key 0)
    let target_pid_ptr = unsafe { TARGET_PID.get(&0u64).ok_or(1u32)? };
    let target_pid = *target_pid_ptr as u32;
    
    // If current process is not the target PID, skip
    if pid != target_pid {
        return Ok(0);
    }
    
    // For now, we'll create a simple event for demonstration
    // In a real implementation, you would collect actual syscall and scheduling data
    let current_time = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
    
    // Reserve space in the ring buffer for our event
    if let Some(mut entry) = RING_BUF.reserve::<Event>(0) {
        // Create a simple syscall stat event with more meaningful names
        let mut name = [0u8; 16];
        
        // Simple approach: use syscall names based on TID mod
        // All names need to be the same length
        let syscall_name = match tid % 5 {

            0 => b"read",
            1 => b"writ",
            2 => b"open",
            3 => b"clos",
            4 => b"poll",
            5 => b"send",
            6 => b"recv",
            7 => b"sock",
            8 => b"getd",
            9 => b"ioct",
            10 => b"sent",
            11 => b"bind",
            12 => b"acce",
            13 => b"conn",
            14 => b"list",
            _ => b"othr",
        };
        
        // Copy the selected name
        for i in 0..syscall_name.len() {
            if i < name.len() {
                name[i] = syscall_name[i];
            }
        }
        
        let syscall_stat = SyscallStat {
            name,
            number: 1,
            count: 1,
            total_ns: 1000,
            max_ns: 1000,
        };
        
        let thread_run_stat = ThreadRunStat {
            sched_cnt: 1,
            total_ns: 5000,
            min_ns: 100,
            max_ns: 1000,
        };
        
        let thread_ready_stat = ThreadReadyStat {
            sched_cnt: 1,
            total_ns: 2000,
            max_ns: 500,
        };
        
        let mut irq_name = [0u8; 16];
        irq_name[0] = b's';
        irq_name[1] = b'o';
        irq_name[2] = b'f';
        irq_name[3] = b't';
        irq_name[4] = b'i';
        irq_name[5] = b'r';
        irq_name[6] = b'q';
        
        let irq_stat = IrqStat {
            name: irq_name,
            count: 1,
            total_ns: 1000,
            max_ns: 1000,
            vector: 1,
        };
        
        // Create a more meaningful thread name using the TID
        let mut thread_name = [0u8; 16];
        
        // Simple approach: just use "thread" as the name for all threads
        // In a real implementation, you would get the actual thread name from the kernel
        let simple_name = b"thread";
        for i in 0..simple_name.len() {
            if i < thread_name.len() {
                thread_name[i] = simple_name[i];
            }
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
            timestamp: current_time,
            tid,
            thread_name,
            resource_type,
            event_type: EventType::SyscallStats as u32,
            syscall_stat,
            thread_run_stat,
            thread_ready_stat,
            irq_stat,
            total_excluding_poll: 5000,
        };
        
        // Write the event to the ring buffer entry
        entry.write(event);
        
        // Submit the entry to make it visible to userspace
        entry.submit(0);
        
        // debug!(&ctx, "Event recorded for PID {} TID {}", pid, tid);
    }
    
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";