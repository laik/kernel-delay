#![no_std]

// Define event types similar to the Python script
#[repr(u32)]
#[derive(Clone, Copy, Debug)]
pub enum EventType {
    StartDump = 0,
    SweepDone = 1,
    RevalEntry = 2,
    SyscallStats = 3,
    ThreadRunStats = 4,
    ThreadReadyStats = 5,
    HardIrqStats = 6,
    SoftIrqStats = 7,
}

// Event structure for syscall statistics
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SyscallStat {
    pub name: [u8; 16],
    pub number: u32,
    pub count: u32,
    pub total_ns: u64,
    pub max_ns: u64,
}

// Event structure for thread run statistics
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ThreadRunStat {
    pub sched_cnt: u32,
    pub total_ns: u64,
    pub min_ns: u64,
    pub max_ns: u64,
}

// Event structure for thread ready statistics
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ThreadReadyStat {
    pub sched_cnt: u32,
    pub total_ns: u64,
    pub max_ns: u64,
}

// Event structure for IRQ statistics
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct IrqStat {
    pub name: [u8; 16],
    pub count: u32,
    pub total_ns: u64,
    pub max_ns: u64,
    pub vector: u32, // For soft IRQs
}

// Main event structure
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Event {
    pub timestamp: u64,
    pub tid: u32,
    pub thread_name: [u8; 16],
    pub resource_type: [u8; 32],
    pub event_type: u32,
    // Union-like fields (only one will be valid based on event_type)
    pub syscall_stat: SyscallStat,
    pub thread_run_stat: ThreadRunStat,
    pub thread_ready_stat: ThreadReadyStat,
    pub irq_stat: IrqStat,
    pub total_excluding_poll: u64,
}

// When compiling for userspace, we need to implement serialization
#[cfg(feature = "user")]
unsafe impl aya::Pod for Event {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SyscallStat {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ThreadRunStat {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ThreadReadyStat {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for IrqStat {}