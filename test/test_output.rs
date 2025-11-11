use std::collections::HashMap as StdHashMap;
use std::thread;
use std::time::Duration;

// Import the Event structure from the common crate
use kernel_delay_common::{Event, EventType, SyscallStat, ThreadReadyStat, ThreadRunStat, IrqStat};

fn main() {
    // Create test data to simulate what would come from eBPF
    let mut thread_events: StdHashMap<u32, Vec<Event>> = StdHashMap::new();
    
    // Create multiple events for the same thread to test aggregation
    let syscall_stat1 = SyscallStat {
        name: [0; 16],
        number: 1, // write
        count: 2,
        total_ns: 20000,
        max_ns: 15000,
    };
    
    let syscall_stat2 = SyscallStat {
        name: [0; 16],
        number: 1, // write (same syscall)
        count: 3,
        total_ns: 30000,
        max_ns: 18000,
    };
    
    let syscall_stat3 = SyscallStat {
        name: [0; 16],
        number: 0, // read
        count: 1,
        total_ns: 5000,
        max_ns: 5000,
    };
    
    let irq_stat1 = IrqStat {
        name: [0; 16],
        count: 1,
        total_ns: 1000,
        max_ns: 1000,
        vector: 7, // SCHED
    };
    
    let irq_stat2 = IrqStat {
        name: [0; 16],
        count: 2,
        total_ns: 3000,
        max_ns: 2000,
        vector: 7, // SCHED (same vector)
    };
    
    let event1 = Event {
        timestamp: 1000000,
        tid: 1234,
        thread_name: [b't'; 16],
        resource_type: [0; 32],
        event_type: EventType::SyscallStats as u32,
        syscall_stat: syscall_stat1,
        thread_run_stat: ThreadRunStat { sched_cnt: 0, total_ns: 0, min_ns: 0, max_ns: 0 },
        thread_ready_stat: ThreadReadyStat { sched_cnt: 0, total_ns: 0, max_ns: 0 },
        irq_stat: IrqStat { name: [0; 16], count: 0, total_ns: 0, max_ns: 0, vector: 0 },
        total_excluding_poll: 50000,
    };
    
    let event2 = Event {
        timestamp: 1000100,
        tid: 1234,
        thread_name: [b't'; 16],
        resource_type: [0; 32],
        event_type: EventType::SyscallStats as u32,
        syscall_stat: syscall_stat2,
        thread_run_stat: ThreadRunStat { sched_cnt: 0, total_ns: 0, min_ns: 0, max_ns: 0 },
        thread_ready_stat: ThreadReadyStat { sched_cnt: 0, total_ns: 0, max_ns: 0 },
        irq_stat: IrqStat { name: [0; 16], count: 0, total_ns: 0, max_ns: 0, vector: 0 },
        total_excluding_poll: 50000,
    };
    
    let event3 = Event {
        timestamp: 1000200,
        tid: 1234,
        thread_name: [b't'; 16],
        resource_type: [0; 32],
        event_type: EventType::SyscallStats as u32,
        syscall_stat: syscall_stat3,
        thread_run_stat: ThreadRunStat { sched_cnt: 0, total_ns: 0, min_ns: 0, max_ns: 0 },
        thread_ready_stat: ThreadReadyStat { sched_cnt: 0, total_ns: 0, max_ns: 0 },
        irq_stat: IrqStat { name: [0; 16], count: 0, total_ns: 0, max_ns: 0, vector: 0 },
        total_excluding_poll: 50000,
    };
    
    let event4 = Event {
        timestamp: 1000300,
        tid: 1234,
        thread_name: [b't'; 16],
        resource_type: [0; 32],
        event_type: EventType::SoftIrqStats as u32,
        syscall_stat: SyscallStat { name: [0; 16], number: 0, count: 0, total_ns: 0, max_ns: 0 },
        thread_run_stat: ThreadRunStat { sched_cnt: 0, total_ns: 0, min_ns: 0, max_ns: 0 },
        thread_ready_stat: ThreadReadyStat { sched_cnt: 0, total_ns: 0, max_ns: 0 },
        irq_stat: irq_stat1,
        total_excluding_poll: 50000,
    };
    
    let event5 = Event {
        timestamp: 1000400,
        tid: 1234,
        thread_name: [b't'; 16],
        resource_type: [0; 32],
        event_type: EventType::SoftIrqStats as u32,
        syscall_stat: SyscallStat { name: [0; 16], number: 0, count: 0, total_ns: 0, max_ns: 0 },
        thread_run_stat: ThreadRunStat { sched_cnt: 0, total_ns: 0, min_ns: 0, max_ns: 0 },
        thread_ready_stat: ThreadReadyStat { sched_cnt: 0, total_ns: 0, max_ns: 0 },
        irq_stat: irq_stat2,
        total_excluding_poll: 50000,
    };
    
    // Add events to the thread
    thread_events.entry(1234).or_insert_with(Vec::new).push(event1);
    thread_events.entry(1234).or_insert_with(Vec::new).push(event2);
    thread_events.entry(1234).or_insert_with(Vec::new).push(event3);
    thread_events.entry(1234).or_insert_with(Vec::new).push(event4);
    thread_events.entry(1234).or_insert_with(Vec::new).push(event5);
    
    // Print the aggregated statistics
    print_thread_statistics(&thread_events, 1234);
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
        _ => format!("syscall_{}", syscall_number),
    }
}

fn get_softirq_name(vector: u32) -> String {
    // Map softirq vectors to names
    match vector {
        7 => "SCHED".to_string(),
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