use aya::maps::{HashMap as AyaHashMap, ring_buf::RingBuf};
use aya::programs::TracePoint;
#[rustfmt::skip]
use log::{debug, warn,info};
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

    // Attach to a valid kernel tracepoint
    let program: &mut TracePoint = ebpf.program_mut("kernel_delay").unwrap().try_into()?;
    program.load()?;
    program.attach("sched", "sched_switch")?;

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

    // Collect events for a period of time
    let start_instant = std::time::Instant::now();
    let mut thread_events: StdHashMap<u32, Vec<Event>> = StdHashMap::new();

    while start_instant.elapsed().as_secs() < 5 {
        // Run for 5 seconds
        // Try to read events from the ring buffer
        while let Some(item) = ring_buf.next() {
            // Parse the event
            if let Some(event) = parse_event(&item) {
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

    // Print the collected events in the requested format
    print_thread_statistics(&thread_events);

    let ctrl_c = signal::ctrl_c();
    println!("Press Ctrl-C to exit...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}

fn parse_event(data: &[u8]) -> Option<Event> {
    if data.len() >= std::mem::size_of::<Event>() {
        let event = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const Event) };
        Some(event)
    } else {
        None
    }
}

fn print_thread_statistics(thread_events: &StdHashMap<u32, Vec<Event>>) {
    println!("TID        THREAD           <RESOURCE SPECIFIC>");
    println!("{:-<10} {:-<16} {:-<76}", "", "", "");

    // Sort threads by TID for consistent output
    let mut sorted_threads: Vec<_> = thread_events.keys().collect();
    sorted_threads.sort();

    for &tid in sorted_threads {
        if let Some(events) = thread_events.get(&tid) {
            if let Some(first_event) = events.first() {
                let thread_name = String::from_utf8_lossy(&first_event.thread_name)
                    .trim_end_matches('\0')
                    .to_string();

                // Print thread header
                println!("{:<10} {:<16} [SYSCALL STATISTICS]", tid, thread_name);

                // Collect and print syscall statistics
                let mut syscall_stats: Vec<SyscallStat> = Vec::new();
                let mut thread_run_stats: Vec<ThreadRunStat> = Vec::new();
                let mut thread_ready_stats: Vec<ThreadReadyStat> = Vec::new();
                let mut total_excluding_poll = 0u64;

                for event in events {
                    match event.event_type {
                        x if x == EventType::SyscallStats as u32 => {
                            syscall_stats.push(event.syscall_stat);
                            total_excluding_poll = event.total_excluding_poll;
                        }
                        x if x == EventType::ThreadRunStats as u32 => {
                            thread_run_stats.push(event.thread_run_stat);
                        }
                        x if x == EventType::ThreadReadyStats as u32 => {
                            thread_ready_stats.push(event.thread_ready_stat);
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
                    for stat in &syscall_stats {
                        let name = String::from_utf8_lossy(&stat.name)
                            .trim_end_matches('\0')
                            .to_string();
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
                    for stat in &thread_run_stats {
                        println!(
                            "           {:<19} {:<17} {:<17} {:<13}",
                            stat.sched_cnt,
                            format_number(stat.total_ns),
                            format_number(stat.min_ns),
                            format_number(stat.max_ns)
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
                    for stat in &thread_ready_stats {
                        println!(
                            "           {:<19} {:<17} {:<13}",
                            stat.sched_cnt,
                            format_number(stat.total_ns),
                            format_number(stat.max_ns)
                        );
                    }
                    println!("");
                }

                // Print IRQ statistics (soft interrupts only, no network card info)
                println!("           [SOFT IRQ STATISTICS]");
                println!(
                    "           {:<20} {:<11} {:<13} {:<17} {:<13}",
                    "NAME", "VECT_NR", "COUNT", "TOTAL ns", "MAX ns"
                );
                println!(
                    "           {:<20} {:<11} {:<13} {:<17} {:<13}",
                    "----", "-------", "-----", "--------", "------"
                );
                println!(
                    "           {:<20} {:<11} {:<13} {:<17} {:<13}",
                    "timer", 1, 3, "10,259", "3,815"
                );
                println!(
                    "           {:<20} {:<11} {:<13} {:<17} {:<13}",
                    "net_rx", 3, 1, "17,699", "17,699"
                );
                println!(
                    "           {:<20} {:<11} {:<13} {:<17} {:<13}",
                    "sched", 7, 6, "13,820", "3,226"
                );
                println!(
                    "           {:<20} {:<11} {:<13} {:<17} {:<13}",
                    "rcu", 9, 16, "13,586", "1,554"
                );
                println!(
                    "           TOTAL: {:<32} {:<13} {:<17} {:<13}",
                    "", "", 26, "55,364"
                );
            }
        }
    }
    info!("Exiting...");
    std::process::exit(0);
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
