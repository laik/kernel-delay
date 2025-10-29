use std::thread;
use std::time::Duration;

fn main() {
    println!("Starting simple multithreaded test program with named threads...");
    
    // Spawn multiple named threads that run indefinitely
    let mut handles = vec![];
    
    for i in 0..5 {
        let thread_name = format!("worker-{}", i);
        let handle = thread::Builder::new()
            .name(thread_name.clone())
            .spawn(move || {
                loop {
                    // Do some work
                    let mut _sum = 0;
                    for j in 0..1000 {
                        _sum += j;
                    }
                    
                    // Sleep for a bit
                    thread::sleep(Duration::from_millis(50));
                    
                    // Print occasionally to show progress
                    static mut COUNTER: u64 = 0;
                    unsafe {
                        COUNTER += 1;
                        if COUNTER % 100 == 0 {
                            println!("Thread {} iteration {}", thread_name, COUNTER / 100);
                        }
                    }
                }
            })
            .unwrap();
        handles.push(handle);
    }
    
    // Also spawn some different types of threads
    for i in 0..3 {
        let thread_name = format!("io-handler-{}", i);
        let handle = thread::Builder::new()
            .name(thread_name.clone())
            .spawn(move || {
                loop {
                    // Simulate I/O work
                    thread::sleep(Duration::from_millis(100));
                    
                    static mut COUNTER: u64 = 0;
                    unsafe {
                        COUNTER += 1;
                        if COUNTER % 50 == 0 {
                            println!("IO Handler {} iteration {}", i, COUNTER / 50);
                        }
                    }
                }
            })
            .unwrap();
        handles.push(handle);
    }
    
    println!("All threads started. Press Ctrl+C to stop.");
    
    // Wait for all threads to complete (they won't in this case)
    // In a real program, you would have a proper shutdown mechanism
    for handle in handles {
        let _ = handle.join();
    }
}