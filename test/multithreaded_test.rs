use std::thread;
use std::time::Duration;
use std::sync::{Arc, Mutex};

fn main() {
    println!("Starting multithreaded test program...");
    
    // Create some shared data
    let counter = Arc::new(Mutex::new(0u64));
    let mut handles = vec![];
    
    // Spawn multiple threads
    for i in 0..5 {
        let counter = Arc::clone(&counter);
        let handle = thread::spawn(move || {
            for _ in 0..u64::MAX {
                let mut num = counter.lock().unwrap();
                *num += 1;
                
                // Occasionally sleep to simulate I/O
                if *num % 100000 == 0 {
                    drop(num); // Release the lock
                    thread::sleep(Duration::from_millis(10));
                }
            }
            println!("Thread {} finished", i);
        });
        handles.push(handle);
    }
    
    // Spawn a few more threads that do different work
    for i in 5..8 {
        let handle = thread::spawn(move || {
            for j in 0..u64::MAX {
                // Simulate some computation with u64 to prevent overflow
                let _result = (j as u6  4) * (j as u64) * (j as u64);
                
                // Occasionally sleep
                if j % 100000 == 0 {
                    thread::sleep(Duration::from_millis(15));
                }
            }
            println!("Computation thread {} finished", i);
        });
        handles.push(handle);
    }
    
    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap();
    }
    
    println!("All threads completed. Final counter value: {}", *counter.lock().unwrap());
}