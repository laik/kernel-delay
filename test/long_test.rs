use std::thread; use std::time::Duration; fn main() { loop { thread::sleep(Duration::from_millis(100)); } }
