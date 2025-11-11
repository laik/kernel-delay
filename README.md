# kernel-delay

A Linux eBPF-based kernel latency monitoring tool that tracks system call delays, thread scheduling delays, and soft interrupt latencies for specific processes.

## Features

- Monitors system call latencies (entry/exit delays)
- Tracks thread scheduling delays (run queue wait times)
- Measures soft interrupt processing times
- Targets specific process IDs for focused monitoring
- Provides detailed per-thread statistics
- Real-time monitoring with configurable duration

## Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
1. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
1. (if cross-compiling) C toolchain: (e.g.) [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

## Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```shell
cargo run --release -- --pid <PID> [--duration <SECONDS>]
```

Or after building:

```shell
sudo -E target/release/kernel-delay --pid <PID> [--duration <SECONDS>]
```

Note: The application must be run with `sudo` privileges to access eBPF functionality.

### Command Line Arguments

- `--pid <PID>`: Process ID to monitor (required)
- `--duration <SECONDS>`: Monitoring duration in seconds (default: 10)

### Example Output

```text
# Start sampling @2025-11-11T03:33:23.920781130+00:00 (03:33:23 UTC)
# Monitoring PID: 3439, Duration: 10 seconds
# Stop sampling @2025-11-11T03:33:33.931373099+00:00 (03:33:33 UTC)
# Sample dump @2025-11-11T03:33:33.931450757+00:00 (03:33:33 UTC)
# Total events captured: 458
TID        THREAD           <RESOURCE SPECIFIC>
---------- ---------------- ----------------------------------------------------------------------------
3439       tailscaled       [SYSCALL STATISTICS]
           NAME                 NUMBER      COUNT         TOTAL ns          MAX ns       
           read                 0           8             7,554,731         3,436,063    
           syscall_3886         3886        1             3,515,906         3,515,906    
           syscall_1800         1800        1             2,080,611         2,080,611    
           syscall_4050         4050        1             1,534,682         1,534,682    
           syscall_1832         1832        1             368,968           368,968      
           syscall_1408         1408        1             363,956           363,956      
           syscall_3968         3968        1             95,205            95,205       
           kill                 62          3             46,314            36,033       
           setregid             114         2             19,067            10,838       
           write                1           1             6,665             6,665        
           syscall_4294967274   4294967274  1             4,483             4,483        
           syscall_4294967285   4294967285  2             3,413             2,172        
           TOTAL( - poll):                                       15,594,001   

           [SOFT IRQ STATISTICS]
           NAME                 VECT_NR     COUNT         TOTAL ns          MAX ns       
           SCHED                7           3             23,103            8,784        
           RCU                  9           2             4,942             3,421        
           TOTAL:                                                5                 28,045       
3460       tailscaled       [SYSCALL STATISTICS]
           [SOFT IRQ STATISTICS]
           NAME                 VECT_NR     COUNT         TOTAL ns          MAX ns       
           SCHED                7           2             9,151             5,667        
           TOTAL:                                                2                 9,151        
3465       tailscaled       [SYSCALL STATISTICS]
           [SOFT IRQ STATISTICS]
           NAME                 VECT_NR     COUNT         TOTAL ns          MAX ns       
           TIMER                1           1             11,914            11,914       
           SCHED                7           1             9,215             9,215        
           RCU                  9           1             2,035             2,035        
           TOTAL:                                                3                 23,164       
3493       tailscaled       [SYSCALL STATISTICS]
           NAME                 NUMBER      COUNT         TOTAL ns          MAX ns       
           read                 0           8             7,546,726         3,434,897    
           syscall_3904         3904        1             3,518,047         3,518,047    
           syscall_1800         1800        1             2,082,282         2,082,282    
           syscall_4050         4050        1             1,536,589         1,536,589    
           syscall_1832         1832        1             379,261           379,261      
           syscall_1408         1408        1             363,943           363,943      
           kill                 62          19            306,712           35,522       
           semctl               66          5             166,892           64,020       
           syscall_3968         3968        1             96,247            96,247       
           write                1           8             58,575            9,850        
           capset               126         1             44,765            44,765       
           sched_get_priority_max 146         2             38,141            32,070       
           timer_create         222         1             37,419            37,419       
           syscall_4294967285   4294967285  16            33,991            4,751        
           rename               82          2             18,184            11,045       
           rt_sigsuspend        130         3             17,334            6,422        
           setregid             114         1             6,685             6,685        
           eventfd2             290         1             5,920             5,920        
           syscall_4294967274   4294967274  1             3,481             3,481        
           TOTAL( - poll):                                       16,261,194   

           [SOFT IRQ STATISTICS]
           NAME                 VECT_NR     COUNT         TOTAL ns          MAX ns       
           SCHED                7           8             50,937            7,832        
           TIMER                1           3             24,399            8,673        
           RCU                  9           5             8,225             1,797        
           TOTAL:                                                16                83,561       
3496       tailscaled       [SYSCALL STATISTICS]
           NAME                 NUMBER      COUNT         TOTAL ns          MAX ns       
           kill                 62          10            187,413           35,618       
           read                 0           11            69,542            14,229       
           fsetxattr            190         1             45,684            45,684       
           sync                 162         1             33,670            33,670       
           syscall_4294967285   4294967285  11            31,774            4,704        
           semctl               66          1             30,753            30,753       
           chmod                90          1             9,211             9,211        
           write                1           1             6,418             6,418        
           timer_delete         226         2             5,760             4,018        
           TOTAL( - poll):                                       420,225      

           [SOFT IRQ STATISTICS]
           NAME                 VECT_NR     COUNT         TOTAL ns          MAX ns       
           SCHED                7           3             20,245            9,314        
           RCU                  9           3             9,467             5,142        
           TOTAL:                                                6                 29,712       
3497       tailscaled       [SYSCALL STATISTICS]
           [SOFT IRQ STATISTICS]
           NAME                 VECT_NR     COUNT         TOTAL ns          MAX ns       
           RCU                  9           1             4,287             4,287        
           TOTAL:                                                1                 4,287        
3498       tailscaled       [SYSCALL STATISTICS]
           NAME                 NUMBER      COUNT         TOTAL ns          MAX ns       
           read                 0           18            15,118,178        3,434,764    
           syscall_3904         3904        2             7,045,589         3,526,841    
           syscall_1800         1800        2             4,167,634         2,098,953    
           syscall_4050         4050        2             3,099,980         1,551,059    
           syscall_1408         1408        2             749,766           385,041      
           syscall_1832         1832        2             747,654           377,420      
           syscall_3968         3968        2             199,931           101,195      
           getppid              110         3             129,860           65,924       
           kill                 62          9             126,041           43,392       
           semctl               66          1             62,820            62,820       
           write                1           9             60,965            9,174        
           syscall_4294967285   4294967285  7             13,787            2,562        
           chown                92          1             10,471            10,471       
           rename               82          1             7,978             7,978        
           syscall_4294967274   4294967274  2             7,367             3,695        
           setregid             114         1             6,114             6,114        
           rt_sigsuspend        130         1             5,177             5,177        
           TOTAL( - poll):                                       31,559,312   

           [SOFT IRQ STATISTICS]
           NAME                 VECT_NR     COUNT         TOTAL ns          MAX ns       
           SCHED                7           5             34,543            10,170       
           TOTAL:                                                5                 34,543       
3501       tailscaled       [SYSCALL STATISTICS]
           [SOFT IRQ STATISTICS]
           NAME                 VECT_NR     COUNT         TOTAL ns          MAX ns       
           RCU                  9           1             3,218             3,218        
           TOTAL:                                                1                 3,218        
3502       tailscaled       [SYSCALL STATISTICS]
           NAME                 NUMBER      COUNT         TOTAL ns          MAX ns       
           read                 0           13            7,588,692         3,452,066    
           syscall_3904         3904        1             3,557,518         3,557,518    
           syscall_1950         1950        1             2,108,004         2,108,004    
           syscall_4050         4050        1             1,633,016         1,633,016    
           syscall_1832         1832        1             379,679           379,679      
           syscall_1536         1536        1             374,310           374,310      
           syscall_3968         3968        1             106,694           106,694      
           kill                 62          5             67,958            35,260       
           semctl               66          1             49,817            49,817       
           getppid              110         1             40,717            40,717       
           setregid             114         1             40,413            40,413       
           write                1           4             36,638            14,427       
           mincore              27          1             21,970            21,970       
           munmap               11          1             13,681            13,681       
           shmget               29          1             10,985            10,985       
           rename               82          1             9,668             9,668        
           setxattr             188         1             8,961             8,961        
           shmat                30          1             7,570             7,570        
           syscall_4294967285   4294967285  3             7,223             2,713        
           TOTAL( - poll):                                       16,063,514   

           [SOFT IRQ STATISTICS]
           NAME                 VECT_NR     COUNT         TOTAL ns          MAX ns       
           SCHED                7           2             10,514            5,433        
           TIMER                1           1             8,547             8,547        
           RCU                  9           1             1,700             1,700        
           TOTAL:                                                4                 20,761       
3507       tailscaled       [SYSCALL STATISTICS]
           [SOFT IRQ STATISTICS]
           NAME                 VECT_NR     COUNT         TOTAL ns          MAX ns       
           RCU                  9           1             3,435             3,435        
           TOTAL:                                                1                 3,435        
3508       tailscaled       [SYSCALL STATISTICS]
           NAME                 NUMBER      COUNT         TOTAL ns          MAX ns       
           read                 0           17            15,133,262        3,445,184    
           syscall_3886         3886        2             7,042,392         3,526,460    
           syscall_1800         1800        2             4,228,493         2,136,208    
           syscall_4050         4050        2             3,163,462         1,621,480    
           syscall_1408         1408        2             762,652           394,710      
           syscall_1832         1832        2             755,295           377,778      
           syscall_3968         3968        2             211,077           110,690      
           semctl               66          4             180,069           55,350       
           kill                 62          2             105,745           54,257       
           getppid              110         2             86,926            48,458       
           arch_prctl           158         1             46,122            46,122       
           capset               126         1             37,512            37,512       
           sched_get_priority_max 146         4             27,172            7,320        
           syscall_4294967285   4294967285  6             21,722            4,831        
           setregid             114         1             18,655            18,655       
           write                1           2             15,312            10,972       
           syscall_4294967274   4294967274  3             13,244            5,172        
           getdents             78          1             6,389             6,389        
           TOTAL( - poll):                                       31,855,501   

           [SOFT IRQ STATISTICS]
           NAME                 VECT_NR     COUNT         TOTAL ns          MAX ns       
           SCHED                7           6             34,630            7,437        
           RCU                  9           2             5,104             3,474        
           TOTAL:                                                8                 39,734       
3549       tailscaled       [SYSCALL STATISTICS]
           NAME                 NUMBER      COUNT         TOTAL ns          MAX ns       
           read                 0           24            22,717,296        3,456,256    
           syscall_3904         3904        3             10,589,068        3,534,776    
           syscall_1800         1800        3             6,303,818         2,127,351    
           syscall_4050         4050        3             4,695,288         1,575,051    
           syscall_1408         1408        3             1,156,592         397,579      
           syscall_1832         1832        3             1,121,329         380,170      
           syscall_3968         3968        3             315,428           113,339      
           semctl               66          6             228,857           46,834       
           kill                 62          9             170,086           44,599       
           getppid              110         4             152,973           39,561       
           capset               126         1             48,587            48,587       
           get_robust_list      274         1             39,317            39,317       
           syscall_422          422         1             34,311            34,311       
           mq_timedsend         242         1             32,655            32,655       
           syscall_4294967285   4294967285  15            30,765            2,930        
           write                1           5             29,139            7,480        
           setregid             114         4             26,478            7,010        
           sched_get_priority_max 146         3             20,126            7,804        
           rt_sigsuspend        130         2             13,480            7,276        
           syscall_4294967274   4294967274  3             11,921            4,347        
           TOTAL( - poll):                                       47,737,514   

           [SOFT IRQ STATISTICS]
           NAME                 VECT_NR     COUNT         TOTAL ns          MAX ns       
           SCHED                7           6             37,400            9,207        
           RCU                  9           2             3,317             1,811        
           TOTAL:                                                8                 40,717       
3551       tailscaled       [SYSCALL STATISTICS]
           [SOFT IRQ STATISTICS]
           NAME                 VECT_NR     COUNT         TOTAL ns          MAX ns       
           TIMER                1           1             14,928            14,928       
           SCHED                7           1             7,314             7,314        
           RCU                  9           1             1,647             1,647        
           TOTAL:                                                3                 23,889       
3552       tailscaled       [SYSCALL STATISTICS]
           [SOFT IRQ STATISTICS]
           NAME                 VECT_NR     COUNT         TOTAL ns          MAX ns       
           RCU                  9           1             3,311             3,311        
           TOTAL:                                                1                 3,311 
```

Output Explanation:
- **SYSCALL STATISTICS**: Shows system call latencies with name, syscall number, count, total time, and max time
- **SOFT IRQ STATISTICS**: Displays soft interrupt processing times with vector names and timing data
- **TOTAL( - poll)**: Aggregated time excluding poll syscalls for cleaner analysis

## Cross-compiling on macOS

Cross compilation should work on both Intel and Apple Silicon Macs.

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package kernel-delay --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```
The cross-compiled program `target/${ARCH}-unknown-linux-musl/release/kernel-delay` can be
copied to a Linux server or VM and run there.

## Docker Support

Multi-platform Docker images are available for easy deployment:
- Supports both AMD64 and ARM64 architectures
- Check the [build/](build/) directory for Dockerfile and build instructions

## License

With the exception of eBPF code, kernel-delay is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2