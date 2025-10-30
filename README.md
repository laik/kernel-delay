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
# Start sampling @2025-10-30T03:40:17.070448894+00:00 (03:40:17 UTC)
# Monitoring PID: 2975, Duration: 10 seconds
# Stop sampling @2025-10-30T03:40:27.079950324+00:00 (03:40:27 UTC)
# Sample dump @2025-10-30T03:40:27.080011875+00:00 (03:40:27 UTC)
# Total events captured: 455
TID        THREAD           <RESOURCE SPECIFIC>
---------- ---------------- ----------------------------------------------------------------------------
2996       tailscaled       [SYSCALL STATISTICS]
           [SOFT IRQ STATISTICS]
           NAME                 VECT_NR     COUNT         TOTAL ns          MAX ns
           SCHED                7           1             4,704             4,704
           RCU                  9           1             948               948
           SCHED                7           1             2,970             2,970
           SCHED                7           1             3,421             3,421
           TOTAL:                                                4                 12,043
3039       tailscaled       [SYSCALL STATISTICS]
           NAME                 NUMBER      COUNT         TOTAL ns          MAX ns
           getrusage            98          1             38,233            38,233
           kill                 62          1             31,495            31,495
           getrusage            98          1             9,240             9,240
           syscall_4294967285   4294967285  1             4,186             4,186
           kill                 62          1             30,550            30,550
           getrusage            98          1             8,658             8,658
           syscall_4294967285   4294967285  1             3,631             3,631
           kill                 62          1             29,100            29,100
           getrusage            98          1             8,319             8,319
           syscall_4294967285   4294967285  1             3,748             3,748
           getrusage            98          1             33,737            33,737
           read                 0           1             21,202            21,202
           write                1           1             8,792             8,792
           write                1           1             9,511             9,511
           write                1           1             10,076            10,076
           write                1           1             8,459             8,459
           read                 0           1             14,855            14,855
           read                 0           1             11,482            11,482
           read                 0           1             17,184            17,184
           read                 0           1             10,122            10,122
           read                 0           1             11,973            11,973
           read                 0           1             10,239            10,239
           read                 0           1             10,012            10,012
           read                 0           1             10,704            10,704
           read                 0           1             10,189            10,189
           read                 0           1             11,138            11,138
           read                 0           1             11,044            11,044
           read                 0           1             10,623            10,623
           read                 0           1             3,384             3,384
           syscall_3450         3450        1             3,393,711         3,393,711
           read                 0           1             3,364,611         3,364,611
           read                 0           1             3,037             3,037
           syscall_2091         2091        1             3,351,934         3,351,934
           read                 0           1             3,251,217         3,251,217
           read                 0           1             3,110             3,110
           syscall_3968         3968        1             271,128           271,128
           syscall_1536         1536        1             386,931           386,931
           read                 0           1             366,356           366,356
           read                 0           1             3,104             3,104
           syscall_1833         1833        1             401,342           401,342
           read                 0           1             368,404           368,404
           pipe                 22          1             23,401            23,401
           madvise              28          1             16,577            16,577
           shmget               29          1             10,429            10,429
           munmap               11          1             23,021            23,021
           read                 0           1             3,438             3,438
           read                 0           1             4,640             4,640
           read                 0           1             3,201             3,201
           read                 0           1             2,181             2,181
           read                 0           1             32,471            32,471
           syscall_4294967274   4294967274  1             4,413             4,413
           write                1           1             6,087             6,087
           syscall_4294967274   4294967274  1             4,289             4,289
           write                1           1             5,799             5,799
           syscall_4294967274   4294967274  1             4,059             4,059
           write                1           1             5,782             5,782
           read                 0           1             3,788             3,788
           syscall_3300         3300        1             3,416,820         3,416,820
           read                 0           1             3,356,639         3,356,639
           read                 0           1             3,504             3,504
           syscall_2091         2091        1             3,303,088         3,303,088
           read                 0           1             3,252,271         3,252,271
           read                 0           1             3,017             3,017
           syscall_3968         3968        1             270,033           270,033
           syscall_1408         1408        1             380,995           380,995
           read                 0           1             365,544           365,544
           read                 0           1             3,294             3,294
           syscall_1833         1833        1             402,448           402,448
           read                 0           1             368,120           368,120
           write                1           1             11,455            11,455
           read                 0           1             3,190             3,190
           syscall_3300         3300        1             3,428,443         3,428,443
           read                 0           1             3,223,345         3,223,345
           read                 0           1             3,217             3,217
           syscall_2091         2091        1             3,318,469         3,318,469
           read                 0           1             3,227,501         3,227,501
           read                 0           1             3,180             3,180
           syscall_3968         3968        1             267,995           267,995
           syscall_1408         1408        1             391,881           391,881
           read                 0           1             354,239           354,239
           read                 0           1             3,274             3,274
           syscall_1833         1833        1             413,810           413,810
           read                 0           1             351,955           351,955
           write                1           1             11,382            11,382
           read                 0           1             3,310             3,310
           syscall_3300         3300        1             3,460,503         3,460,503
           read                 0           1             3,362,529         3,362,529
           read                 0           1             3,253             3,253
           syscall_2091         2091        1             3,304,857         3,304,857
           read                 0           1             3,228,434         3,228,434
           read                 0           1             3,144             3,144
           syscall_3968         3968        1             267,581           267,581
           syscall_1408         1408        1             384,653           384,653
           read                 0           1             353,010           353,010
           read                 0           1             3,030             3,030
           syscall_1833         1833        1             417,922           417,922
           read                 0           1             351,804           351,804
           write                1           1             11,676            11,676
           syscall_4294967274   4294967274  1             4,299             4,299
           TOTAL( - poll):                                       4,299

           [SOFT IRQ STATISTICS]
           NAME                 VECT_NR     COUNT         TOTAL ns          MAX ns
           SCHED                7           1             5,238             5,238
           RCU                  9           1             2,653             2,653
           SCHED                7           1             8,812             8,812
           RCU                  9           1             5,596             5,596
           RCU                  9           1             6,617             6,617
           RCU                  9           1             3,788             3,788
           SCHED                7           1             5,231             5,231
           SCHED                7           1             9,250             9,250
           SCHED                7           1             9,194             9,194
           RCU                  9           1             2,198             2,198
           SCHED                7           1             8,833             8,833
           SCHED                7           1             8,235             8,235
           SCHED                7           1             9,460             9,460
           RCU                  9           1             2,028             2,028
           TOTAL:                                                14                87,133
3042       tailscaled       [SYSCALL STATISTICS]
           NAME                 NUMBER      COUNT         TOTAL ns          MAX ns
           getrusage            98          1             24,439            24,439
           syscall_4294967285   4294967285  1             2,411             2,411
           set_tid_address      218         1             4,580             4,580
           syscall_4294967285   4294967285  1             1,731             1,731
           write                1           1             4,793             4,793
           kill                 62          1             21,109            21,109
           getrusage            98          1             22,843            22,843
           syscall_4294967285   4294967285  1             2,378             2,378
           kill                 62          1             21,146            21,146
           getrusage            98          1             4,827             4,827
           write                1           1             3,922             3,922
           kill                 62          1             21,497            21,497
           getrusage            98          1             21,451            21,451
           syscall_4294967285   4294967285  1             2,656             2,656
           kill                 62          1             20,258            20,258
           getrusage            98          1             25,582            25,582
           getrusage            98          1             26,842            26,842
           syscall_4294967285   4294967285  1             3,511             3,511
           kill                 62          1             26,077            26,077
           getrusage            98          1             6,243             6,243
           syscall_4294967285   4294967285  1             1,820             1,820
           getrusage            98          1             28,042            28,042
           kill                 62          1             25,182            25,182
           getrusage            98          1             5,953             5,953
           getrusage            98          1             27,002            27,002
           syscall_4294967285   4294967285  1             3,083             3,083
           kill                 62          1             25,108            25,108
           getrusage            98          1             6,130             6,130
           syscall_4294967285   4294967285  1             1,814             1,814
           write                1           1             4,733             4,733
           kill                 62          1             25,719            25,719
           getrusage            98          1             5,726             5,726
           syscall_4294967285   4294967285  1             3,485             3,485
           TOTAL( - poll):                                       3,485

           [SOFT IRQ STATISTICS]
           NAME                 VECT_NR     COUNT         TOTAL ns          MAX ns
           NET_RX               3           1             6,925             6,925
           NET_RX               3           1             7,570             7,570
           NET_RX               3           1             8,612             8,612
           NET_RX               3           1             9,421             9,421
           SCHED                7           1             9,999             9,999
           NET_RX               3           1             9,961             9,961
           NET_RX               3           1             8,896             8,896
           NET_RX               3           1             8,598             8,598
           SCHED                7           1             5,055             5,055
           SCHED                7           1             8,311             8,311
           NET_RX               3           1             8,822             8,822
           NET_RX               3           1             4,613             4,613
           TOTAL:                                                12                96,783
3043       tailscaled       [SYSCALL STATISTICS]
           NAME                 NUMBER      COUNT         TOTAL ns          MAX ns
           getrusage            98          1             6,200             6,200
           write                1           1             7,630             7,630
           kill                 62          1             24,633            24,633
           getrusage            98          1             4,557             4,557
           getrusage            98          1             25,305            25,305
           syscall_4294967285   4294967285  1             2,578             2,578
           write                1           1             4,774             4,774
           read                 0           1             3,681             3,681
           syscall_3300         3300        1             3,356,823         3,356,823
           read                 0           1             3,203,472         3,203,472
           read                 0           1             2,224             2,224
           syscall_2091         2091        1             3,265,500         3,265,500
           read                 0           1             3,198,692         3,198,692
           read                 0           1             1,954             1,954
           syscall_3968         3968        1             249,010           249,010
           syscall_1408         1408        1             372,169           372,169
           read                 0           1             340,944           340,944
           read                 0           1             2,088             2,088
           syscall_1833         1833        1             375,042           375,042
           read                 0           1             341,562           341,562
           getrusage            98          1             5,168             5,168
           syscall_4294967285   4294967285  1             1,875             1,875
           getrusage            98          1             27,006            27,006
           syscall_4294967285   4294967285  1             2,686             2,686
           kill                 62          1             23,825            23,825
           getrusage            98          1             4,910             4,910
           syscall_4294967285   4294967285  1             1,597             1,597
           getrusage            98          1             25,396            25,396
           syscall_4294967285   4294967285  1             2,719             2,719
           kill                 62          1             23,415            23,415
           getrusage            98          1             5,950             5,950
           syscall_4294967285   4294967285  1             1,660             1,660
           kill                 62          1             24,921            24,921
           getrusage            98          1             5,756             5,756
           getrusage            98          1             27,991            27,991
           kill                 62          1             24,777            24,777
           getrusage            98          1             5,556             5,556
           syscall_4294967285   4294967285  1             1,630             1,630
           getrusage            98          1             27,734            27,734
           syscall_4294967285   4294967285  1             2,749             2,749
           kill                 62          1             24,918            24,918
           getrusage            98          1             5,589             5,589
           getrusage            98          1             26,822            26,822
           write                1           1             7,433             7,433
           getrusage            98          1             23,999            23,999
           kill                 62          1             25,766            25,766
           getrusage            98          1             5,612             5,612
           syscall_4294967285   4294967285  1             1,611             1,611
           getrusage            98          1             26,350            26,350
           kill                 62          1             24,570            24,570
           getrusage            98          1             5,676             5,676
           getrusage            98          1             26,822            26,822
           kill                 62          1             24,667            24,667
           getrusage            98          1             5,472             5,472
           syscall_4294967285   4294967285  1             1,787             1,787
           kill                 62          1             25,152            25,152
           getrusage            98          1             7,106             7,106
           syscall_4294967285   4294967285  1             2,308             2,308
           kill                 62          1             25,168            25,168
           getrusage            98          1             20,872            20,872
           syscall_4294967285   4294967285  1             2,252             2,252
           getrusage            98          1             27,360            27,360
           kill                 62          1             24,587            24,587
           getrusage            98          1             5,281             5,281
           getrusage            98          1             26,351            26,351
           kill                 62          1             26,882            26,882
           getrusage            98          1             5,261             5,261
           syscall_4294967285   4294967285  1             2,078             2,078
           getrusage            98          1             29,314            29,314
           kill                 62          1             24,470            24,470
           getrusage            98          1             5,382             5,382
           syscall_4294967285   4294967285  1             1,771             1,771
           getrusage            98          1             26,705            26,705
           syscall_4294967285   4294967285  1             3,307             3,307
           kill                 62          1             23,742            23,742
           getrusage            98          1             5,204             5,204
           syscall_4294967285   4294967285  1             1,771             1,771
           getrusage            98          1             28,258            28,258
           kill                 62          1             26,511            26,511
           getrusage            98          1             5,780             5,780
           getrusage            98          1             29,821            29,821
           kill                 62          1             24,674            24,674
           getrusage            98          1             5,251             5,251
           syscall_4294967285   4294967285  1             1,788             1,788
           getrusage            98          1             29,761            29,761
           kill                 62          1             27,463            27,463
           getrusage            98          1             5,328             5,328
           syscall_4294967285   4294967285  1             1,848             1,848
           getrusage            98          1             29,658            29,658
           kill                 62          1             25,405            25,405
           getrusage            98          1             5,315             5,315
           getrusage            98          1             28,950            28,950
           kill                 62          1             25,980            25,980
           getrusage            98          1             5,262             5,262
           getrusage            98          1             28,232            28,232
           kill                 62          1             26,260            26,260
           getrusage            98          1             5,442             5,442
           syscall_4294967285   4294967285  1             1,720             1,720
           getrusage            98          1             28,953            28,953
           kill                 62          1             26,795            26,795
           getrusage            98          1             5,261             5,261
           getrusage            98          1             28,973            28,973
           read                 0           1             3,314             3,314
           syscall_3300         3300        1             3,296,974         3,296,974
           read                 0           1             3,222,444         3,222,444
           read                 0           1             1,898             1,898
           syscall_2091         2091        1             3,245,150         3,245,150
           read                 0           1             3,201,646         3,201,646
           read                 0           1             1,543             1,543
           syscall_3968         3968        1             251,305           251,305
           syscall_1408         1408        1             376,601           376,601
           read                 0           1             335,305           335,305
           read                 0           1             1,627             1,627
           syscall_1833         1833        1             368,968           368,968
           read                 0           1             341,168           341,168
           getrusage            98          1             6,053             6,053
           syscall_4294967285   4294967285  1             1,977             1,977
           getrusage            98          1             30,510            30,510
           getrusage            98          1             26,946            26,946
           getrusage            98          1             28,485            28,485
           kill                 62          1             45,302            45,302
           getrusage            98          1             5,960             5,960
           syscall_4294967285   4294967285  1             1,814             1,814
           kill                 62          1             24,363            24,363
           TOTAL( - poll):                                       24,363

           [SOFT IRQ STATISTICS]
           NAME                 VECT_NR     COUNT         TOTAL ns          MAX ns
           RCU                  9           1             2,378             2,378
           SCHED                7           1             4,302             4,302
           SCHED                7           1             5,145             5,145
           SCHED                7           1             7,904             7,904
           SCHED                7           1             8,171             8,171
           SCHED                7           1             6,317             6,317
           SCHED                7           1             6,487             6,487
           SCHED                7           1             4,116             4,116
           SCHED                7           1             3,791             3,791
           SCHED                7           1             4,390             4,390
           SCHED                7           1             7,657             7,657
           TOTAL:                                                11                60,658
3045       tailscaled       [SYSCALL STATISTICS]
           NAME                 NUMBER      COUNT         TOTAL ns          MAX ns
           write                1           1             5,826             5,826
           write                1           1             5,335             5,335
           syscall_4294967274   4294967274  1             3,855             3,855
           write                1           1             3,721             3,721
           write                1           1             7,924             7,924
           setxattr             188         1             19,513            19,513
           TOTAL( - poll):                                       19,513

3080       tailscaled       [SYSCALL STATISTICS]
           NAME                 NUMBER      COUNT         TOTAL ns          MAX ns
           getrusage            98          1             6,291             6,291
           getrusage            98          1             28,328            28,328
           kill                 62          1             22,128            22,128
           getrusage            98          1             4,510             4,510
           getrusage            98          1             24,219            24,219
           kill                 62          1             20,602            20,602
           getrusage            98          1             4,597             4,597
           getrusage            98          1             27,226            27,226
           kill                 62          1             24,910            24,910
           getrusage            98          1             5,191             5,191
           syscall_4294967285   4294967285  1             1,801             1,801
           getrusage            98          1             25,566            25,566
           syscall_4294967285   4294967285  1             3,281             3,281
           kill                 62          1             23,391            23,391
           getrusage            98          1             5,155             5,155
           syscall_4294967285   4294967285  1             1,674             1,674
           syscall_4294967274   4294967274  1             3,441             3,441
           getrusage            98          1             27,293            27,293
           getrusage            98          1             24,213            24,213
           getrusage            98          1             23,141            23,141
           kill                 62          1             24,059            24,059
           getrusage            98          1             5,255             5,255
           syscall_4294967285   4294967285  1             1,851             1,851
           getrusage            98          1             26,358            26,358
           syscall_4294967285   4294967285  1             2,939             2,939
           kill                 62          1             23,882            23,882
           getrusage            98          1             5,048             5,048
           syscall_4294967285   4294967285  1             1,663             1,663
           getrusage            98          1             26,475            26,475
           kill                 62          1             25,212            25,212
           getrusage            98          1             5,054             5,054
           syscall_4294967285   4294967285  1             1,947             1,947
           getrusage            98          1             25,970            25,970
           kill                 62          1             22,555            22,555
           getrusage            98          1             6,016             6,016
           getrusage            98          1             26,404            26,404
           kill                 62          1             24,360            24,360
           getrusage            98          1             5,793             5,793
           syscall_4294967285   4294967285  1             1,837             1,837
           getrusage            98          1             26,882            26,882
           syscall_4294967285   4294967285  1             2,960             2,960
           kill                 62          1             45,553            45,553
           getrusage            98          1             5,238             5,238
           syscall_4294967285   4294967285  1             1,691             1,691
           getrusage            98          1             26,598            26,598
           kill                 62          1             26,495            26,495
           getrusage            98          1             5,612             5,612
           syscall_4294967285   4294967285  1             1,760             1,760
           getrusage            98          1             26,662            26,662
           kill                 62          1             50,633            50,633
           getrusage            98          1             5,599             5,599
           syscall_4294967285   4294967285  1             1,868             1,868
           getrusage            98          1             27,477            27,477
           syscall_4294967285   4294967285  1             2,840             2,840
           kill                 62          1             23,588            23,588
           getrusage            98          1             5,466             5,466
           syscall_4294967285   4294967285  1             1,623             1,623
           getrusage            98          1             28,930            28,930
           syscall_4294967285   4294967285  1             2,686             2,686
           kill                 62          1             25,028            25,028
           getrusage            98          1             5,178             5,178
           syscall_4294967285   4294967285  1             1,637             1,637
           getrusage            98          1             25,806            25,806
           kill                 62          1             25,004            25,004
           getrusage            98          1             5,549             5,549
           syscall_4294967285   4294967285  1             1,660             1,660
           getrusage            98          1             29,037            29,037
           syscall_4294967285   4294967285  1             3,040             3,040
           kill                 62          1             26,190            26,190
           getrusage            98          1             5,211             5,211
           syscall_4294967285   4294967285  1             1,724             1,724
           kill                 62          1             26,411            26,411
           write                1           1             6,167             6,167
           TOTAL( - poll):                                       6,167

           [SOFT IRQ STATISTICS]
           NAME                 VECT_NR     COUNT         TOTAL ns          MAX ns
           SCHED                7           1             5,996             5,996
           SCHED                7           1             4,711             4,711
           SCHED                7           1             3,972             3,972
           SCHED                7           1             3,989             3,989
           SCHED                7           1             6,691             6,691
           SCHED                7           1             4,323             4,323
           SCHED                7           1             4,206             4,206
           TOTAL:                                                7                 33,888
3081       tailscaled       [SYSCALL STATISTICS]
           NAME                 NUMBER      COUNT         TOTAL ns          MAX ns
           write                1           1             10,018            10,018
           read                 0           1             3,678             3,678
           syscall_3300         3300        1             3,307,096         3,307,096
           read                 0           1             3,207,760         3,207,760
           read                 0           1             1,617             1,617
           syscall_2091         2091        1             3,243,401         3,243,401
           read                 0           1             3,206,757         3,206,757
           read                 0           1             1,463             1,463
           syscall_3968         3968        1             241,035           241,035
           syscall_1408         1408        1             367,034           367,034
           read                 0           1             341,442           341,442
           read                 0           1             1,617             1,617
           syscall_1833         1833        1             369,342           369,342
           read                 0           1             334,550           334,550
           write                1           1             7,623             7,623
           read                 0           1             2,816             2,816
           syscall_3300         3300        1             3,315,227         3,315,227
           read                 0           1             3,292,170         3,292,170
           read                 0           1             1,924             1,924
           syscall_2091         2091        1             3,249,290         3,249,290
           read                 0           1             3,203,605         3,203,605
           read                 0           1             1,507             1,507
           syscall_3968         3968        1             235,664           235,664
           syscall_1408         1408        1             370,696           370,696
           read                 0           1             334,456           334,456
           read                 0           1             1,580             1,580
           syscall_1833         1833        1             367,071           367,071
           read                 0           1             340,616           340,616
           write                1           1             7,205             7,205
           read                 0           1             2,866             2,866
           syscall_3300         3300        1             3,283,709         3,283,709
           read                 0           1             3,215,848         3,215,848
           read                 0           1             1,661             1,661
           syscall_2091         2091        1             3,251,032         3,251,032
           read                 0           1             3,201,202         3,201,202
           read                 0           1             1,467             1,467
           syscall_3968         3968        1             237,682           237,682
           syscall_1408         1408        1             372,576           372,576
           read                 0           1             334,710           334,710
           read                 0           1             1,503             1,503
           syscall_1833         1833        1             367,422           367,422
           read                 0           1             340,726           340,726
           write                1           1             6,929             6,929
           syscall_4294967274   4294967274  1             2,873             2,873
           write                1           1             4,085             4,085
           syscall_4294967274   4294967274  1             3,461             3,461
           write                1           1             3,758             3,758
           syscall_4294967274   4294967274  1             3,284             3,284
           write                1           1             3,621             3,621
           read                 0           1             3,267             3,267
           syscall_3300         3300        1             3,317,805         3,317,805
           read                 0           1             3,202,868         3,202,868
           read                 0           1             1,700             1,700
           syscall_2091         2091        1             3,251,250         3,251,250
           read                 0           1             3,201,616         3,201,616
           read                 0           1             1,473             1,473
           syscall_3968         3968        1             240,585           240,585
           syscall_1408         1408        1             373,709           373,709
           read                 0           1             335,038           335,038
           read                 0           1             1,556             1,556
           syscall_1833         1833        1             370,061           370,061
           read                 0           1             342,073           342,073
           TOTAL( - poll):                                       342,073

           [SOFT IRQ STATISTICS]
           NAME                 VECT_NR     COUNT         TOTAL ns          MAX ns
           SCHED                7           1             3,705             3,705
           TIMER                1           1             7,123             7,123
           SCHED                7           1             6,371             6,371
           SCHED                7           1             3,511             3,511
           SCHED                7           1             6,063             6,063
           RCU                  9           1             1,436             1,436
           SCHED                7           1             5,999             5,999
           TOTAL:                                                7                 34,208
3491       tailscaled       [SYSCALL STATISTICS]
           NAME                 NUMBER      COUNT         TOTAL ns          MAX ns
           syscall_4294967274   4294967274  1             4,657             4,657
           read                 0           1             14,114            14,114
           TOTAL( - poll):                                       14,114

           [SOFT IRQ STATISTICS]
           NAME                 VECT_NR     COUNT         TOTAL ns          MAX ns
           SCHED                7           1             7,089             7,089
           TOTAL:                                                1                 7,089
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