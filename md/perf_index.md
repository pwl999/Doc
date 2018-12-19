

## 1、内核态解析:

# [1.1、perf_event内核框架](./perf_event_architecture.md)

# [1.2、tracepoint events](./perf_tracepoint_events.md)

# [1.3、software events ](./perf_software_events.md)

# [1.4、hardware events](./perf_hardware_events.md)


## 2、用户态解析:

# [2.1、simpleperf](./perf_simpleperf.md)


perf工作的基础是trace数据的采集和分析，但是当铺天盖地的trace数据采集上来的时候该如何分析？答案是具体数据具体分析。  

perf在trace数据分析方面取得了很多成果，针对一系列具体场景给出了具体的分析工具(子命令)：

- perf list。
- perf stat。
- perf record/report。

perf的trace数据采集方面，既复用了ftrace的插桩法，还引入了采样法(硬件PMU)。可以从更多维度来提供trace数据。

因为perf原生的用户态工具(kerneldir/tools/perf)交叉编译出错较多，用户态源码分析改用android简化版simpleperf来分析。

> 本文如果不作说明，默认采用kernel 4.4的代码进行解析。

