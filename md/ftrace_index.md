
## 1、Ftrace原理和代码分析:

# [1.1、ring buffer](./ftrace_ringbuffer.md)

# [1.2、trace event](./ftrace_trace_event.md)

# [1.3、tracer (function、function_graph、irq_off) ](./ftrace_tracer.md)

# [1.4、kprobe event](./ftrace_kprobe_event.md)

# [1.5、syscall event](./ftrace_syscall_event.md)

## 2、Ftrace的使用指南:

# [2.1、ftrace的使用](./ftrace_use_ftrace.md)

# [2.2、trace event的使用](./ftrace_use_trace_event.md)

# [2.3、kprobe event的使用](./ftrace_use_kprobe_event.md)

# [2.4、uprobe event的使用](./ftrace_use_uprobe_event.md)

Ftrace从字面上理解=Function trace，但是发展到现在已经不仅仅是function trace而是一个大集合，鉴于其搭建的良好的框架(ringbuffer、tracefs...)，各种trace纷纷投奔而来。现在大概分为两大类：tracer、event。

- tracer。发展出了function tracer、function_graph tracer、irqsoff tracer、preemptoff tracer、wakeup tracer等一系列tracer。
- event。也发展出trace event、kprobe event、uprobe event、syscall event等一系列的event。

trace采集数据的手段归根到底就两种：插桩、采样。ftrace是插桩法的集大成者，各种trace为了插桩使出了浑身解数给出了花样百变的插桩方法。

这里的**Ftrace**指的是，代码在"kernel/trace"目录下、操作路径在"/sys/kernel/debug/tracing"下的所有trace的集合。

> 本文如果不作说明，默认采用kernel 4.4的代码进行解析。



