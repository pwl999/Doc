
原始的trace event插桩是静态的：使用TRACE_EVENT()定义tracepoint，并且在代码中显式调用tracepoint。而kprobe机制可以实现在内核运行时动态的插桩，利用kprobe机制我们可以动态的插入trace event，实现和静态trace event同样的功能。

参考原文：[Kprobe-based Event Tracing](https://www.kernel.org/doc/html/latest/trace/kprobetrace.html)

# 1、Overview

这些event和基于tracepoint的event非常类似，使用kprobe机制来替代tracepoint机制。所以它能够探测任何kprobe能探测到的地方(这意味着所有的函数除了那些使用__kprobes/nokprobe_inline注明和被NOKPROBE_SYMBOL标记的函数)。不像那些基于tracepoint的静态event，本event可以实现动态的增加和删除。

在编译内核时配置 CONFIG_KPROBE_EVENTS=y，使能这个特性。

类似event tracer，不需要通过current_tracer文件接口来激活。取而代之的是，增加probe点通过“/sys/kernel/debug/tracing/kprobe_events”接口，enable通过“/sys/kernel/debug/tracing/events/kprobes/<EVENT>/enabled”接口。

# 2、Synopsis of kprobe_events

增加/删除kprobe event的命令格式：

```
 p[:[GRP/]EVENT] [MOD:]SYM[+offs]|MEMADDR [FETCHARGS]  : Set a probe
 r[MAXACTIVE][:[GRP/]EVENT] [MOD:]SYM[+0] [FETCHARGS]  : Set a return probe
 -:[GRP/]EVENT                                         : Clear a probe

GRP            : Group name. If omitted, use "kprobes" for it.
EVENT          : Event name. If omitted, the event name is generated
                 based on SYM+offs or MEMADDR.
MOD            : Module name which has given SYM.
SYM[+offs]     : Symbol+offset where the probe is inserted.
MEMADDR        : Address where the probe is inserted.
MAXACTIVE      : Maximum number of instances of the specified function that
                 can be probed simultaneously, or 0 for the default value
                 as defined in Documentation/kprobes.txt section 1.3.1.

FETCHARGS      : Arguments. Each probe can have up to 128 args.
 %REG          : Fetch register REG
 @ADDR         : Fetch memory at ADDR (ADDR should be in kernel)
 @SYM[+|-offs] : Fetch memory at SYM +|- offs (SYM should be a data symbol)
 $stackN       : Fetch Nth entry of stack (N >= 0)
 $stack        : Fetch stack address.
 $retval       : Fetch return value.(*)
 $comm         : Fetch current task comm.
 +|-offs(FETCHARG) : Fetch memory at FETCHARG +|- offs address.(**)
 NAME=FETCHARG : Set NAME as the argument name of FETCHARG.
 FETCHARG:TYPE : Set TYPE as the type of FETCHARG. Currently, basic types
                 (u8/u16/u32/u64/s8/s16/s32/s64), hexadecimal types
                 (x8/x16/x32/x64), "string" and bitfield are supported.

 (*) only for return probe.
 (**) this is useful for fetching a field of data structures.
```

## 2.1、Types

在"fetch-args"中支持一系列的types，Kprobe tracer能够使用给定的type来存取内存。

-  ‘s’ 、‘u’前缀：分别表明signed、unsigned；
-  ‘x’前缀：意味着unsigned；
-  数字：十进制(‘s’ and ‘u’) ，16进制(‘x’)。没有类型固定，数字使用‘x32’还是‘x64’取决于架构(x86-32 uses x32, and x86-64 uses x64)；
-  字符串：将会在内存中读取一个“null-terminated”的字符串。
-  Bitfield：有3个参数bit-width, bit- offset, container-size (usually 32).
    
    ```
    b<bit-width>@<bit-offset>/<container-size>
    ```

对“$comm”，默认是“string”类型，其他类型非法。

# 3、Per-Probe Event Filtering

每个probe event也支持filter功能，允许你设置不同的filter并给出跟trace buffer中显示的参数。  
如果你使用了“‘p:’ or ‘r:’+event name” > kprobe_events命令，新的kprobe event将会被添加，可以看到新event对应的文件夹tracing/events/kprobes/<EVENT>，包含‘id’, ‘enabled’, ‘format’ and ‘filter’文件。

- enabled: enable/disbale这个kprobe event；
- format: 打印出这个event的trace格式；
- filter: 可以对这个event配置filter规则；
- id: event对应的id

# 4、Event Profiling

你可以通过/sys/kernel/debug/tracing/kprobe_profile查看所有kprobe event的命中和miss情况。第一列是event name，第二列是probe hits计数，第三列是probe miss-hits计数。

# 5、Usage examples

通过向kprobe_events写入命令来增加新的kprobe event：

```
echo 'p:myprobe do_sys_open dfd=%ax filename=%dx flags=%cx mode=+4($stack)' > /sys/kernel/debug/tracing/kprobe_events
```
上述在do_sys_open()函数之上创建一个kprobe，对应的“myprobe” event用来记录4个参数的。

注意：寄存器/堆栈怎么分配给函数的参数依赖于架构ABI的定义，如果你不确定ABI，可以使用 perf-tools的probe子命令。如本例所示，用户可以为每个参数选择更熟悉的名称。

```
echo 'r:myretprobe do_sys_open $retval' >> /sys/kernel/debug/tracing/kprobe_events
```

上述在do_sys_open()函数非返回点设置了一个kretprobe，对应的“myretprobe” event用来记录返回值。可以通过“ /sys/kernel/debug/tracing/events/kprobes/<EVENT>/format”查看event的输出格式。

```
cat /sys/kernel/debug/tracing/events/kprobes/myprobe/format
name: myprobe
ID: 780
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3; size:1;signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:unsigned long __probe_ip; offset:12;      size:4; signed:0;
        field:int __probe_nargs;        offset:16;      size:4; signed:1;
        field:unsigned long dfd;        offset:20;      size:4; signed:0;
        field:unsigned long filename;   offset:24;      size:4; signed:0;
        field:unsigned long flags;      offset:28;      size:4; signed:0;
        field:unsigned long mode;       offset:32;      size:4; signed:0;


print fmt: "(%lx) dfd=%lx filename=%lx flags=%lx mode=%lx", REC->__probe_ip,
REC->dfd, REC->filename, REC->flags, REC->mode
```

你可以看到表达式中描述的4个参数。

```
echo > /sys/kernel/debug/tracing/kprobe_events
```

这个命令可以清除所有的probe points。或者清除选择的probe points：

```
echo -:myprobe >> kprobe_events
```

在定义以后，所有的event模式时disable状态。在tracing时，需要enbale：

```
echo 1 > /sys/kernel/debug/tracing/events/kprobes/myprobe/enable
echo 1 > /sys/kernel/debug/tracing/events/kprobes/myretprobe/enable
```

可以在/sys/kernel/debug/tracing/trace文件中看到trace信息：

```
cat /sys/kernel/debug/tracing/trace
# tracer: nop
#
#           TASK-PID    CPU#    TIMESTAMP  FUNCTION
#              | |       |          |         |
           <...>-1447  [001] 1038282.286875: myprobe: (do_sys_open+0x0/0xd6) dfd=3 filename=7fffd1ec4440 flags=8000 mode=0
           <...>-1447  [001] 1038282.286878: myretprobe: (sys_openat+0xc/0xe <- do_sys_open) $retval=fffffffffffffffe
           <...>-1447  [001] 1038282.286885: myprobe: (do_sys_open+0x0/0xd6) dfd=ffffff9c filename=40413c flags=8000 mode=1b6
           <...>-1447  [001] 1038282.286915: myretprobe: (sys_open+0x1b/0x1d <- do_sys_open) $retval=3
           <...>-1447  [001] 1038282.286969: myprobe: (do_sys_open+0x0/0xd6) dfd=ffffff9c filename=4041c6 flags=98800 mode=10
           <...>-1447  [001] 1038282.286976: myretprobe: (sys_open+0x1b/0x1d <- do_sys_open) $retval=3
```
每一行代表kernel命中event， <- SYMBOL代表kernel返回到SYMBOL(例如： “sys_open+0x1b/0x1d <- do_sys_open” 代表kernel从do_sys_open返回到sys_open+0x1b)


# 参考资料

[1、Kprobe-based Event Tracing](https://www.kernel.org/doc/html/latest/trace/kprobetrace.html)
[2、ARMv8 上的 kprobes 事件跟踪](https://linux.cn/article-9098-1.html)