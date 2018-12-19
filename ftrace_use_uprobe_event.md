uprobe是用户态的探针，它和kprobe是相对应的，kprobe是内核态的探针。uprobe需要制定用户态探针在执行文件中的位置，插入探针的原理和kprobe类似。

参考原文：[Uprobe-tracer: Uprobe-based Event Tracing](https://www.kernel.org/doc/html/latest/trace/uprobetracer.html)

# 1、Overview

uprobe event类似于kprobe event。在编译内核时配置CONFIG_UPROBE_EVENTS=y使能这个特性。

它的active不是通过current_tracer接口，而是通过“/sys/kernel/debug/tracing/uprobe_events”来增加probe points，通过“/sys/kernel/debug/tracing/events/uprobes/<EVENT>/enabled”来使能。

然而和kprobe event不同，uprobe event期望用户计算probepoint在目标中的偏移。

# 2、Synopsis of uprobe_tracer

增加/删除event的命令格式：

```
p[:[GRP/]EVENT] PATH:OFFSET [FETCHARGS] : Set a uprobe
r[:[GRP/]EVENT] PATH:OFFSET [FETCHARGS] : Set a return uprobe (uretprobe)
-:[GRP/]EVENT                           : Clear uprobe or uretprobe event

GRP           : Group name. If omitted, "uprobes" is the default value.
EVENT         : Event name. If omitted, the event name is generated based
                on PATH+OFFSET.
PATH          : Path to an executable or a library.
OFFSET        : Offset where the probe is inserted.

FETCHARGS     : Arguments. Each probe can have up to 128 args.
 %REG         : Fetch register REG
 @ADDR        : Fetch memory at ADDR (ADDR should be in userspace)
 @+OFFSET     : Fetch memory at OFFSET (OFFSET from same file as PATH)
 $stackN      : Fetch Nth entry of stack (N >= 0)
 $stack       : Fetch stack address.
 $retval      : Fetch return value.(*)
 $comm        : Fetch current task comm.
 +|-offs(FETCHARG) : Fetch memory at FETCHARG +|- offs address.(**)
 NAME=FETCHARG     : Set NAME as the argument name of FETCHARG.
 FETCHARG:TYPE     : Set TYPE as the type of FETCHARG. Currently, basic types
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

# 3、Event Profiling

你可以通过/sys/kernel/debug/tracing/uprobe_profile查看所有kprobe event的命中和miss情况。第一列是event name，第二列是probe hits计数，第三列是probe miss-hits计数。

# 4、Usage examples

- 增加一个新的uprobe event，命令如下(在可执行文件/bin/bash的0x4245c0偏移处增加一个uprobe探针)：

    ```
    echo 'p /bin/bash:0x4245c0' > /sys/kernel/debug/tracing/uprobe_events
    ```

- 增加一个uretprobe event：

    ```
    echo 'r /bin/bash:0x4245c0' > /sys/kernel/debug/tracing/uprobe_events
    ```

- 删除一个已注册的event：

    ```
    echo '-:p_bash_0x4245c0' >> /sys/kernel/debug/tracing/uprobe_events
    ```

- 打印出所有已注册的events：

    ```
    cat /sys/kernel/debug/tracing/uprobe_events
    ```

- 清除掉所有的events：
    
    ```
    echo > /sys/kernel/debug/tracing/uprobe_events
    ```

以下的例子展示怎么找到probe位置的地址，dump其instruction pointer 和 %ax register，探测/bin/zsh中的zfree函数：

```
# cd /sys/kernel/debug/tracing/
# cat /proc/`pgrep zsh`/maps | grep /bin/zsh | grep r-xp
00400000-0048a000 r-xp 00000000 08:03 130904 /bin/zsh
# objdump -T /bin/zsh | grep -w zfree
0000000000446420 g    DF .text  0000000000000012  Base        zfree
```

0x46420是zfree在/bin/zsh中的偏移，/bin/zsh的内存加载地址为0x00400000。因此命令为：

```
# echo 'p:zfree_entry /bin/zsh:0x46420 %ip %ax' > uprobe_events
```

同样的uretprobe为：

```
# echo 'r:zfree_exit /bin/zsh:0x46420 %ip %ax' >> uprobe_events
```

注意：用户必须明确的计算对象中的探测点的偏移量

我们可以看到已经注册的events：

```
# cat uprobe_events
p:uprobes/zfree_entry /bin/zsh:0x00046420 arg1=%ip arg2=%ax
r:uprobes/zfree_exit /bin/zsh:0x00046420 arg1=%ip arg2=%ax
```

可以从 events/uprobes/zfree_entry/format中查看event的输出格式：

```
# cat events/uprobes/zfree_entry/format
name: zfree_entry
ID: 922
format:
     field:unsigned short common_type;         offset:0;  size:2; signed:0;
     field:unsigned char common_flags;         offset:2;  size:1; signed:0;
     field:unsigned char common_preempt_count; offset:3;  size:1; signed:0;
     field:int common_pid;                     offset:4;  size:4; signed:1;
     field:int common_padding;                 offset:8;  size:4; signed:1;

     field:unsigned long __probe_ip;           offset:12; size:4; signed:0;
     field:u32 arg1;                           offset:16; size:4; signed:0;
     field:u32 arg2;                           offset:20; size:4; signed:0;

print fmt: "(%lx) arg1=%lx arg2=%lx", REC->__probe_ip, REC->arg1, REC->arg2
```
    
定义以后，使能所有的events：

```
# echo 1 > events/uprobes/enable
```

sleep以后，disable events：

```
# sleep 20
# echo 0 > events/uprobes/enable
```

还可以通过/sys/kernel/debug/tracing/trace文件查看trace信息：

```
# cat trace
# tracer: nop
#
#           TASK-PID    CPU#    TIMESTAMP  FUNCTION
#              | |       |          |         |
             zsh-24842 [006] 258544.995456: zfree_entry: (0x446420) arg1=446420 arg2=79
             zsh-24842 [007] 258545.000270: zfree_exit:  (0x446540 <- 0x446420) arg1=446540 arg2=0
             zsh-24842 [002] 258545.043929: zfree_entry: (0x446420) arg1=446420 arg2=79
             zsh-24842 [004] 258547.046129: zfree_exit:  (0x446540 <- 0x446420) arg1=446540 arg2=0
```

输出显示给我们uprobe被触发时：pid 24842、ip 0x446420、ax register 79，uretprobe被触发时：ip at 0x446540从函数入口0x446420返回。


# 参考资料

[1、Uprobe-tracer: Uprobe-based Event Tracing](https://www.kernel.org/doc/html/latest/trace/uprobetracer.html)
