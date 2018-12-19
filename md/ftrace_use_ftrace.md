关于Ftrace的使用，最权威的解读就在"Documentation/trace"文件夹下，我们挑选其中最经典的几个文件来进行翻译，加上自己理解的解读。

参考原文：[ftrace - Function Tracer](https://www.kernel.org/doc/html/latest/trace/ftrace.html)

# 1、背景：

Ftrace本来设计作为一个内部的tracer提供给系统的开发者和设计者，帮助他们弄清kernel正在发生的行为。它能够调试分析延迟和性能问题。

Ftrace发展到现在已经不仅仅是作为一个function tracer了，它实际上成为了一个通用的trace工具框架：

- 一方面tracer已经从function tracer扩展到irqsoff tracer(trace关中断时间)、preemptoff tracer等；
- 另一方面静态的trace event也成为trace的一个重要组成部分；

# 2、文件接口

整个trace对应的操作目录增加到/etc/fstab，在系统启动时挂载：

```
tracefs       /sys/kernel/tracing       tracefs defaults        0       0
```

或者运行时手工挂载：

```
mount -t tracefs nodev /sys/kernel/tracing
```

在4.1版本以前的，trace目录在以下路径：

```
/sys/kernel/debug/tracing
```

我们用列表来遍历“tracing/”文件夹下每一个文件的作用和描述：

<table border="1">
<caption> tracing/ </caption>


<tr>
<th style="width: 100px;">file</th>
<th style="width: 300px;">Description</th>
<th style="width: 100px;">所属模块</th>
<th style="width: 300px;">说明</th>
</tr>


<tr>
<td> current_tracer </td>
<td>
This is used to set or display the current tracer that is configured.
</td>
<td> tracer_comm </td>
<td>
显示当前使用的tracer，默认是nop。
<pre>
 # cat current_tracer
nop
</pre>
</td>
</tr>


<tr>
<td> available_tracers </td>
<td>
This holds the different types of tracers that have been compiled into the kernel. The tracers listed here can be configured by echoing their name into current_tracer.
</td>
<td> tracer_comm </td>
<td>
列出当前已经注册的tracer
<pre>
 # cat available_tracers
blk function_graph preemptirqsoff preemptoff irqsoff function nop
</pre>
</td>
</tr>


<tr>
<td> tracing_on </td>
<td>
This sets or displays whether writing to the trace ring buffer is enabled. Echo 0 into this file to disable the tracer or 1 to enable it. Note, this only disables writing to the ring buffer, the tracing overhead may still be occurring.<br/>
The kernel function tracing_off() can be used within the kernel to disable writing to the ring buffer, which will set this file to “0”. User space can re-enable tracing by echoing “1” into the file.<br/>
Note, the function and event trigger “traceoff” will also set this file to zero and stop tracing. Which can also be re-enabled by user space using this file.
</td>
<td> ring buffer </td>
<td>
0: disable ring buffer<br/>
1: enable ring buffer<br/>
这个仅仅只是禁止数据写入ring buffer，但是各种桩函数还是被调用，trace动作仍然发生，开销依然存在。
</td>
</tr>


<tr>
<td> trace </td>
<td>
This file holds the output of the trace in a human readable format (described below). Note, tracing is temporarily disabled while this file is being read (opened).
</td>
<td> comm </td>
<td>
该文件把ringbuffer数据输出成用户可读的格式。<br/><br/>
注意：在这个文件open时，ring buffer是临时关闭的。<br/>
读操作并不会清除掉ring buffer中的数据，可以重复读；
</td>
</tr>


<tr>
<td> trace_pipe </td>
<td>
The output is the same as the “trace” file but this file is meant to be streamed with live tracing. Reads from this file will block until new data is retrieved. Unlike the “trace” file, this file is a consumer. This means reading from this file causes sequential reads to display more current data. Once data is read from this file, it is consumed, and will not be read again with a sequential read. The “trace” file is static, and if the tracer is not adding more data, it will display the same information every time it is read. This file will not disable tracing while being read.
</td>
<td> comm </td>
<td>
文件内容和“trace”文件是一样的，区别在于：<br/><br/>
1、并行读，读操作不会disable写操作；<br/>
2、只支持读一次，该读操作会清除掉ring buffer中的数据，再次去读没有内容了；
</td>
</tr>


<tr>
<td> trace_options </td>
<td>
This file lets the user control the amount of data that is displayed in one of the above output files. Options also exist to modify how a tracer or events work (stack traces, timestamps, etc).
</td>
<td> comm </td>
<td>
一些通用的trace相关的option。
<pre>
 # cat trace_options
print-parent
nosym-offset
nosym-addr
noverbose
noraw
nohex
nobin
noblock
trace_printk
annotate
nouserstacktrace
nosym-userobj
noprintk-msg-only
context-info
nolatency-format
record-cmd
overwrite
nodisable_on_free
irq-info
markers
function-trace
nodisplay-graph
nostacktrace
noprint-tgid
notest_nop_accept
</pre>
echo xxx > trace_options    // enable xxx option<br/>
echo noxxx > trace_options  // disable xxx option<br/>
</td>
</tr>


<tr>
<td> options </td>
<td>
This is a directory that has a file for every available trace option (also in trace_options). Options may also be set or cleared by writing a “1” or “0” respectively into the corresponding file with the option name.
</td>
<td> tracer_comm </td>
<td>
"options"是一个文件夹，包含了所有注册的tracer可配置的option。
<pre>
 # ls options/
annotate
bin
blk_classic
block
context-info
disable_on_free
display-graph
func_stack_trace
funcgraph-abstime
funcgraph-cpu
funcgraph-duration
funcgraph-flat
funcgraph-irqs
funcgraph-overhead
funcgraph-overrun
funcgraph-proc
funcgraph-tail
function-trace
graph-time
hex
irq-info
latency-format
markers
overwrite
print-parent
print-tgid
printk-msg-only
raw
record-cmd
sleep-time
stacktrace
sym-addr
sym-offset
sym-userobj
test_nop_accept
test_nop_refuse
trace_printk
userstacktrace
verbose
</pre>
echo 1 > options/xxx    // enable xxx tracer option<br/>
echo 0 > options/xxx    // disable xxx tracer option<br/>
</td>
</tr>


<tr>
<td> tracing_max_latency </td>
<td>
Some of the tracers record the max latency. For example, the maximum time that interrupts are disabled. The maximum time is saved in this file. The max trace will also be stored, and displayed by “trace”. A new max trace will only be recorded if the latency is greater than the value in this file (in microseconds).<br/><br/>
By echoing in a time into this file, no latency will be recorded unless it is greater than the time in this file.
</td>
<td> tracer_comm </td>
<td>
某些tracer用来记录最大latency。例如，最大中断disable时间。<br/>
最大时间被记录到本文件，对应的trace被记录到“trace”文件。<br/>
新的trace最有大于现在的max latency胡，才会被记录。<br/><br/>
echo xxx > tracing_max_latency // 手工设置一个门限，只有大于门限才会被记录。<br/>
</td>
</tr>


<tr>
<td> tracing_thresh </td>
<td>
Some latency tracers will record a trace whenever the latency is greater than the number in this file. Only active when the file contains a number greater than 0. (in microseconds)
</td>
<td> tracer_comm </td>
<td>
有一些latency tracers判断latency大于本文件的标值才会被记录。只有值大于0才会被激活。
</td>
</tr>


<tr>
<td> buffer_size_kb </td>
<td>
This sets or displays the number of kilobytes each CPU buffer holds. By default, the trace buffers are the same size for each CPU. The displayed number is the size of the CPU buffer and not total size of all buffers. The trace buffers are allocated in pages (blocks of memory that the kernel uses for allocation, usually 4 KB in size). If the last page allocated has room for more bytes than requested, the rest of the page will be used, making the actual allocation bigger than requested or shown. ( Note, the size may not be a multiple of the page size due to buffer management meta-data. )<br/><br/>

Buffer sizes for individual CPUs may vary (see “per_cpu/cpu0/buffer_size_kb” below), and if they do this file will show “X”.
</td>
<td> ring buffer </td>
<td>
设置ring buffer在每个cpu上的大小。<br/><br/>
默认在每个cpu上大小都是相等的，如果显示“X”，查看“per_cpu/cpu0/buffer_size_kb”具体每个cpu的大小。
<pre>
 # cat buffer_size_kb
1410
</pre>
</td>
</tr>


<tr>
<td> buffer_total_size_kb </td>
<td>
This displays the total combined size of all the trace buffers.
</td>
<td> ring buffer </td>
<td>
ring buffer总的的大小
<pre>
 # cat buffer_total_size_kb
11280
</pre>
</td>
</tr>


<tr>
<td> free_buffer </td>
<td>
If a process is performing tracing, and the ring buffer should be shrunk “freed” when the process is finished, even if it were to be killed by a signal, this file can be used for that purpose. On close of this file, the ring buffer will be resized to its minimum size. Having a process that is tracing also open this file, when the process exits its file descriptor for this file will be closed, and in doing so, the ring buffer will be “freed”.<br/><br/>

It may also stop tracing if disable_on_free option is set.
</td>
<td> ring buffer </td>
<td>
本文件用来控制ring buffer的free，当free时ring buffer被resize到它的最小尺寸。<br/><br/>
使用方法：<br/>
当进程不需要使用ring buffer了，他open“free_buffer”并且close文件，ring buffer会被resize到最小尺寸。
</td>
</tr>


<tr>
<td> tracing_cpumask </td>
<td>
This is a mask that lets the user only trace on specified CPUs. The format is a hex string representing the CPUs.
</td>
<td> ring buffer </td>
<td>
独立控制在每个cpu上是否开trace功能。
<pre>
 # cat tracing_cpumask
ff
</pre>
</td>
</tr>


<tr>
<td> set_ftrace_filter </td>
<td>
When dynamic ftrace is configured in (see the section below “dynamic ftrace”), the code is dynamically modified (code text rewrite) to disable calling of the function profiler (mcount). This lets tracing be configured in with practically no overhead in performance. This also has a side effect of enabling or disabling specific functions to be traced. Echoing names of functions into this file will limit the trace to only those functions.<br/><br/>

The functions listed in “available_filter_functions” are what can be written into this file.<br/><br/>

This interface also allows for commands to be used. See the “Filter commands” section for more details.<br/><br/>
</td>
<td> tracer_function </td>
<td>
function tracer的filter。<br/>
dynamic ftrace是通过动态修改函数代码来插入桩函数的，这让对没有被trace的函数的影响降到了最低。<br/><br/>
需要使用dynamic ftrace跟踪哪些函数：echo 函数名 > set_ftrace_filter
<pre>
 # cat set_ftrace_filter
 #### all functions enabled ####
 # echo schedule &gt; set_ftrace_filter
 # cat set_ftrace_filter
schedule
 # echo scheduler_tick &gt;&gt; set_ftrace_filter
 # cat set_ftrace_filter
scheduler_tick
schedule
</pre>
</td>
</tr>


<tr>
<td> set_ftrace_notrace </td>
<td>
This has an effect opposite to that of set_ftrace_filter. Any function that is added here will not be traced. If a function exists in both set_ftrace_filter and set_ftrace_notrace, the function will _not_ be traced.
</td>
<td> tracer_function </td>
<td>
function tracer的filter。<br/>
和“set_ftrace_filter”的作用相反，设置哪些函数不要被trace。<br/><br/>
如果同一函数在“set_ftrace_filter”和“set_ftrace_notrace”中同时被设置，效果等同于没有trace。
<pre>
 # cat set_ftrace_notrace
 #### no functions disabled ####
</pre>
</td>
</tr>


<tr>
<td> set_ftrace_pid </td>
<td>
Have the function tracer only trace the threads whose PID are listed in this file.<br/><br/>

If the “function-fork” option is set, then when a task whose PID is listed in this file forks, the child’s PID will automatically be added to this file, and the child will be traced by the function tracer as well. This option will also cause PIDs of tasks that exit to be removed from the file.
</td>
<td> tracer_function </td>
<td>
function tracer的filter。<br/>
function tracer只追踪这个文件描述的PID。
<pre>
 # cat set_ftrace_pid
no pid
</pre>
</td>
</tr>

<tr>
<td> set_event_pid </td>
<td>
Have the events only trace a task with a PID listed in this file. Note, sched_switch and sched_wake_up will also trace events listed in this file.<br/><br/>

To have the PIDs of children of tasks with their PID in this file added on fork, enable the “event-fork” option. That option will also cause the PIDs of tasks to be removed from this file when the task exits.
</td>
<td> trace_event </td>
<td>
trace event的filter。<br/>
只有本文件描述的PID的进程，才会记录其trace event。
</td>
</tr>


<tr>
<td> set_graph_function </td>
<td>
Functions listed in this file will cause the function graph tracer to only trace these functions and the functions that they call. (See the section “dynamic ftrace” for more details).
</td>
<td> tracer_function_graph </td>
<td>
function graph tracer的filter。<br/>
function graph tracer仅仅trace在本文件中描述的函数。
</td>
</tr>


<tr>
<td> set_graph_notrace </td>
<td>
Similar to set_graph_function, but will disable function graph tracing when the function is hit until it exits the function. This makes it possible to ignore tracing functions that are called by a specific function.
</td>
<td> tracer_function_graph </td>
<td>
function graph tracer的filter。<br/>
和“set_graph_function”功能相反，function graph tracer不trace在本文件中描述的函数。
</td>
</tr>


<tr>
<td> available_filter_functions </td>
<td>
This lists the functions that ftrace has processed and can trace. These are the function names that you can pass to “set_ftrace_filter” or “set_ftrace_notrace”. (See the section “dynamic ftrace” below for more details.)
</td>
<td> tracer_function、tracer_function_graph </td>
<td>
有效的可以被设置为filter的函数名。
</td>
</tr>


<tr>
<td> dyn_ftrace_total_info </td>
<td>
This file is for debugging purposes. The number of functions that have been converted to nops and are available to be traced.
</td>
<td> tracer_function </td>
<td>
该文件是调试目的，有多少个函数的桩函数被dynamic ftrace转换成nop可以被追踪。
<pre>
 # cat dyn_ftrace_total_info
49099
</pre>
</td>
</tr>


<tr>
<td> enabled_functions </td>
<td>
This file is more for debugging ftrace, but can also be useful in seeing if any function has a callback attached to it. Not only does the trace infrastructure use ftrace function trace utility, but other subsystems might too. This file displays all functions that have a callback attached to them as well as the number of callbacks that have been attached. Note, a callback may also call multiple functions which will not be listed in this count.<br/><br/>

If the callback registered to be traced by a function with the “save regs” attribute (thus even more overhead), a ‘R’ will be displayed on the same line as the function that is returning registers.<br/><br/>

If the callback registered to be traced by a function with the “ip modify” attribute (thus the regs->ip can be changed), an ‘I’ will be displayed on the same line as the function that can be overridden.<br/><br/>

If the architecture supports it, it will also show what callback is being directly called by the function. If the count is greater than 1 it most likely will be ftrace_ops_list_func().<br/><br/>

If the callback of the function jumps to a trampoline that is specific to a the callback and not the standard trampoline, its address will be printed as well as the function that the trampoline calls.
</td>
<td> tracer_function </td>
<td>
该文件用来调试ftrace的，它可以显示所有attach了回调函数的函数。
<pre>
 # cat set_ftrace_filter
scheduler_tick
schedule
 # echo function > current_tracer
 # cat enabled_functions
scheduler_tick (1)
schedule (1)
</pre>
</td>
</tr>


<tr>
<td> function_profile_enabled </td>
<td>
When set it will enable all functions with either the function tracer, or if configured, the function graph tracer. It will keep a histogram of the number of functions that were called and if the function graph tracer was configured, it will also keep track of the time spent in those functions. The histogram content can be displayed in the files:<br/><br/>

trace_stats/function<cpu> ( function0, function1, etc).
</td>
<td> tracer_function、tracer_function_graph </td>
<td>
开始统计功能
</td>
</tr>


<tr>
<td> trace_stats </td>
<td>
A directory that holds different tracing stats.
</td>
<td> tracer_function、tracer_function_graph </td>
<td>

</td>
</tr>


<tr>
<td> kprobe_events </td>
<td>
Enable dynamic trace points. See kprobetrace.txt.
</td>
<td> trace_event_kprobe </td>
<td>
通过kprobe动态的创建trace event。而通过TRACE_EVENT()宏定义的都是静态的trace event。
</td>
</tr>


<tr>
<td> kprobe_profile </td>
<td>
Dynamic trace points stats. See kprobetrace.txt.
</td>
<td> trace_event_kprobe </td>
<td>
kprobe trace_event的统计。
</td>
</tr>


<tr>
<td> max_graph_depth </td>
<td>
Used with the function graph tracer. This is the max depth it will trace into a function. Setting this to a value of one will show only the first kernel function that is called from user space.
</td>
<td> tracer_function_graph </td>
<td>
function graph tracer显示函数调用关系的层级。
</td>
</tr>


<tr>
<td> printk_formats </td>
<td>
This is for tools that read the raw format files. If an event in the ring buffer references a string, only a pointer to the string is recorded into the buffer and not the string itself. This prevents tools from knowing what that string was. This file displays the string and address for the string allowing tools to map the pointers to what the strings were.
</td>
<td> trace_printk </td>
<td>
使用trace_printk()打印数据的格式化字符串。<br/>
使用“trace”文件读取ringbuffer中trace_printk()打印的数据时，需要知道解析格式。这个文件保存了所有的trace_printk()的打印格式。
<pre>
 # more printk_formats
0x0 : "%u, %u\n"
0x0 : "%u, %u\n"
</pre>
</td>
</tr>


<tr>
<td> saved_cmdlines </td>
<td>
Only the pid of the task is recorded in a trace event unless the event specifically saves the task comm as well. Ftrace makes a cache of pid mappings to comms to try to display comms for events. If a pid for a comm is not listed, then “&lt;...&gt;” is displayed in the output.<br/><br/>

If the option “record-cmd” is set to “0”, then comms of tasks will not be saved during recording. By default, it is enabled.
</td>
<td> comm </td>
<td>
ftrace建立起了一个cache，用来记录进程“pid”和“comms”之间的映射关系，在输出时能根据pid快速查找到进程的comms。如果进程的comms没有缓冲，使用空白填充 “&lt;...&gt;” 。
<pre>
 # cat saved_cmdlines
19464 sensors.qcom
14 ksoftirqd/1
2164 Thread-6
7350 RxSchedulerPur
19419 kworker/1:2
547 kworker/2:1H
420 mmc-cmdqd/0
1775 PowerManagerSe
4710 HandlerThread[
2971 Binder:1569_8
1097 rild
2564 RILReceiver0
19465 rild
58 mpss_smem_glin
57 smem_native_mp
</pre>
</td>
</tr>


<tr>
<td> saved_cmdlines_size </td>
<td>
By default, 128 comms are saved (see “saved_cmdlines” above). To increase or decrease the amount of comms that are cached, echo in a the number of comms to cache, into this file.
</td>
<td> comm </td>
<td>
saved_cmdlines这块cache的大小
</td>
</tr>


<tr>
<td> saved_tgids </td>
<td>
If the option “record-tgid” is set, on each scheduling context switch the Task Group ID of a task is saved in a table mapping the PID of the thread to its TGID. By default, the “record-tgid” option is disabled.
</td>
<td> comm </td>
<td>
如果“record-tgid”选项被使能，PID对应的TGID映射也会被记录。
</td>
</tr>


<tr>
<td> snapshot </td>
<td>
This displays the “snapshot” buffer and also lets the user take a snapshot of the current running trace. See the “Snapshot” section below for more details.
</td>
<td> comm </td>
<td>
显示“snapshot”缓存中的内存，类似“trace”文件。<br/><br/>
snapshot对应一块独立的ring buffer，用来快照ring buffer中的内容。
</td>
</tr>


<tr>
<td> stack_max_size </td>
<td>
When the stack tracer is activated, this will display the maximum stack size it has encountered. See the “Stack Trace” section below.
</td>
<td> tracer_stack</td>
<td>
stack tracer遭遇到的最大的堆栈尺寸。
</td>
</tr>


<tr>
<td> stack_trace </td>
<td>
This displays the stack back trace of the largest stack that was encountered when the stack tracer is activated. See the “Stack Trace” section below.
</td>
<td> tracer_stack </td>
<td>
stack tracer遭遇到的最大的堆栈的具体的回调情况。
</td>
</tr>


<tr>
<td> stack_trace_filter </td>
<td>
This is similar to “set_ftrace_filter” but it limits what functions the stack tracer will check.
</td>
<td> tracer_stack </td>
<td>
stack tracer的filter。<br/>
指示哪些函数可以被stack tracer跟踪。
</td>
</tr>


<tr>
<td> trace_clock </td>
<td>
Whenever an event is recorded into the ring buffer, a “timestamp” is added. This stamp comes from a specified clock. By default, ftrace uses the “local” clock. This clock is very fast and strictly per cpu, but on some systems it may not be monotonic with respect to other CPUs. In other words, the local clocks may not be in sync with local clocks on other CPUs.<br/><br/>

Usual clocks for tracing:<br/>

<pre>
 # cat trace_clock
[local] global counter x86-tsc
</pre>

The clock with the square brackets around it is the one in effect.<br/>
local:<br/>
    Default clock, but may not be in sync across CPUs<br/>
global:<br/>
    This clock is in sync with all CPUs but may be a bit slower than the local clock.<br/>
counter:<br/>
    This is not a clock at all, but literally an atomic counter. It counts up one by one, but is in sync with all CPUs. This is useful when you need to know exactly the order events occurred with respect to each other on different CPUs.<br/>
uptime:<br/>
    This uses the jiffies counter and the time stamp is relative to the time since boot up.<br/>
perf:<br/>
    This makes ftrace use the same clock that perf uses. Eventually perf will be able to read ftrace buffers and this will help out in interleaving the data.<br/>
x86-tsc:<br/>
    Architectures may define their own clocks. For example, x86 uses its own TSC cycle clock here.<br/>
ppc-tb:<br/>
    This uses the powerpc timebase register value. This is in sync across CPUs and can also be used to correlate events across hypervisor/guest if tb_offset is known.<br/>
mono:<br/>
    This uses the fast monotonic clock (CLOCK_MONOTONIC) which is monotonic and is subject to NTP rate adjustments.<br/>
mono_raw:<br/>
    This is the raw monotonic clock (CLOCK_MONOTONIC_RAW) which is montonic but is not subject to any rate adjustments and ticks at the same rate as the hardware clocksource.<br/>
boot:<br/>
    This is the boot clock (CLOCK_BOOTTIME) and is based on the fast monotonic clock, but also accounts for time spent in suspend. Since the clock access is designed for use in tracing in the suspend path, some side effects are possible if clock is accessed after the suspend time is accounted before the fast mono clock is updated. In this case, the clock update appears to happen slightly sooner than it normally would have. Also on 32-bit systems, it’s possible that the 64-bit boot offset sees a partial update. These effects are rare and post processing should be able to handle them. See comments in the ktime_get_boot_fast_ns() function for more information.<br/><br/>

To set a clock, simply echo the clock name into this file:<br/>

<pre>
 # echo global > trace_clock
</pre>
</td>
<td> ring buffer </td>
<td>
ring buffer记录时间戳所使用的时钟源。

<pre>
 # cat trace_clock
[local] global counter uptime perf mono mono_raw
</pre>
</td>
</tr>


<tr>
<td> trace_marker </td>
<td>
This is a very useful file for synchronizing user space with events happening in the kernel. Writing strings into this file will be written into the ftrace buffer.<br/>
It is useful in applications to open this file at the start of the application and just reference the file descriptor for the file:<br/>
<pre>
void trace_write(const char *fmt, ...)
{
        va_list ap;
        char buf[256];
        int n;

        if (trace_fd &lt; 0)
                return;

        va_start(ap, fmt);
        n = vsnprintf(buf, 256, fmt, ap);
        va_end(ap);

        write(trace_fd, buf, n);
}
</pre>
start:
<pre>
trace_fd = open("trace_marker", WR_ONLY);
</pre>
</td>
<td> ring buffer </td>
<td>
该文件运行用户态直接写内容到ring buffer，通常用来同步用户态和内核态的事件。
</td>
</tr>

<tr>
<td> trace_marker_raw </td>
<td>
This is similar to trace_marker above, but is meant for for binary data to be written to it, where a tool can be used to parse the data from trace_pipe_raw.
</td>
<td> ring buffer </td>
<td>
和“trace_marker”类似，但是写入的是二进制格式。工具可以解析数据通过“trace_pipe_raw”。
</td>
</tr>


<tr>
<td> uprobe_events </td>
<td>
Add dynamic tracepoints in programs. See uprobetracer.txt
</td>
<td> trace_event_uprobe </td>
<td>
通过uprobe动态的创建trace event。而通过TRACE_EVENT()宏定义的都是静态的trace event。
</td>
</tr>


<tr>
<td> uprobe_profile </td>
<td>
Uprobe statistics. See uprobetrace.txt
</td>
<td> trace_event_uprobe </td>
<td>
Uprobe的统计功能
</td>
</tr>


<tr>
<td> instances </td>
<td>
This is a way to make multiple trace buffers where different events can be recorded in different buffers. See “Instances” section below.
</td>
<td> ring buffer </td>
<td>
这是一个创建多个ring buffer的方法，可以让不同的events使用不同的ring buffer。
</td>
</tr>


<tr>
<td> events </td>
<td>
This is the trace event directory. It holds event tracepoints (also known as static tracepoints) that have been compiled into the kernel. It shows what event tracepoints exist and how they are grouped by system. There are “enable” files at various levels that can enable the tracepoints when a “1” is written to them.<br/><br/>

See events.txt for more information.
</td>
<td> trace_event </td>
<td>
trace event的文件夹，包含所有通过TRACE_EVENT()宏定义的静态event 和 通过kprobe、uprobe定义的动态event。
</td>
</tr>


<tr>
<td> set_event </td>
<td>
By echoing in the event into this file, will enable that event.<br/><br/>

See events.txt for more information.
</td>
<td> trace_event </td>
<td>
使能trace event。<br/><br/>

echo xxxevent &gt; set_event // enbale对应的xxxevent
</td>
</tr>


<tr>
<td> available_events </td>
<td>
A list of events that can be enabled in tracing.<br/><br/>

See events.txt for more information.
</td>
<td> trace_event </td>
<td>
列出所有有效的event。相当于“events”文件夹中所有event名字的集合。
</td>
</tr>


<tr>
<td> timestamp_mode </td>
<td>
Certain tracers may change the timestamp mode used when logging trace events into the event buffer. Events with different modes can coexist within a buffer but the mode in effect when an event is logged determines which timestamp mode is used for that event. The default timestamp mode is ‘delta’.<br/><br/>
Usual timestamp modes for tracing:
<pre>
 # cat timestamp_mode 
[delta] absolute
</pre>
The timestamp mode with the square brackets around it is the one in effect.<br/>
delta: Default timestamp mode - timestamp is a delta against a per-buffer timestamp.
absolute: The timestamp is a full timestamp, not a delta against some other value. As such it takes up more space and is less efficient.
</td>
<td> ring buffer </td>
<td>
配置ring buffer中的时间戳为delta mode还是absolute 模式。<br/>
</td>
</tr>


<tr>
<td> hwlat_detector </td>
<td>
Directory for the Hardware Latency Detector. See “Hardware Latency Detector” section below.
</td>
<td> comm </td>
<td>
Hardware Latency Detector文件夹
</td>
</tr>


<tr>
<td> per_cpu </td>
<td>
This is a directory that contains the trace per_cpu information.
</td>
<td> per_cpu </td>
<td>
per cpu的文件夹
</td>
</tr>


<tr>
<td> per_cpu/cpu0/buffer_size_kb </td>
<td>
The ftrace buffer is defined per_cpu. That is, there’s a separate buffer for each CPU to allow writes to be done atomically, and free from cache bouncing. These buffers may have different size buffers. This file is similar to the buffer_size_kb file, but it only displays or sets the buffer size for the specific CPU. (here cpu0).
</td>
<td> per_cpu </td>
<td>

</td>
</tr>


<tr>
<td> per_cpu/cpu0/trace </td>
<td>
This is similar to the “trace” file, but it will only display the data specific for the CPU. If written to, it only clears the specific CPU buffer.
</td>
<td> per_cpu </td>
<td>
单个cpu上的trace信息
</td>
</tr>


<tr>
<td> per_cpu/cpu0/trace_pipe </td>
<td>
This is similar to the “trace_pipe” file, and is a consuming read, but it will only display (and consume) the data specific for the CPU.
</td>
<td> per_cpu </td>
<td>
单个cpu上的trace_pipe信息
</td>
</tr>


<tr>
<td> per_cpu/cpu0/trace_pipe_raw </td>
<td>
For tools that can parse the ftrace ring buffer binary format, the trace_pipe_raw file can be used to extract the data from the ring buffer directly. With the use of the splice() system call, the buffer data can be quickly transferred to a file or to the network where a server is collecting the data.<br/><br/>

Like trace_pipe, this is a consuming reader, where multiple reads will always produce different data.
</td>
<td> per_cpu </td>
<td>
如果工具可以自己解析二进制数据，那么可以通过“trace_pipe_raw”文件来读取ring buffer数据，这样速度更快。类似于“trace_pipe”，也是一次性读。
</td>
</tr>


<tr>
<td> per_cpu/cpu0/snapshot </td>
<td>
This is similar to the main “snapshot” file, but will only snapshot the current CPU (if supported). It only displays the content of the snapshot for a given CPU, and if written to, only clears this CPU buffer.
</td>
<td> per_cpu </td>
<td>
单个cpu上的snapshot
</td>
</tr>


<tr>
<td> per_cpu/cpu0/snapshot_raw </td>
<td>
Similar to the trace_pipe_raw, but will read the binary format from the snapshot buffer for the given CPU.
</td>
<td> per_cpu </td>
<td>
单个cpu上的raw snapshot，返回二进制信息，由工具自己解析。
</td>
</tr>


<tr>
<td> per_cpu/cpu0/stats </td>
<td>
This displays certain stats about the ring buffer:<br/><br/>

entries:<br/>
    The number of events that are still in the buffer.<br/>
overrun:<br/>
    The number of lost events due to overwriting when the buffer was full.<br/>
commit overrun:<br/>
    Should always be zero. This gets set if so many events happened within a nested event (ring buffer is re-entrant), that it fills the buffer and starts dropping events.<br/>
bytes:<br/>
    Bytes actually read (not overwritten).<br/>
oldest event ts:<br/>
    The oldest timestamp in the buffer<br/>
now ts:<br/>
    The current timestamp<br/>
dropped events:<br/>
    Events lost due to overwrite option being off.<br/>
read events:<br/>
    The number of events read.<br/>
</td>
<td> per_cpu </td>
<td>
显示每个cpu的ring buffer统计：
<pre>
per_cpu/cpu0 # cat stats
entries: 243
overrun: 4268740
commit overrun: 0
bytes: 8144
oldest event ts: 94221.885584
now ts: 94222.755451
dropped events: 0
read events: 0
</pre>
</td>
</tr>

</table>


# 3、Tracers

目前支持的Tracer有以下这些：

<table border="1">
<caption> Tracer </caption>


<tr>
<th style="width: 200px;">Tracer</th>
<th style="width: 400px;">Description</th>
<th style="width: 400px;">说明</th>
</tr>


<tr>
<td> function </td>
<td>
Function call tracer to trace all kernel functions.
</td>
<td>
追踪所有的内核函数
</td>
</tr>


<tr>
<td> function_graph </td>
<td>
Similar to the function tracer except that the function tracer probes the functions on their entry whereas the function graph tracer traces on both entry and exit of the functions. It then provides the ability to draw a graph of function calls similar to C code source.
</td>
<td>
和“function tracer”比较类似，但它除了探测函数的入口还探测函数的出口。它可以画出一个图形化的函数调用，类似于c源代码风格。
</td>
</tr>


<tr>
<td> blk </td>
<td>
The block tracer. The tracer used by the blktrace user application.
</td>
<td>
块设备tracer
</td>
</tr>


<tr>
<td> hwlat </td>
<td>
The Hardware Latency tracer is used to detect if the hardware produces any latency. See “Hardware Latency Detector” section below.
</td>
<td>
用来侦测硬件产生的延迟。
</td>
</tr>


<tr>
<td> irqsoff </td>
<td>
Traces the areas that disable interrupts and saves the trace with the longest max latency. See tracing_max_latency. When a new max is recorded, it replaces the old trace. It is best to view this trace with the latency-format option enabled, which happens automatically when the tracer is selected.
</td>
<td>
追踪最大关闭中断时间。
</td>
</tr>


<tr>
<td> preemptoff </td>
<td>
Similar to irqsoff but traces and records the amount of time for which preemption is disabled.
</td>
<td>
追踪最大关闭抢占时间。
</td>
</tr>


<tr>
<td> preemptirqsoff </td>
<td>
Similar to irqsoff and preemptoff, but traces and records the largest time for which irqs and/or preemption is disabled.
</td>
<td>
追踪 关闭中断 and/or 关闭抢占 的最大时间。
</td>
</tr>


<tr>
<td> wakeup </td>
<td>
Traces and records the max latency that it takes for the highest priority task to get scheduled after it has been woken up. Traces all tasks as an average developer would expect.
</td>
<td>
追踪最高优先级普通任务从获得调度到被唤醒的最大延迟时间。
</td>
</tr>


<tr>
<td> wakeup_rt </td>
<td>
Traces and records the max latency that it takes for just RT tasks (as the current “wakeup” does). This is useful for those interested in wake up timings of RT tasks.
</td>
<td>
追踪RT类型的任务从获得调度到被唤醒的最大延迟时间。
</td>
</tr>


<tr>
<td> wakeup_dl </td>
<td>
Traces and records the max latency that it takes for a SCHED_DEADLINE task to be woken (as the “wakeup” and “wakeup_rt” does).
</td>
<td>
追踪Deadline类型的任务从获得调度到被唤醒的最大延迟时间。
</td>
</tr>


<tr>
<td> mmiotrace </td>
<td>
A special tracer that is used to trace binary module. It will trace all the calls that a module makes to the hardware. Everything it writes and reads from the I/O as well.
</td>
<td>
追踪硬件IO
</td>
</tr>


<tr>
<td> branch </td>
<td>
This tracer can be configured when tracing likely/unlikely calls within the kernel. It will trace when a likely and unlikely branch is hit and if it was correct in its prediction of being correct.
</td>
<td>
追踪likely/unlikely的分支预测情况
</td>
</tr>


<tr>
<td> nop </td>
<td>
This is the “trace nothing” tracer. To remove all tracers from tracing simply echo “nop” into current_tracer.
</td>
<td>
空的tracer
</td>
</tr>

</table>



# 4、Examples of using the tracer

接下来使用一系列的例子来演示tracer的使用，仅仅使用tracefs文件接口而不需要使用任何用户侧的工具。

## 4.1、Output format

以下是一个“trace”文件的输出实例：

```
# tracer: function
#
# entries-in-buffer/entries-written: 140080/250280   #P:4
#
#                              _-----=> irqs-off
#                             / _----=> need-resched
#                            | / _---=> hardirq/softirq
#                            || / _--=> preempt-depth
#                            ||| /     delay
#           TASK-PID   CPU#  ||||    TIMESTAMP  FUNCTION
#              | |       |   ||||       |         |
            bash-1977  [000] .... 17284.993652: sys_close <-system_call_fastpath
            bash-1977  [000] .... 17284.993653: __close_fd <-sys_close
            bash-1977  [000] .... 17284.993653: _raw_spin_lock <-__close_fd
            sshd-1974  [003] .... 17284.993653: __srcu_read_unlock <-fsnotify
            bash-1977  [000] .... 17284.993654: add_preempt_count <-_raw_spin_lock
            bash-1977  [000] ...1 17284.993655: _raw_spin_unlock <-__close_fd
            bash-1977  [000] ...1 17284.993656: sub_preempt_count <-_raw_spin_unlock
            bash-1977  [000] .... 17284.993657: filp_close <-__close_fd
            bash-1977  [000] .... 17284.993657: dnotify_flush <-filp_close
            sshd-1974  [003] .... 17284.993658: sys_select <-system_call_fastpath
            ....
```

- 首先在头部打印当前tracer的名字，这个例子里tracer是“function”；
- 然后打印"buffer中有多少个event/总共写了多少个entry"，两者的差值是丢失的entry(250280 - 140080 = 110200 events lost)。
- 每行的信息解析格式：进程名 “bash”, 进程PID “1977”, 运行的cpu “000”, latency format (explained below), 时间戳 <secs>.<usecs> format, 被trace的函数 “sys_close” 父函数 “system_call_fastpath”.。时间戳表示的是函数enter的时刻。

## 4.2、Latency trace format

“latency format”是trace文件的另一种典型的输出格式。当trace_option中“latency-format”选项被设置或者任何一种latency tracers被设置，trace文件输出了更多的信息来解释延迟的发生。

```
# tracer: irqsoff
#
# irqsoff latency trace v1.1.5 on 3.8.0-test+
# --------------------------------------------------------------------
# latency: 259 us, #4/4, CPU#2 | (M:preempt VP:0, KP:0, SP:0 HP:0 #P:4)
#    -----------------
#    | task: ps-6143 (uid:0 nice:0 policy:0 rt_prio:0)
#    -----------------
#  => started at: __lock_task_sighand
#  => ended at:   _raw_spin_unlock_irqrestore
#
#
#                  _------=> CPU#
#                 / _-----=> irqs-off
#                | / _----=> need-resched
#                || / _---=> hardirq/softirq
#                ||| / _--=> preempt-depth
#                |||| /     delay
#  cmd     pid   ||||| time  |   caller
#     \   /      |||||  \    |   /
      ps-6143    2d...    0us!: trace_hardirqs_off <-__lock_task_sighand
      ps-6143    2d..1  259us+: trace_hardirqs_on <-_raw_spin_unlock_irqrestore
      ps-6143    2d..1  263us+: time_hardirqs_on <-_raw_spin_unlock_irqrestore
      ps-6143    2d..1  306us : <stack trace>
 => trace_hardirqs_on_caller
 => trace_hardirqs_on
 => _raw_spin_unlock_irqrestore
 => do_task_stat
 => proc_tgid_stat
 => proc_single_show
 => seq_read
 => vfs_read
 => sys_read
 => system_call_fastpath
```

- 当前tracer是“irqsoff”，用来trace最大的中断关闭时间；
- trace version，kernel version(3.8)；
- 最大延迟时间(259 us)，多少条trace entries显示/总共多少条(both are four: #4/4)。VP, KP, SP, and HP一直为0保留使用。#P是多少个online的cpu(#P:4)；
- task是最大延迟发生所在的进程(ps pid: 6143)；
- start和stop的操作导致了延迟(本例中分布是关中断、开中断)：__lock_task_sighand 关中断，_raw_spin_unlock_irqrestore开中断；
- header以下的行是具体trace信息。包含以下字段：

<table border="1">
<caption> Latency trace format </caption>

<tr>
<th style="width: 200px;">field</th>
<th style="width: 400px;">Description</th>
<th style="width: 400px;">说明</th>
</tr>


<tr>
<td> cmd </td>
<td>
The name of the process in the trace.
</td>
<td>
进程名
</td>
</tr>

<tr>
<td> pid </td>
<td>
The PID of that process.
</td>
<td>
进程PID
</td>
</tr>

<tr>
<td> CPU# </td>
<td>
The CPU which the process was running on.
</td>
<td>
运行CPU
</td>
</tr>

<tr>
<td> irqs-off </td>
<td>
<pre>
‘d’ interrupts are disabled. 
‘.’ otherwise.
</pre>
</td>
<td>
中断是否disable：
<pre>
‘d’：中断disable；
‘.’：中断没有disable；
‘X’：架构不支持读取该信息
</pre>
</td>
</tr>

<tr>
<td> need-resched </td>
<td>
<pre>
‘N’ both TIF_NEED_RESCHED and PREEMPT_NEED_RESCHED is set,
‘n’ only TIF_NEED_RESCHED is set,
‘p’ only PREEMPT_NEED_RESCHED is set,
‘.’ otherwise.
</pre>
</td>
<td>
需要调度标志：
</td>
</tr>

<tr>
<td> hardirq/softirq </td>
<td>
<pre>
‘Z’ - NMI occurred inside a hardirq
‘z’ - NMI is running
‘H’ - hard irq occurred inside a softirq.
‘h’ - hard irq is running
‘s’ - soft irq is running
‘.’ - normal context.
</pre>
</td>
<td>
当前所处中断环境：
</td>
</tr>

<tr>
<td> preempt-depth </td>
<td>
The level of preempt_disabled
</td>
<td>
禁止抢占的深度，即禁止抢占的计数值。
</td>
</tr>

<tr>
<td> time </td>
<td>
When the latency-format option is enabled, the trace file output includes a timestamp relative to the start of the trace. This differs from the output when latency-format is disabled, which includes an absolute timestamp.
</td>
<td>
从latency开始的相对时间
</td>
</tr>

<tr>
<td> delay </td>
<td>
This is just to help catch your eye a bit better. And needs to be fixed to be only relative to the same CPU. The marks are determined by the difference between this current trace and the next trace.
<pre>
‘$’ - greater than 1 second
‘@’ - greater than 100 milisecond
‘*’ - greater than 10 milisecond
‘#’ - greater than 1000 microsecond
‘!’ - greater than 100 microsecond
‘+’ - greater than 10 microsecond
‘ ‘ - less than or equal to 10 microsecond.
</pre>
</td>
<td>
时间间隔大小所处的等级，可以迅速分类出不同的严重程度。
</td>
</tr>

</table>

- 其他的和“trace”文件相同；
- 最后还有backtrace，能迅速定位latency发生的位置；


# 5、trace_options

“trace_options”文件(或者“option”文件夹中的文件)用来控制trace文件的输出格式，或者由tracer自动配置。

```
cat trace_options
      print-parent
      nosym-offset
      nosym-addr
      noverbose
      noraw
      nohex
      nobin
      noblock
      trace_printk
      annotate
      nouserstacktrace
      nosym-userobj
      noprintk-msg-only
      context-info
      nolatency-format
      record-cmd
      norecord-tgid
      overwrite
      nodisable_on_free
      irq-info
      markers
      noevent-fork
      function-trace
      nofunction-fork
      nodisplay-graph
      nostacktrace
      nobranch
```

Disable某个选项，使用“no”前缀：

```
echo noprint-parent > trace_options
```

Enable某个选项，去掉“no”前缀：

```
echo sym-offset > trace_options
```

- 有效的trace optione列表：

<table border="1">
<caption> available trace options </caption>

<tr>
<th style="width: 200px;">Option</th>
<th style="width: 400px;">Description</th>
<th style="width: 400px;">说明</th>
</tr>


<tr>
<td> print-parent </td>
<td>
On function traces, display the calling (parent) function as well as the function being traced.
<pre>
print-parent:
 bash-4000  [01]  1477.606694: simple_strtoul &lt;-kstrtoul

noprint-parent:
 bash-4000  [01]  1477.606694: simple_strtoul
</pre>
</td>
<td>
是否打印父进程
</td>
</tr>

<tr>
<td> sym-offset </td>
<td>
Display not only the function name, but also the offset in the function. For example, instead of seeing just “ktime_get”, you will see “ktime_get+0xb/0x20”.
<pre>
sym-offset:
 bash-4000  [01]  1477.606694: simple_strtoul+0x6/0xa0
</pre>
</td>
<td>
是否打印符号的offset
</td>
</tr>

<tr>
<td> sym-addr </td>
<td>
This will also display the function address as well as the function name.
<pre>
sym-addr:
 bash-4000  [01]  1477.606694: simple_strtoul &lt;c0339346&gt;
</pre>
</td>
<td>
是否打印符号地址
</td>
</tr>

<tr>
<td> verbose </td>
<td>
This deals with the trace file when the latency-format option is enabled.
<pre>
bash  4000 1 0 00000000 00010a95 [58127d26] 1720.415ms \
(+0.000ms): simple_strtoul (kstrtoul)
</pre>
</td>
<td>
显示详细信息
</td>
</tr>

<tr>
<td> raw </td>
<td>
This will display raw numbers. This option is best for use with user applications that can translate the raw numbers better than having it done in the kernel.
</td>
<td>
显示裸数据。如果用户应用知道裸数据的解析方法，可以在用户态解析，优于在内核解析。
</td>
</tr>

<tr>
<td> hex </td>
<td>
Similar to raw, but the numbers will be in a hexadecimal format.
</td>
<td>
使用hex格式解析裸数据。
</td>
</tr>

<tr>
<td> bin </td>
<td>
This will print out the formats in raw binary.
</td>
<td>
使用bin格式解析裸数据。
</td>
</tr>

<tr>
<td> block </td>
<td>
When set, reading trace_pipe will not block when polled.
</td>
<td>
如果设置，读trace_pipe文件不会在轮询时阻塞。
</td>
</tr>

<tr>
<td> trace_printk </td>
<td>
Can disable trace_printk() from writing into the buffer.
</td>
<td>
禁止trace_printk写入数据到ring buffer。
</td>
</tr>

<tr>
<td> annotate </td>
<td>
It is sometimes confusing when the CPU buffers are full and one CPU buffer had a lot of events recently, thus a shorter time frame, were another CPU may have only had a few events, which lets it have older events. When the trace is reported, it shows the oldest events first, and it may look like only one CPU ran (the one with the oldest events). When the annotate option is set, it will display when a new CPU buffer started:
<pre>
    <idle>-0     [001] dNs4 21169.031481: wake_up_idle_cpu &lt;-add_timer_on
    <idle>-0     [001] dNs4 21169.031482: _raw_spin_unlock_irqrestore &lt;-add_timer_on
    <idle>-0     [001] .Ns4 21169.031484: sub_preempt_count &lt;-_raw_spin_unlock_irqrestore
 ##### CPU 2 buffer started ####
    <idle>-0     [002] .N.1 21169.031484: rcu_idle_exit &lt;-cpu_idle
    <idle>-0     [001] .Ns3 21169.031484: _raw_spin_unlock &lt;-clocksource_watchdog
    <idle>-0     [001] .Ns3 21169.031485: sub_preempt_count &lt;-_raw_spin_unlock
</pre>
</td>
<td>
提示，内容的切换
</td>
</tr>

<tr>
<td> userstacktrace </td>
<td>
This option changes the trace. It records a stacktrace of the current user space thread after each trace event.
</td>
<td>
记录用户空间的堆栈回调
</td>
</tr>

<tr>
<td> sym-userobj </td>
<td>
when user stacktrace are enabled, look up which object the address belongs to, and print a relative address. This is especially useful when ASLR is on, otherwise you don’t get a chance to resolve the address to object/file/line after the app is no longer running

The lookup is performed when you read trace,trace_pipe. Example:
<pre>
a.out-1623  [000] 40874.465068: /root/a.out[+0x480] &lt;-/root/a.out[+0
x494] &lt;- /root/a.out[+0x4a8] &lt;- /lib/libc-2.7.so[+0x1e1a6]
</pre>
</td>
<td>
记录用户空间的堆栈回调，并且解析出对应符号。这在ASLR使能时非常有用，因为ASLR是随机加载库地址，事后根据堆栈可能恢复不出原来的调用关系。
</td>
</tr>

<tr>
<td> printk-msg-only </td>
<td>
When set, trace_printk()s will only show the format and not their parameters (if trace_bprintk() or trace_bputs() was used to save the trace_printk()).
</td>
<td>
trace_printk()仅仅打印格式不打印参数
</td>
</tr>

<tr>
<td> context-info </td>
<td>
Show only the event data. Hides the comm, PID, timestamp, CPU, and other useful data.
</td>
<td>
是否打印trace event的头部通用信息：comm, PID, timestamp, CPU, and other useful data.
</td>
</tr>

<tr>
<td> latency-format </td>
<td>
This option changes the trace output. When it is enabled, the trace displays additional information about the latency, as described in “Latency trace format”.
</td>
<td>
是否使用“Latency trace format”打印
</td>
</tr>

<tr>
<td> record-cmd </td>
<td>
When any event or tracer is enabled, a hook is enabled in the sched_switch trace point to fill comm cache with mapped pids and comms. But this may cause some overhead, and if you only care about pids, and not the name of the task, disabling this option can lower the impact of tracing. See “saved_cmdlines”.
</td>
<td>
是否在sched_switch时间点来创建pid到comm的转换cache。
</td>
</tr>

<tr>
<td> record-tgid </td>
<td>
When any event or tracer is enabled, a hook is enabled in the sched_switch trace point to fill the cache of mapped Thread Group IDs (TGID) mapping to pids. See “saved_tgids”.
</td>
<td>
是否创建pid到tgid的cache。
</td>
</tr>

<tr>
<td> overwrite </td>
<td>
This controls what happens when the trace buffer is full. If “1” (default), the oldest events are discarded and overwritten. If “0”, then the newest events are discarded. (see per_cpu/cpu0/stats for overrun and dropped)
</td>
<td>
控制ringbuffer满后的行为是，overwrite旧数据，还是discard新数据。
</td>
</tr>

<tr>
<td> disable_on_free </td>
<td>
When the free_buffer is closed, tracing will stop (tracing_on set to 0).
</td>
<td>
当使用“set_free_buffer”释放ringbuffer空间时，是否停止tracing。
</td>
</tr>

<tr>
<td> irq-info </td>
<td>
Shows the interrupt, preempt count, need resched data. When disabled, the trace looks like:
<pre>
 # tracer: function
 #
 # entries-in-buffer/entries-written: 144405/9452052   #P:4
 #
 #           TASK-PID   CPU#      TIMESTAMP  FUNCTION
 #              | |       |          |         |
           <idle>-0     [002]  23636.756054: ttwu_do_activate.constprop.89 &lt;-try_to_wake_up
           <idle>-0     [002]  23636.756054: activate_task &lt;-ttwu_do_activate.constprop.89
           <idle>-0     [002]  23636.756055: enqueue_task &lt;-activate_task
</pre>
</td>
<td>
是否打印相关flag信息：interrupt, preempt count, need resched
</td>
</tr>

<tr>
<td> markers </td>
<td>
When set, the trace_marker is writable (only by root). When disabled, the trace_marker will error with EINVAL on write.
</td>
<td>
是否允许用户态直接通过trace_marker接口往ringbuffer中写数据
</td>
</tr>

<tr>
<td> event-fork </td>
<td>
When set, tasks with PIDs listed in set_event_pid will have the PIDs of their children added to set_event_pid when those tasks fork. Also, when tasks with PIDs in set_event_pid exit, their PIDs will be removed from the file.
</td>
<td>
对于trace_event，如果进程在pid filter列表中，fork创建的子进程是否自动加入到filter列表中。
</td>
</tr>

<tr>
<td> function-trace </td>
<td>
The latency tracers will enable function tracing if this option is enabled (default it is). When it is disabled, the latency tracers do not trace functions. This keeps the overhead of the tracer down when performing latency tests.
</td>
<td>
在latency tracers是可以同时使能function tracing。
</td>
</tr>

<tr>
<td> function-fork </td>
<td>
When set, tasks with PIDs listed in set_ftrace_pid will have the PIDs of their children added to set_ftrace_pid when those tasks fork. Also, when tasks with PIDs in set_ftrace_pid exit, their PIDs will be removed from the file.
</td>
<td>
对于ftrace，如果进程在pid filter列表中，fork创建的子进程是否自动加入到filter列表中。
</td>
</tr>

<tr>
<td> display-graph </td>
<td>
When set, the latency tracers (irqsoff, wakeup, etc) will use function graph tracing instead of function tracing.
</td>
<td>
“function graph tracing”风格的显示
</td>
</tr>

<tr>
<td> stacktrace </td>
<td>
When set, a stack trace is recorded after any trace event is recorded.
</td>
<td>
event中是否记录堆栈回调
</td>
</tr>

<tr>
<td> branch </td>
<td>
Enable branch tracing with the tracer. This enables branch tracer along with the currently set tracer. Enabling this with the “nop” tracer is the same as just enabling the “branch” tracer.
</td>
<td>
启用分支追踪
</td>
</tr>

</table>

- function tracer特有的选项：

<table border="1">
<caption> function tracer options </caption>

<tr>
<th style="width: 200px;">Option</th>
<th style="width: 400px;">Description</th>
<th style="width: 400px;">说明</th>
</tr>

<tr>
<td> func_stack_trace </td>
<td>
When set, a stack trace is recorded after every function that is recorded. NOTE! Limit the functions that are recorded before enabling this, with “set_ftrace_filter” otherwise the system performance will be critically degraded. Remember to disable this option before clearing the function filter.
</td>
<td>
每次进入函数，都记录函数的回调关系。
</td>
</tr>

</table>

-  function_graph tracer特有的选项：

<table border="1">
<caption>  function_graph tracer options </caption>

<tr>
<th style="width: 200px;">Option</th>
<th style="width: 400px;">Description</th>
<th style="width: 400px;">说明</th>
</tr>

<tr>
<td> funcgraph-overrun </td>
<td>
When set, the “overrun” of the graph stack is displayed after each function traced. The overrun, is when the stack depth of the calls is greater than what is reserved for each task. Each task has a fixed array of functions to trace in the call graph. If the depth of the calls exceeds that, the function is not traced. The overrun is the number of functions missed due to exceeding this array.
</td>
<td>

</td>
</tr>

<tr>
<td> funcgraph-cpu </td>
<td>
When set, the CPU number of the CPU where the trace occurred is displayed.
</td>
<td>
显示所在CPU
</td>
</tr>

<tr>
<td> funcgraph-overhead </td>
<td>
When set, if the function takes longer than A certain amount, then a delay marker is displayed. See “delay” above, under the header description.
</td>
<td>
显示“delay”程度
</td>
</tr>

<tr>
<td> funcgraph-proc </td>
<td>
Unlike other tracers, the process’ command line is not displayed by default, but instead only when a task is traced in and out during a context switch. Enabling this options has the command of each process displayed at every line.
</td>
<td>
显示进程comm
</td>
</tr>

<tr>
<td> funcgraph-duration </td>
<td>
At the end of each function (the return) the duration of the amount of time in the function is displayed in microseconds.
</td>
<td>
显示函数执行时间
</td>
</tr>

<tr>
<td> funcgraph-abstime </td>
<td>
When set, the timestamp is displayed at each line.
</td>
<td>
显示绝对时间戳
</td>
</tr>

<tr>
<td> funcgraph-irqs </td>
<td>
When disabled, functions that happen inside an interrupt will not be traced.
</td>
<td>
如果disable，将不会跟踪中断中的函数
</td>
</tr>

<tr>
<td> funcgraph-tail </td>
<td>
When set, the return event will include the function that it represents. By default this is off, and only a closing curly bracket “}” is displayed for the return of a function.
</td>
<td>
在函数结束时显示函数名
</td>
</tr>

<tr>
<td> sleep-time </td>
<td>
When running function graph tracer, to include the time a task schedules out in its function. When enabled, it will account time the task has been scheduled out as part of the function call.
</td>
<td>
函数的执行时间包括进程被调度出去的sleep时间
</td>
</tr>

<tr>
<td> graph-time </td>
<td>
When running function profiler with function graph tracer, to include the time to call nested functions. When this is not set, the time reported for the function will only include the time the function itself executed for, not the time for functions that it called.
</td>
<td>

</td>
</tr>

</table>

- blk  tracer特有的选项：

<table border="1">
<caption> blk  tracer options </caption>

<tr>
<th style="width: 200px;">Option</th>
<th style="width: 400px;">Description</th>
<th style="width: 400px;">说明</th>
</tr>

<tr>
<td> blk_classic </td>
<td>
Shows a more minimalistic output.
</td>
<td>
显示出更加简约的输出。
</td>
</tr>

</table>


# 6、irqsoff

当中断关闭CPU不能响应任何外部的事件，将会阻止内核响应timer、鼠标中断，对应的结果就是响应延迟。

irqsoff tracer追踪关中断时间，当一个新的最大latency到来时，它会记住新的最大latency event，丢弃掉旧的最大latency event。"echo 0 >tracing_max_latency"会复位最大值。

```
# echo 0 > options/function-trace
# echo irqsoff > current_tracer
# echo 1 > tracing_on
# echo 0 > tracing_max_latency
# ls -ltr
[...]
# echo 0 > tracing_on
# cat trace
# tracer: irqsoff
#
# irqsoff latency trace v1.1.5 on 3.8.0-test+
# --------------------------------------------------------------------
# latency: 16 us, #4/4, CPU#0 | (M:preempt VP:0, KP:0, SP:0 HP:0 #P:4)
#    -----------------
#    | task: swapper/0-0 (uid:0 nice:0 policy:0 rt_prio:0)
#    -----------------
#  => started at: run_timer_softirq
#  => ended at:   run_timer_softirq
#
#
#                  _------=> CPU#
#                 / _-----=> irqs-off
#                | / _----=> need-resched
#                || / _---=> hardirq/softirq
#                ||| / _--=> preempt-depth
#                |||| /     delay
#  cmd     pid   ||||| time  |   caller
#     \   /      |||||  \    |   /
  <idle>-0       0d.s2    0us+: _raw_spin_lock_irq <-run_timer_softirq
  <idle>-0       0dNs3   17us : _raw_spin_unlock_irq <-run_timer_softirq
  <idle>-0       0dNs3   17us+: trace_hardirqs_on <-run_timer_softirq
  <idle>-0       0dNs3   25us : <stack trace>
 => _raw_spin_unlock_irq
 => run_timer_softirq
 => __do_softirq
 => call_softirq
 => do_softirq
 => irq_exit
 => smp_apic_timer_interrupt
 => apic_timer_interrupt
 => rcu_idle_exit
 => cpu_idle
 => rest_init
 => start_kernel
 => x86_64_start_reservations
 => x86_64_start_kernel
```

- 看到16us的延迟
-  _raw_spin_lock_irq <- run_timer_softirq 关闭了中断
-  16us到25us之间，是在做记录工作

下面是irqsoff tracer和function-trace同时打开的情况：

```
with echo 1 > options/function-trace

 # tracer: irqsoff
 #
 # irqsoff latency trace v1.1.5 on 3.8.0-test+
 # --------------------------------------------------------------------
 # latency: 71 us, #168/168, CPU#3 | (M:preempt VP:0, KP:0, SP:0 HP:0 #P:4)
 #    -----------------
 #    | task: bash-2042 (uid:0 nice:0 policy:0 rt_prio:0)
 #    -----------------
 #  => started at: ata_scsi_queuecmd
 #  => ended at:   ata_scsi_queuecmd
 #
 #
 #                  _------=> CPU#
 #                 / _-----=> irqs-off
 #                | / _----=> need-resched
 #                || / _---=> hardirq/softirq
 #                ||| / _--=> preempt-depth
 #                |||| /     delay
 #  cmd     pid   ||||| time  |   caller
 #     \   /      |||||  \    |   /
     bash-2042    3d...    0us : _raw_spin_lock_irqsave <-ata_scsi_queuecmd
     bash-2042    3d...    0us : add_preempt_count <-_raw_spin_lock_irqsave
     bash-2042    3d..1    1us : ata_scsi_find_dev <-ata_scsi_queuecmd
     bash-2042    3d..1    1us : __ata_scsi_find_dev <-ata_scsi_find_dev
     bash-2042    3d..1    2us : ata_find_dev.part.14 <-__ata_scsi_find_dev
     bash-2042    3d..1    2us : ata_qc_new_init <-__ata_scsi_queuecmd
     bash-2042    3d..1    3us : ata_sg_init <-__ata_scsi_queuecmd
     bash-2042    3d..1    4us : ata_scsi_rw_xlat <-__ata_scsi_queuecmd
     bash-2042    3d..1    4us : ata_build_rw_tf <-ata_scsi_rw_xlat
 [...]
     bash-2042    3d..1   67us : delay_tsc <-__delay
     bash-2042    3d..1   67us : add_preempt_count <-delay_tsc
     bash-2042    3d..2   67us : sub_preempt_count <-delay_tsc
     bash-2042    3d..1   67us : add_preempt_count <-delay_tsc
     bash-2042    3d..2   68us : sub_preempt_count <-delay_tsc
     bash-2042    3d..1   68us+: ata_bmdma_start <-ata_bmdma_qc_issue
     bash-2042    3d..1   71us : _raw_spin_unlock_irqrestore <-ata_scsi_queuecmd
     bash-2042    3d..1   71us : _raw_spin_unlock_irqrestore <-ata_scsi_queuecmd
     bash-2042    3d..1   72us+: trace_hardirqs_on <-ata_scsi_queuecmd
     bash-2042    3d..1  120us : <stack trace>
  => _raw_spin_unlock_irqrestore
  => ata_scsi_queuecmd
  => scsi_dispatch_cmd
  => scsi_request_fn
  => __blk_run_queue_uncond
  => __blk_run_queue
  => blk_queue_bio
  => generic_make_request
  => submit_bio
  => submit_bh
  => __ext3_get_inode_loc
  => ext3_iget
  => ext3_lookup
  => lookup_real
  => __lookup_hash
  => walk_component
  => lookup_last
  => path_lookupat
  => filename_lookup
  => user_path_at_empty
  => user_path_at
  => vfs_fstatat
  => vfs_stat
  => sys_newstat
  => system_call_fastpath
```

- 71us的延迟
- 但是我们可以看到在此之间的函数调用
- 使能function-trace增加了不少开销，会增加延迟时间，但是也提供了更多的有用信息


# 7、preemptoff

当抢占关闭，我们除了接收中断，不能进行任务调度。

preemptoff tracer用来追踪抢占关闭时间，和irqsoff非常类似。

```
# echo 0 > options/function-trace
# echo preemptoff > current_tracer
# echo 1 > tracing_on
# echo 0 > tracing_max_latency
# ls -ltr
[...]
# echo 0 > tracing_on
# cat trace
# tracer: preemptoff
#
# preemptoff latency trace v1.1.5 on 3.8.0-test+
# --------------------------------------------------------------------
# latency: 46 us, #4/4, CPU#1 | (M:preempt VP:0, KP:0, SP:0 HP:0 #P:4)
#    -----------------
#    | task: sshd-1991 (uid:0 nice:0 policy:0 rt_prio:0)
#    -----------------
#  => started at: do_IRQ
#  => ended at:   do_IRQ
#
#
#                  _------=> CPU#
#                 / _-----=> irqs-off
#                | / _----=> need-resched
#                || / _---=> hardirq/softirq
#                ||| / _--=> preempt-depth
#                |||| /     delay
#  cmd     pid   ||||| time  |   caller
#     \   /      |||||  \    |   /
    sshd-1991    1d.h.    0us+: irq_enter <-do_IRQ
    sshd-1991    1d..1   46us : irq_exit <-do_IRQ
    sshd-1991    1d..1   47us+: trace_preempt_on <-do_IRQ
    sshd-1991    1d..1   52us : <stack trace>
 => sub_preempt_count
 => irq_exit
 => do_IRQ
 => ret_from_intr
```

- 当一个中断进入时 (注意 ‘h’)关闭抢占，退出中断时打开抢占；
- 在抢占关闭打开的整个过程中，中断处于关闭状态(‘d’)，我们不能确定中断的打开时刻；

```
# tracer: preemptoff
#
# preemptoff latency trace v1.1.5 on 3.8.0-test+
# --------------------------------------------------------------------
# latency: 83 us, #241/241, CPU#1 | (M:preempt VP:0, KP:0, SP:0 HP:0 #P:4)
#    -----------------
#    | task: bash-1994 (uid:0 nice:0 policy:0 rt_prio:0)
#    -----------------
#  => started at: wake_up_new_task
#  => ended at:   task_rq_unlock
#
#
#                  _------=> CPU#
#                 / _-----=> irqs-off
#                | / _----=> need-resched
#                || / _---=> hardirq/softirq
#                ||| / _--=> preempt-depth
#                |||| /     delay
#  cmd     pid   ||||| time  |   caller
#     \   /      |||||  \    |   /
    bash-1994    1d..1    0us : _raw_spin_lock_irqsave <-wake_up_new_task
    bash-1994    1d..1    0us : select_task_rq_fair <-select_task_rq
    bash-1994    1d..1    1us : __rcu_read_lock <-select_task_rq_fair
    bash-1994    1d..1    1us : source_load <-select_task_rq_fair
    bash-1994    1d..1    1us : source_load <-select_task_rq_fair
[...]
    bash-1994    1d..1   12us : irq_enter <-smp_apic_timer_interrupt
    bash-1994    1d..1   12us : rcu_irq_enter <-irq_enter
    bash-1994    1d..1   13us : add_preempt_count <-irq_enter
    bash-1994    1d.h1   13us : exit_idle <-smp_apic_timer_interrupt
    bash-1994    1d.h1   13us : hrtimer_interrupt <-smp_apic_timer_interrupt
    bash-1994    1d.h1   13us : _raw_spin_lock <-hrtimer_interrupt
    bash-1994    1d.h1   14us : add_preempt_count <-_raw_spin_lock
    bash-1994    1d.h2   14us : ktime_get_update_offsets <-hrtimer_interrupt
[...]
    bash-1994    1d.h1   35us : lapic_next_event <-clockevents_program_event
    bash-1994    1d.h1   35us : irq_exit <-smp_apic_timer_interrupt
    bash-1994    1d.h1   36us : sub_preempt_count <-irq_exit
    bash-1994    1d..2   36us : do_softirq <-irq_exit
    bash-1994    1d..2   36us : __do_softirq <-call_softirq
    bash-1994    1d..2   36us : __local_bh_disable <-__do_softirq
    bash-1994    1d.s2   37us : add_preempt_count <-_raw_spin_lock_irq
    bash-1994    1d.s3   38us : _raw_spin_unlock <-run_timer_softirq
    bash-1994    1d.s3   39us : sub_preempt_count <-_raw_spin_unlock
    bash-1994    1d.s2   39us : call_timer_fn <-run_timer_softirq
[...]
    bash-1994    1dNs2   81us : cpu_needs_another_gp <-rcu_process_callbacks
    bash-1994    1dNs2   82us : __local_bh_enable <-__do_softirq
    bash-1994    1dNs2   82us : sub_preempt_count <-__local_bh_enable
    bash-1994    1dN.2   82us : idle_cpu <-irq_exit
    bash-1994    1dN.2   83us : rcu_irq_exit <-irq_exit
    bash-1994    1dN.2   83us : sub_preempt_count <-irq_exit
    bash-1994    1.N.1   84us : _raw_spin_unlock_irqrestore <-task_rq_unlock
    bash-1994    1.N.1   84us+: trace_preempt_on <-task_rq_unlock
    bash-1994    1.N.1  104us : <stack trace>
 => sub_preempt_count
 => _raw_spin_unlock_irqrestore
 => task_rq_unlock
 => wake_up_new_task
 => do_fork
 => sys_clone
 => stub_clone
```

- 以上是preemptoff tracer + function-trace
- 可以看到在整个周期中中断并不是一直被disable
- 可以看到irq_enter代码进入‘h’中断。在此之前是看不到这种信息的


# 8、preemptirqsoff

preemptirqsoff tracer追踪抢占/中断任一被关闭的最大延迟时间。

```
local_irq_disable();
call_function_with_irqs_off();
preempt_disable();
call_function_with_irqs_and_preemption_off();
local_irq_enable();
call_function_with_preemption_off();
preempt_enable();
```

- irqsoff tracer记录的时间 = call_function_with_irqs_off() + call_function_with_irqs_and_preemption_off()
- preemptoff tracer记录的时间 = call_function_with_irqs_and_preemption_off() + call_function_with_preemption_off()
- preemptirqsoff tracer记录的时间 = total时间

```
# echo 0 > options/function-trace
# echo preemptirqsoff > current_tracer
# echo 1 > tracing_on
# echo 0 > tracing_max_latency
# ls -ltr
[...]
# echo 0 > tracing_on
# cat trace
# tracer: preemptirqsoff
#
# preemptirqsoff latency trace v1.1.5 on 3.8.0-test+
# --------------------------------------------------------------------
# latency: 100 us, #4/4, CPU#3 | (M:preempt VP:0, KP:0, SP:0 HP:0 #P:4)
#    -----------------
#    | task: ls-2230 (uid:0 nice:0 policy:0 rt_prio:0)
#    -----------------
#  => started at: ata_scsi_queuecmd
#  => ended at:   ata_scsi_queuecmd
#
#
#                  _------=> CPU#
#                 / _-----=> irqs-off
#                | / _----=> need-resched
#                || / _---=> hardirq/softirq
#                ||| / _--=> preempt-depth
#                |||| /     delay
#  cmd     pid   ||||| time  |   caller
#     \   /      |||||  \    |   /
      ls-2230    3d...    0us+: _raw_spin_lock_irqsave <-ata_scsi_queuecmd
      ls-2230    3...1  100us : _raw_spin_unlock_irqrestore <-ata_scsi_queuecmd
      ls-2230    3...1  101us+: trace_preempt_on <-ata_scsi_queuecmd
      ls-2230    3...1  111us : <stack trace>
 => sub_preempt_count
 => _raw_spin_unlock_irqrestore
 => ata_scsi_queuecmd
 => scsi_dispatch_cmd
 => scsi_request_fn
 => __blk_run_queue_uncond
 => __blk_run_queue
 => blk_queue_bio
 => generic_make_request
 => submit_bio
 => submit_bh
 => ext3_bread
 => ext3_dir_bread
 => htree_dirblock_to_tree
 => ext3_htree_fill_tree
 => ext3_readdir
 => vfs_readdir
 => sys_getdents
 => system_call_fastpath
```

以下是“preemptirqsoff tracer” + “function-trace”：

```
# tracer: preemptirqsoff
#
# preemptirqsoff latency trace v1.1.5 on 3.8.0-test+
# --------------------------------------------------------------------
# latency: 161 us, #339/339, CPU#3 | (M:preempt VP:0, KP:0, SP:0 HP:0 #P:4)
#    -----------------
#    | task: ls-2269 (uid:0 nice:0 policy:0 rt_prio:0)
#    -----------------
#  => started at: schedule
#  => ended at:   mutex_unlock
#
#
#                  _------=> CPU#
#                 / _-----=> irqs-off
#                | / _----=> need-resched
#                || / _---=> hardirq/softirq
#                ||| / _--=> preempt-depth
#                |||| /     delay
#  cmd     pid   ||||| time  |   caller
#     \   /      |||||  \    |   /
kworker/-59      3...1    0us : __schedule <-schedule
kworker/-59      3d..1    0us : rcu_preempt_qs <-rcu_note_context_switch
kworker/-59      3d..1    1us : add_preempt_count <-_raw_spin_lock_irq
kworker/-59      3d..2    1us : deactivate_task <-__schedule
kworker/-59      3d..2    1us : dequeue_task <-deactivate_task
kworker/-59      3d..2    2us : update_rq_clock <-dequeue_task
kworker/-59      3d..2    2us : dequeue_task_fair <-dequeue_task
kworker/-59      3d..2    2us : update_curr <-dequeue_task_fair
kworker/-59      3d..2    2us : update_min_vruntime <-update_curr
kworker/-59      3d..2    3us : cpuacct_charge <-update_curr
kworker/-59      3d..2    3us : __rcu_read_lock <-cpuacct_charge
kworker/-59      3d..2    3us : __rcu_read_unlock <-cpuacct_charge
kworker/-59      3d..2    3us : update_cfs_rq_blocked_load <-dequeue_task_fair
kworker/-59      3d..2    4us : clear_buddies <-dequeue_task_fair
kworker/-59      3d..2    4us : account_entity_dequeue <-dequeue_task_fair
kworker/-59      3d..2    4us : update_min_vruntime <-dequeue_task_fair
kworker/-59      3d..2    4us : update_cfs_shares <-dequeue_task_fair
kworker/-59      3d..2    5us : hrtick_update <-dequeue_task_fair
kworker/-59      3d..2    5us : wq_worker_sleeping <-__schedule
kworker/-59      3d..2    5us : kthread_data <-wq_worker_sleeping
kworker/-59      3d..2    5us : put_prev_task_fair <-__schedule
kworker/-59      3d..2    6us : pick_next_task_fair <-pick_next_task
kworker/-59      3d..2    6us : clear_buddies <-pick_next_task_fair
kworker/-59      3d..2    6us : set_next_entity <-pick_next_task_fair
kworker/-59      3d..2    6us : update_stats_wait_end <-set_next_entity
      ls-2269    3d..2    7us : finish_task_switch <-__schedule
      ls-2269    3d..2    7us : _raw_spin_unlock_irq <-finish_task_switch
      ls-2269    3d..2    8us : do_IRQ <-ret_from_intr
      ls-2269    3d..2    8us : irq_enter <-do_IRQ
      ls-2269    3d..2    8us : rcu_irq_enter <-irq_enter
      ls-2269    3d..2    9us : add_preempt_count <-irq_enter
      ls-2269    3d.h2    9us : exit_idle <-do_IRQ
[...]
      ls-2269    3d.h3   20us : sub_preempt_count <-_raw_spin_unlock
      ls-2269    3d.h2   20us : irq_exit <-do_IRQ
      ls-2269    3d.h2   21us : sub_preempt_count <-irq_exit
      ls-2269    3d..3   21us : do_softirq <-irq_exit
      ls-2269    3d..3   21us : __do_softirq <-call_softirq
      ls-2269    3d..3   21us+: __local_bh_disable <-__do_softirq
      ls-2269    3d.s4   29us : sub_preempt_count <-_local_bh_enable_ip
      ls-2269    3d.s5   29us : sub_preempt_count <-_local_bh_enable_ip
      ls-2269    3d.s5   31us : do_IRQ <-ret_from_intr
      ls-2269    3d.s5   31us : irq_enter <-do_IRQ
      ls-2269    3d.s5   31us : rcu_irq_enter <-irq_enter
[...]
      ls-2269    3d.s5   31us : rcu_irq_enter <-irq_enter
      ls-2269    3d.s5   32us : add_preempt_count <-irq_enter
      ls-2269    3d.H5   32us : exit_idle <-do_IRQ
      ls-2269    3d.H5   32us : handle_irq <-do_IRQ
      ls-2269    3d.H5   32us : irq_to_desc <-handle_irq
      ls-2269    3d.H5   33us : handle_fasteoi_irq <-handle_irq
[...]
      ls-2269    3d.s5  158us : _raw_spin_unlock_irqrestore <-rtl8139_poll
      ls-2269    3d.s3  158us : net_rps_action_and_irq_enable.isra.65 <-net_rx_action
      ls-2269    3d.s3  159us : __local_bh_enable <-__do_softirq
      ls-2269    3d.s3  159us : sub_preempt_count <-__local_bh_enable
      ls-2269    3d..3  159us : idle_cpu <-irq_exit
      ls-2269    3d..3  159us : rcu_irq_exit <-irq_exit
      ls-2269    3d..3  160us : sub_preempt_count <-irq_exit
      ls-2269    3d...  161us : __mutex_unlock_slowpath <-mutex_unlock
      ls-2269    3d...  162us+: trace_hardirqs_on <-mutex_unlock
      ls-2269    3d...  186us : <stack trace>
 => __mutex_unlock_slowpath
 => mutex_unlock
 => process_output
 => n_tty_write
 => tty_write
 => vfs_write
 => sys_write
 => system_call_fastpath
```

- 该例子是一个非常典型的例子
- kworker进程切换到ls
- 在ls released the rq lock and enabled interrupts 是一个中断被触发
- 当中断完成，它开始处理软中断
- 当软中断执行时，又触发了另一次硬中断。在软中断中的中断，显示‘H’


# 9、wakeup

wakeup tracer追踪普通进程从被唤醒到真正得到执行之间的延迟。

```
# echo 0 > options/function-trace
# echo wakeup > current_tracer
# echo 1 > tracing_on
# echo 0 > tracing_max_latency
# chrt -f 5 sleep 1
# echo 0 > tracing_on
# cat trace
# tracer: wakeup
#
# wakeup latency trace v1.1.5 on 3.8.0-test+
# --------------------------------------------------------------------
# latency: 15 us, #4/4, CPU#3 | (M:preempt VP:0, KP:0, SP:0 HP:0 #P:4)
#    -----------------
#    | task: kworker/3:1H-312 (uid:0 nice:-20 policy:0 rt_prio:0)
#    -----------------
#
#                  _------=> CPU#
#                 / _-----=> irqs-off
#                | / _----=> need-resched
#                || / _---=> hardirq/softirq
#                ||| / _--=> preempt-depth
#                |||| /     delay
#  cmd     pid   ||||| time  |   caller
#     \   /      |||||  \    |   /
  <idle>-0       3dNs7    0us :      0:120:R   + [003]   312:100:R kworker/3:1H
  <idle>-0       3dNs7    1us+: ttwu_do_activate.constprop.87 <-try_to_wake_up
  <idle>-0       3d..3   15us : __schedule <-schedule
  <idle>-0       3d..3   15us :      0:120:R ==> [003]   312:100:R kworker/3:1H
```

- tracer追踪优先级最高的进程。我们看到nice -20的kworker进程花了15us到唤醒。

# 10、wakeup_rt

non-RT进程通常看平均延迟。RT进程的最大延迟非常有意义，反应了调度器的性能。

```
# echo 0 > options/function-trace
# echo wakeup_rt > current_tracer
# echo 1 > tracing_on
# echo 0 > tracing_max_latency
# chrt -f 5 sleep 1
# echo 0 > tracing_on
# cat trace
# tracer: wakeup
#
# tracer: wakeup_rt
#
# wakeup_rt latency trace v1.1.5 on 3.8.0-test+
# --------------------------------------------------------------------
# latency: 5 us, #4/4, CPU#3 | (M:preempt VP:0, KP:0, SP:0 HP:0 #P:4)
#    -----------------
#    | task: sleep-2389 (uid:0 nice:0 policy:1 rt_prio:5)
#    -----------------
#
#                  _------=> CPU#
#                 / _-----=> irqs-off
#                | / _----=> need-resched
#                || / _---=> hardirq/softirq
#                ||| / _--=> preempt-depth
#                |||| /     delay
#  cmd     pid   ||||| time  |   caller
#     \   /      |||||  \    |   /
  <idle>-0       3d.h4    0us :      0:120:R   + [003]  2389: 94:R sleep
  <idle>-0       3d.h4    1us+: ttwu_do_activate.constprop.87 <-try_to_wake_up
  <idle>-0       3d..3    5us : __schedule <-schedule
  <idle>-0       3d..3    5us :      0:120:R ==> [003]  2389: 94:R sleep
```

- 从idle进程切换到rt进程花了5us
- 进程 PID为2389，rt_prio 5对应内部优先级(99 - rtprio)：

```
<idle>-0       3d..3    5us :      0:120:R ==> [003]  2389: 94:R sleep
```
以下是“wakeup_rt tracer” + “function-trace”：

```
echo 1 > options/function-trace

# tracer: wakeup_rt
#
# wakeup_rt latency trace v1.1.5 on 3.8.0-test+
# --------------------------------------------------------------------
# latency: 29 us, #85/85, CPU#3 | (M:preempt VP:0, KP:0, SP:0 HP:0 #P:4)
#    -----------------
#    | task: sleep-2448 (uid:0 nice:0 policy:1 rt_prio:5)
#    -----------------
#
#                  _------=> CPU#
#                 / _-----=> irqs-off
#                | / _----=> need-resched
#                || / _---=> hardirq/softirq
#                ||| / _--=> preempt-depth
#                |||| /     delay
#  cmd     pid   ||||| time  |   caller
#     \   /      |||||  \    |   /
  <idle>-0       3d.h4    1us+:      0:120:R   + [003]  2448: 94:R sleep
  <idle>-0       3d.h4    2us : ttwu_do_activate.constprop.87 <-try_to_wake_up
  <idle>-0       3d.h3    3us : check_preempt_curr <-ttwu_do_wakeup
  <idle>-0       3d.h3    3us : resched_curr <-check_preempt_curr
  <idle>-0       3dNh3    4us : task_woken_rt <-ttwu_do_wakeup
  <idle>-0       3dNh3    4us : _raw_spin_unlock <-try_to_wake_up
  <idle>-0       3dNh3    4us : sub_preempt_count <-_raw_spin_unlock
  <idle>-0       3dNh2    5us : ttwu_stat <-try_to_wake_up
  <idle>-0       3dNh2    5us : _raw_spin_unlock_irqrestore <-try_to_wake_up
  <idle>-0       3dNh2    6us : sub_preempt_count <-_raw_spin_unlock_irqrestore
  <idle>-0       3dNh1    6us : _raw_spin_lock <-__run_hrtimer
  <idle>-0       3dNh1    6us : add_preempt_count <-_raw_spin_lock
  <idle>-0       3dNh2    7us : _raw_spin_unlock <-hrtimer_interrupt
  <idle>-0       3dNh2    7us : sub_preempt_count <-_raw_spin_unlock
  <idle>-0       3dNh1    7us : tick_program_event <-hrtimer_interrupt
  <idle>-0       3dNh1    7us : clockevents_program_event <-tick_program_event
  <idle>-0       3dNh1    8us : ktime_get <-clockevents_program_event
  <idle>-0       3dNh1    8us : lapic_next_event <-clockevents_program_event
  <idle>-0       3dNh1    8us : irq_exit <-smp_apic_timer_interrupt
  <idle>-0       3dNh1    9us : sub_preempt_count <-irq_exit
  <idle>-0       3dN.2    9us : idle_cpu <-irq_exit
  <idle>-0       3dN.2    9us : rcu_irq_exit <-irq_exit
  <idle>-0       3dN.2   10us : rcu_eqs_enter_common.isra.45 <-rcu_irq_exit
  <idle>-0       3dN.2   10us : sub_preempt_count <-irq_exit
  <idle>-0       3.N.1   11us : rcu_idle_exit <-cpu_idle
  <idle>-0       3dN.1   11us : rcu_eqs_exit_common.isra.43 <-rcu_idle_exit
  <idle>-0       3.N.1   11us : tick_nohz_idle_exit <-cpu_idle
  <idle>-0       3dN.1   12us : menu_hrtimer_cancel <-tick_nohz_idle_exit
  <idle>-0       3dN.1   12us : ktime_get <-tick_nohz_idle_exit
  <idle>-0       3dN.1   12us : tick_do_update_jiffies64 <-tick_nohz_idle_exit
  <idle>-0       3dN.1   13us : cpu_load_update_nohz <-tick_nohz_idle_exit
  <idle>-0       3dN.1   13us : _raw_spin_lock <-cpu_load_update_nohz
  <idle>-0       3dN.1   13us : add_preempt_count <-_raw_spin_lock
  <idle>-0       3dN.2   13us : __cpu_load_update <-cpu_load_update_nohz
  <idle>-0       3dN.2   14us : sched_avg_update <-__cpu_load_update
  <idle>-0       3dN.2   14us : _raw_spin_unlock <-cpu_load_update_nohz
  <idle>-0       3dN.2   14us : sub_preempt_count <-_raw_spin_unlock
  <idle>-0       3dN.1   15us : calc_load_nohz_stop <-tick_nohz_idle_exit
  <idle>-0       3dN.1   15us : touch_softlockup_watchdog <-tick_nohz_idle_exit
  <idle>-0       3dN.1   15us : hrtimer_cancel <-tick_nohz_idle_exit
  <idle>-0       3dN.1   15us : hrtimer_try_to_cancel <-hrtimer_cancel
  <idle>-0       3dN.1   16us : lock_hrtimer_base.isra.18 <-hrtimer_try_to_cancel
  <idle>-0       3dN.1   16us : _raw_spin_lock_irqsave <-lock_hrtimer_base.isra.18
  <idle>-0       3dN.1   16us : add_preempt_count <-_raw_spin_lock_irqsave
  <idle>-0       3dN.2   17us : __remove_hrtimer <-remove_hrtimer.part.16
  <idle>-0       3dN.2   17us : hrtimer_force_reprogram <-__remove_hrtimer
  <idle>-0       3dN.2   17us : tick_program_event <-hrtimer_force_reprogram
  <idle>-0       3dN.2   18us : clockevents_program_event <-tick_program_event
  <idle>-0       3dN.2   18us : ktime_get <-clockevents_program_event
  <idle>-0       3dN.2   18us : lapic_next_event <-clockevents_program_event
  <idle>-0       3dN.2   19us : _raw_spin_unlock_irqrestore <-hrtimer_try_to_cancel
  <idle>-0       3dN.2   19us : sub_preempt_count <-_raw_spin_unlock_irqrestore
  <idle>-0       3dN.1   19us : hrtimer_forward <-tick_nohz_idle_exit
  <idle>-0       3dN.1   20us : ktime_add_safe <-hrtimer_forward
  <idle>-0       3dN.1   20us : ktime_add_safe <-hrtimer_forward
  <idle>-0       3dN.1   20us : hrtimer_start_range_ns <-hrtimer_start_expires.constprop.11
  <idle>-0       3dN.1   20us : __hrtimer_start_range_ns <-hrtimer_start_range_ns
  <idle>-0       3dN.1   21us : lock_hrtimer_base.isra.18 <-__hrtimer_start_range_ns
  <idle>-0       3dN.1   21us : _raw_spin_lock_irqsave <-lock_hrtimer_base.isra.18
  <idle>-0       3dN.1   21us : add_preempt_count <-_raw_spin_lock_irqsave
  <idle>-0       3dN.2   22us : ktime_add_safe <-__hrtimer_start_range_ns
  <idle>-0       3dN.2   22us : enqueue_hrtimer <-__hrtimer_start_range_ns
  <idle>-0       3dN.2   22us : tick_program_event <-__hrtimer_start_range_ns
  <idle>-0       3dN.2   23us : clockevents_program_event <-tick_program_event
  <idle>-0       3dN.2   23us : ktime_get <-clockevents_program_event
  <idle>-0       3dN.2   23us : lapic_next_event <-clockevents_program_event
  <idle>-0       3dN.2   24us : _raw_spin_unlock_irqrestore <-__hrtimer_start_range_ns
  <idle>-0       3dN.2   24us : sub_preempt_count <-_raw_spin_unlock_irqrestore
  <idle>-0       3dN.1   24us : account_idle_ticks <-tick_nohz_idle_exit
  <idle>-0       3dN.1   24us : account_idle_time <-account_idle_ticks
  <idle>-0       3.N.1   25us : sub_preempt_count <-cpu_idle
  <idle>-0       3.N..   25us : schedule <-cpu_idle
  <idle>-0       3.N..   25us : __schedule <-preempt_schedule
  <idle>-0       3.N..   26us : add_preempt_count <-__schedule
  <idle>-0       3.N.1   26us : rcu_note_context_switch <-__schedule
  <idle>-0       3.N.1   26us : rcu_sched_qs <-rcu_note_context_switch
  <idle>-0       3dN.1   27us : rcu_preempt_qs <-rcu_note_context_switch
  <idle>-0       3.N.1   27us : _raw_spin_lock_irq <-__schedule
  <idle>-0       3dN.1   27us : add_preempt_count <-_raw_spin_lock_irq
  <idle>-0       3dN.2   28us : put_prev_task_idle <-__schedule
  <idle>-0       3dN.2   28us : pick_next_task_stop <-pick_next_task
  <idle>-0       3dN.2   28us : pick_next_task_rt <-pick_next_task
  <idle>-0       3dN.2   29us : dequeue_pushable_task <-pick_next_task_rt
  <idle>-0       3d..3   29us : __schedule <-preempt_schedule
  <idle>-0       3d..3   30us :      0:120:R ==> [003]  2448: 94:R sleep
```



# 11、Latency tracing and events

如果“xxxlatency tracer” + “function-trace”方式会带来很多开销，但是你又想知道中间发生了什么，可以使用折中的方法：“xxxlatency tracer” + “trace event”：

```
# echo 0 > options/function-trace
# echo wakeup_rt > current_tracer
# echo 1 > events/enable
# echo 1 > tracing_on
# echo 0 > tracing_max_latency
# chrt -f 5 sleep 1
# echo 0 > tracing_on
# cat trace
# tracer: wakeup_rt
#
# wakeup_rt latency trace v1.1.5 on 3.8.0-test+
# --------------------------------------------------------------------
# latency: 6 us, #12/12, CPU#2 | (M:preempt VP:0, KP:0, SP:0 HP:0 #P:4)
#    -----------------
#    | task: sleep-5882 (uid:0 nice:0 policy:1 rt_prio:5)
#    -----------------
#
#                  _------=> CPU#
#                 / _-----=> irqs-off
#                | / _----=> need-resched
#                || / _---=> hardirq/softirq
#                ||| / _--=> preempt-depth
#                |||| /     delay
#  cmd     pid   ||||| time  |   caller
#     \   /      |||||  \    |   /
  <idle>-0       2d.h4    0us :      0:120:R   + [002]  5882: 94:R sleep
  <idle>-0       2d.h4    0us : ttwu_do_activate.constprop.87 <-try_to_wake_up
  <idle>-0       2d.h4    1us : sched_wakeup: comm=sleep pid=5882 prio=94 success=1 target_cpu=002
  <idle>-0       2dNh2    1us : hrtimer_expire_exit: hrtimer=ffff88007796feb8
  <idle>-0       2.N.2    2us : power_end: cpu_id=2
  <idle>-0       2.N.2    3us : cpu_idle: state=4294967295 cpu_id=2
  <idle>-0       2dN.3    4us : hrtimer_cancel: hrtimer=ffff88007d50d5e0
  <idle>-0       2dN.3    4us : hrtimer_start: hrtimer=ffff88007d50d5e0 function=tick_sched_timer expires=34311211000000 softexpires=34311211000000
  <idle>-0       2.N.2    5us : rcu_utilization: Start context switch
  <idle>-0       2.N.2    5us : rcu_utilization: End context switch
  <idle>-0       2d..3    6us : __schedule <-schedule
  <idle>-0       2d..3    6us :      0:120:R ==> [002]  5882: 94:R sleep
```

# 12、Hardware Latency Detector

计算硬件延迟。

```
# echo hwlat > current_tracer
# sleep 100
# cat trace
# tracer: hwlat
#
#                              _-----=> irqs-off
#                             / _----=> need-resched
#                            | / _---=> hardirq/softirq
#                            || / _--=> preempt-depth
#                            ||| /     delay
#           TASK-PID   CPU#  ||||    TIMESTAMP  FUNCTION
#              | |       |   ||||       |         |
           <...>-3638  [001] d... 19452.055471: #1     inner/outer(us):   12/14    ts:1499801089.066141940
           <...>-3638  [003] d... 19454.071354: #2     inner/outer(us):   11/9     ts:1499801091.082164365
           <...>-3638  [002] dn.. 19461.126852: #3     inner/outer(us):   12/9     ts:1499801098.138150062
           <...>-3638  [001] d... 19488.340960: #4     inner/outer(us):    8/12    ts:1499801125.354139633
           <...>-3638  [003] d... 19494.388553: #5     inner/outer(us):    8/12    ts:1499801131.402150961
           <...>-3638  [003] d... 19501.283419: #6     inner/outer(us):    0/12    ts:1499801138.297435289 nmi-total:4 nmi-count:1
```

所有的event都是在中断disable 'd'。每个字段相应的含义如下：

<table border="1">
<caption> hwlat </caption>

<tr>
<th style="width: 200px;">Field</th>
<th style="width: 200px;">Value</th>
<th style="width: 400px;">Description</th>
<th style="width: 400px;">说明</th>
</tr>

<tr>
<td> #1 </td>
<td> - </td>
<td>
This is the count of events recorded that were greater than the tracing_threshold (See below).
</td>
<td>
大于tracing_threshold的event的编号
</td>
</tr>

<tr>
<td> inner/outer(us) </td>
<td> 12/14 </td>
<td>
This shows two numbers as “inner latency” and “outer latency”. The test runs in a loop checking a timestamp twice. The latency detected within the two timestamps is the “inner latency” and the latency detected after the previous timestamp and the next timestamp in the loop is the “outer latency”.
</td>
<td>
“inner latency” 和 “outer latency”
</td>
</tr>

<tr>
<td> ts </td>
<td> 1499801089.066141940 </td>
<td>
The absolute timestamp that the event happened.
</td>
<td>
绝对时间戳
</td>
</tr>

<tr>
<td> nmi-total:4 nmi-count:1 </td>
<td> - </td>
<td>
On architectures that support it, if an NMI comes in during the test, the time spent in NMI is reported in “nmi-total” (in microseconds).<br/>
All architectures that have NMIs will show the “nmi-count” if an NMI comes in during the test.
</td>
<td>

</td>
</tr>

</table>

hwlat相关的文件：

<table border="1">
<caption> hwlat file </caption>

<tr>
<th style="width: 200px;">File</th>
<th style="width: 400px;">Description</th>
<th style="width: 400px;">说明</th>
</tr>

<tr>
<td> tracing_threshold </td>
<td>
This gets automatically set to “10” to represent 10 microseconds. This is the threshold of latency that needs to be detected before the trace will be recorded.<br/>
Note, when hwlat tracer is finished (another tracer is written into “current_tracer”), the original value for tracing_threshold is placed back into this file.
</td>
<td>
大于tracing_threshold的event才会被记录
</td>
</tr>

<tr>
<td> hwlat_detector/width </td>
<td>
The length of time the test runs with interrupts disabled.
</td>
<td>

</td>
</tr>

<tr>
<td> hwlat_detector/window </td>
<td>
The length of time of the window which the test runs. That is, the test will run for “width” microseconds per “window” microseconds
</td>
<td>

</td>
</tr>

<tr>
<td> tracing_cpumask </td>
<td>
When the test is started. A kernel thread is created that runs the test. This thread will alternate between CPUs listed in the tracing_cpumask between each period (one “window”). To limit the test to specific CPUs set the mask in this file to only the CPUs that the test should run on.
</td>
<td>

</td>
</tr>

</table>

# 13、function

function tracer，确保“ftrace_enabled”被设置：

```
# sysctl kernel.ftrace_enabled=1
# echo function > current_tracer
# echo 1 > tracing_on
# usleep 1
# echo 0 > tracing_on
# cat trace
# tracer: function
#
# entries-in-buffer/entries-written: 24799/24799   #P:4
#
#                              _-----=> irqs-off
#                             / _----=> need-resched
#                            | / _---=> hardirq/softirq
#                            || / _--=> preempt-depth
#                            ||| /     delay
#           TASK-PID   CPU#  ||||    TIMESTAMP  FUNCTION
#              | |       |   ||||       |         |
            bash-1994  [002] ....  3082.063030: mutex_unlock <-rb_simple_write
            bash-1994  [002] ....  3082.063031: __mutex_unlock_slowpath <-mutex_unlock
            bash-1994  [002] ....  3082.063031: __fsnotify_parent <-fsnotify_modify
            bash-1994  [002] ....  3082.063032: fsnotify <-fsnotify_modify
            bash-1994  [002] ....  3082.063032: __srcu_read_lock <-fsnotify
            bash-1994  [002] ....  3082.063032: add_preempt_count <-__srcu_read_lock
            bash-1994  [002] ...1  3082.063032: sub_preempt_count <-__srcu_read_lock
            bash-1994  [002] ....  3082.063033: __srcu_read_unlock <-fsnotify
[...]
```

使用echo来打开关闭tracing的方式太慢了，可能会引起数据覆盖。可以使用c预研代码来操控开关：

```
int trace_fd;
[...]
int main(int argc, char *argv[]) {
        [...]
        trace_fd = open(tracing_file("tracing_on"), O_WRONLY);
        [...]
        if (condition_hit()) {
                write(trace_fd, "0", 1);
        }
        [...]
}
```

## 13.1、Single thread tracing

function tracer可以针对某一个PID的进程设置过滤：

```
# cat set_ftrace_pid
no pid
# echo 3111 > set_ftrace_pid
# cat set_ftrace_pid
3111
# echo function > current_tracer
# cat trace | head
# tracer: function
#
#           TASK-PID    CPU#    TIMESTAMP  FUNCTION
#              | |       |          |         |
    yum-updatesd-3111  [003]  1637.254676: finish_task_switch <-thread_return
    yum-updatesd-3111  [003]  1637.254681: hrtimer_cancel <-schedule_hrtimeout_range
    yum-updatesd-3111  [003]  1637.254682: hrtimer_try_to_cancel <-hrtimer_cancel
    yum-updatesd-3111  [003]  1637.254683: lock_hrtimer_base <-hrtimer_try_to_cancel
    yum-updatesd-3111  [003]  1637.254685: fget_light <-do_sys_poll
    yum-updatesd-3111  [003]  1637.254686: pipe_poll <-do_sys_poll
# echo > set_ftrace_pid
# cat trace |head
# tracer: function
#
#           TASK-PID    CPU#    TIMESTAMP  FUNCTION
#              | |       |          |         |
##### CPU 3 buffer started ####
    yum-updatesd-3111  [003]  1701.957688: free_poll_entry <-poll_freewait
    yum-updatesd-3111  [003]  1701.957689: remove_wait_queue <-free_poll_entry
    yum-updatesd-3111  [003]  1701.957691: fput <-free_poll_entry
    yum-updatesd-3111  [003]  1701.957692: audit_syscall_exit <-sysret_audit
    yum-updatesd-3111  [003]  1701.957693: path_put <-audit_syscall_exit
```

可以在程序运行时，通过C程序来设置：

```
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#define _STR(x) #x
#define STR(x) _STR(x)
#define MAX_PATH 256

const char *find_tracefs(void)
{
       static char tracefs[MAX_PATH+1];
       static int tracefs_found;
       char type[100];
       FILE *fp;

       if (tracefs_found)
               return tracefs;

       if ((fp = fopen("/proc/mounts","r")) == NULL) {
               perror("/proc/mounts");
               return NULL;
       }

       while (fscanf(fp, "%*s %"
                     STR(MAX_PATH)
                     "s %99s %*s %*d %*d\n",
                     tracefs, type) == 2) {
               if (strcmp(type, "tracefs") == 0)
                       break;
       }
       fclose(fp);

       if (strcmp(type, "tracefs") != 0) {
               fprintf(stderr, "tracefs not mounted");
               return NULL;
       }

       strcat(tracefs, "/tracing/");
       tracefs_found = 1;

       return tracefs;
}

const char *tracing_file(const char *file_name)
{
       static char trace_file[MAX_PATH+1];
       snprintf(trace_file, MAX_PATH, "%s/%s", find_tracefs(), file_name);
       return trace_file;
}

int main (int argc, char **argv)
{
        if (argc < 1)
                exit(-1);

        if (fork() > 0) {
                int fd, ffd;
                char line[64];
                int s;

                ffd = open(tracing_file("current_tracer"), O_WRONLY);
                if (ffd < 0)
                        exit(-1);
                write(ffd, "nop", 3);

                fd = open(tracing_file("set_ftrace_pid"), O_WRONLY);
                s = sprintf(line, "%d\n", getpid());
                write(fd, line, s);

                write(ffd, "function", 8);

                close(fd);
                close(ffd);

                execvp(argv[1], argv+1);
        }

        return 0;
}
```

或者通过脚本来设置：

```
#!/bin/bash

tracefs=`sed -ne 's/^tracefs \(.*\) tracefs.*/\1/p' /proc/mounts`
echo nop > $tracefs/tracing/current_tracer
echo 0 > $tracefs/tracing/tracing_on
echo $$ > $tracefs/tracing/set_ftrace_pid
echo function > $tracefs/tracing/current_tracer
echo 1 > $tracefs/tracing/tracing_on
exec "$@"
```

# 14、function graph tracer

function graph tracer非常类似function tracer除了同时追踪函数的进入和退出。它是利用每个task_struct中的return address堆栈动态分配来实现的，在进入函数的时候会使用自定义的probe函数替换掉原本的return地址。因此原始的return地址会存放在task_struct返回地址堆栈中。

在所有的函数退出点插入probe函数，导致新的特性：

- 测量函数的执行时间
- 有一个可靠的调用栈来画函数调用图

这个tracer应用到以下的场景：

- 你想要找出内核奇怪行为的原因，需要看到具体细节上发生了什么
- 你正在经历奇怪的延迟但是非常难找到它的起源
- 你想要快速查找出特定函数的执行路径
- 你想窥视一个正在工作中的内核，看看到底发生了什么

```
# tracer: function_graph
#
# CPU  DURATION                  FUNCTION CALLS
# |     |   |                     |   |   |   |

 0)               |  sys_open() {
 0)               |    do_sys_open() {
 0)               |      getname() {
 0)               |        kmem_cache_alloc() {
 0)   1.382 us    |          __might_sleep();
 0)   2.478 us    |        }
 0)               |        strncpy_from_user() {
 0)               |          might_fault() {
 0)   1.389 us    |            __might_sleep();
 0)   2.553 us    |          }
 0)   3.807 us    |        }
 0)   7.876 us    |      }
 0)               |      alloc_fd() {
 0)   0.668 us    |        _spin_lock();
 0)   0.570 us    |        expand_files();
 0)   0.586 us    |        _spin_unlock();
```

这有一系列的列信息可以动态的anbale/disable，你可以根据你的需要组合option配置：

- 运行cpu的编号：

    hide: echo nofuncgraph-cpu > trace_options  
    show: echo funcgraph-cpu > trace_options
    
- 函数执行时间。在函数的闭括号行显示，或者在叶子函数的同一行显示。默认enable：

    hide: echo nofuncgraph-duration > trace_options  
    show: echo funcgraph-duration > trace_options

- 开销字段，在执行时间字段之前，标明时间大小的程度：

    例如：
    
    ```
    3) # 1837.709 us |          } /* __switch_to */
    3)               |          finish_task_switch() {
    3)   0.313 us    |            _raw_spin_unlock_irq();
    3)   3.177 us    |          }
    3) # 1889.063 us |        } /* __schedule */
    3) ! 140.417 us  |      } /* __schedule */
    3) # 2034.948 us |    } /* schedule */
    3) * 33998.59 us |  } /* schedule_preempt_disabled */
    
    [...]
    
    1)   0.260 us    |              msecs_to_jiffies();
    1)   0.313 us    |              __rcu_read_unlock();
    1) + 61.770 us   |            }
    1) + 64.479 us   |          }
    1)   0.313 us    |          rcu_bh_qs();
    1)   0.313 us    |          __local_bh_enable();
    1) ! 217.240 us  |        }
    1)   0.365 us    |        idle_cpu();
    1)               |        rcu_irq_exit() {
    1)   0.417 us    |          rcu_eqs_enter_common.isra.47();
    1)   3.125 us    |        }
    1) ! 227.812 us  |      }
    1) ! 457.395 us  |    }
    1) @ 119760.2 us |  }
    
    [...]
    
    2)               |    handle_IPI() {
    1)   6.979 us    |                  }
    2)   0.417 us    |      scheduler_ipi();
    1)   9.791 us    |                }
    1) + 12.917 us   |              }
    2)   3.490 us    |    }
    1) + 15.729 us   |            }
    1) + 18.542 us   |          }
    2) $ 3594274 us  |  }
    ```
    
    flgs的含义如下：
    
    ```
    + means that the function exceeded 10 usecs.
    ! means that the function exceeded 100 usecs.
    # means that the function exceeded 1000 usecs.
    * means that the function exceeded 10 msecs.
    @ means that the function exceeded 100 msecs.
    $ means that the function exceeded 1 sec.
    ```

- task/pid字段，用来显示执行进程的cmdline和pid。默认disable：

    hide: echo nofuncgraph-proc > trace_options  
    show: echo funcgraph-proc > trace_options
    
    例如：
    
    ```
    # tracer: function_graph
    #
    # CPU  TASK/PID        DURATION                  FUNCTION CALLS
    # |    |    |           |   |                     |   |   |   |
    0)    sh-4802     |               |                  d_free() {
    0)    sh-4802     |               |                    call_rcu() {
    0)    sh-4802     |               |                      __call_rcu() {
    0)    sh-4802     |   0.616 us    |                        rcu_process_gp_end();
    0)    sh-4802     |   0.586 us    |                        check_for_new_grace_period();
    0)    sh-4802     |   2.899 us    |                      }
    0)    sh-4802     |   4.040 us    |                    }
    0)    sh-4802     |   5.151 us    |                  }
    0)    sh-4802     | + 49.370 us   |                }
    ```

- 绝对时间戳字段：

    hide: echo nofuncgraph-abstime > trace_options  
    show: echo funcgraph-abstime > trace_options
    
    例如：
    
    ```
    #
    #      TIME       CPU  DURATION                  FUNCTION CALLS
    #       |         |     |   |                     |   |   |   |
    360.774522 |   1)   0.541 us    |                                          }
    360.774522 |   1)   4.663 us    |                                        }
    360.774523 |   1)   0.541 us    |                                        __wake_up_bit();
    360.774524 |   1)   6.796 us    |                                      }
    360.774524 |   1)   7.952 us    |                                    }
    360.774525 |   1)   9.063 us    |                                  }
    360.774525 |   1)   0.615 us    |                                  journal_mark_dirty();
    360.774527 |   1)   0.578 us    |                                  __brelse();
    360.774528 |   1)               |                                  reiserfs_prepare_for_journal() {
    360.774528 |   1)               |                                    unlock_buffer() {
    360.774529 |   1)               |                                      wake_up_bit() {
    360.774529 |   1)               |                                        bit_waitqueue() {
    360.774530 |   1)   0.594 us    |                                          __phys_addr();
    ```

- 在函数结束括号处显示函数名。这样方便使用grep找出函数的执行时间，默认disable：

    hide: echo nofuncgraph-tail > trace_options  
    show: echo funcgraph-tail > trace_options
    
    例子nofuncgraph-tail (default)：
    
    ```
    0)               |      putname() {
    0)               |        kmem_cache_free() {
    0)   0.518 us    |          __phys_addr();
    0)   1.757 us    |        }
    0)   2.861 us    |      }
    ```
    
    例子funcgraph-tail：
    
    ```
    0)               |      putname() {
    0)               |        kmem_cache_free() {
    0)   0.518 us    |          __phys_addr();
    0)   1.757 us    |        } /* kmem_cache_free() */
    0)   2.861 us    |      } /* putname() */
    ```

- 还可以使用 trace_printk() 打印一些注释。可以在__might_sleep()中加一些注释，你可以include <linux/ftrace.h>然后在__might_sleep()中调用trace_printk()：

    ```
    trace_printk("I'm a comment!\n")
    ```

    将会产生：
    
    ```
    1)               |             __might_sleep() {
    1)               |                /* I'm a comment! */
    1)   1.449 us    |             }
    ```


# 15、dynamic ftrace

如果CONFIG_DYNAMIC_FTRACE被设置，系统在function tracing disbale时几乎没有开销。这种方式利用了gcc的-pg选项，会在每个函数的入口处放置mcount函数，初始时mcount函数只是一个简单的返回。

在编译c代码时kernel使用一个脚本解析c obj文件搜集出所有需要跟踪的mount函数的调用位置。gcc verson 4.6在x86中已经使用“__fentry__”替代了“mcount”。mount的调用在 函数stack frame创建之前。

不是所有的函数都需要跟踪的，notrace声明函数、inline函数都不需要跟踪，在 “available_filter_functions”中可以看到所有需要跟踪的函数名。

脚本创建了一个section “__mcount_loc” 用来存放所有mcount/fentry 的调用位置，这个section最后会被编译到kernel当中，被链接成一张表。

在boot up阶段，SMP启动之前，dynamic ftrace扫描“__mcount_loc”表并把所有的调用mcount替换成nop指令。在available_filter_functions列表中的函数会机型记录。驱动模块在load时在运行之前会处理，在驱动模块unload时会从ftrace function list中移除。这都是自动完成的，不需要驱动模块作者来担心的。

当tracing enable，修改插入点的方法依赖于架构。老机制使用kstop_machine来防止修改代码时多cpu的竞争；新机制放一个breakpoint 指令到修改的位置，同步cpu修改breakpoint没有覆盖的剩下指令，再次同步cpu移除掉breakpoint指令完成完整ftrace call的设置。

有些架构没有同步问题，可以直接使用新代码覆盖旧代码，其他CPU同时执行没有问题。

函数被跟踪后又较大的副作用。我们可以来选择哪些函数希望被trace、哪些函数希望保持nops指令。有两个文件用来配置这个功能：

set_ftrace_filter  
set_ftrace_notrace

我们把希望trace的函数加入到available_filter_functions文件中：

```
# cat available_filter_functions
put_prev_task_idle
kmem_cache_create
pick_next_task_rt
get_online_cpus
pick_next_task_fair
mutex_lock
[...]
```
    
如果我们只想跟踪sys_nanosleep 、hrtimer_interrupt：

```
# echo sys_nanosleep hrtimer_interrupt > set_ftrace_filter
# echo function > current_tracer
# echo 1 > tracing_on
# usleep 1
# echo 0 > tracing_on
# cat trace
# tracer: function
#
# entries-in-buffer/entries-written: 5/5   #P:4
#
#                              _-----=> irqs-off
#                             / _----=> need-resched
#                            | / _---=> hardirq/softirq
#                            || / _--=> preempt-depth
#                            ||| /     delay
#           TASK-PID   CPU#  ||||    TIMESTAMP  FUNCTION
#              | |       |   ||||       |         |
          usleep-2665  [001] ....  4186.475355: sys_nanosleep <-system_call_fastpath
          <idle>-0     [001] d.h1  4186.475409: hrtimer_interrupt <-smp_apic_timer_interrupt
          usleep-2665  [001] d.h1  4186.475426: hrtimer_interrupt <-smp_apic_timer_interrupt
          <idle>-0     [003] d.h1  4186.475426: hrtimer_interrupt <-smp_apic_timer_interrupt
          <idle>-0     [002] d.h1  4186.475427: hrtimer_interrupt <-smp_apic_timer_interrupt
```

看哪些函数被跟踪，同样可以cat文件查看：

```
# cat set_ftrace_filter
hrtimer_interrupt
sys_nanosleep
```

可能这些还不够，我们还运行块匹配：

```
<match>*
    will match functions that begin with <match>
*<match>
    will match functions that end with <match>
*<match>*
    will match functions that have <match> in it
<match1>*<match2>
    will match functions that begin with <match1> and end with <match2>
```

配置：

```
# echo 'hrtimer_*' > set_ftrace_filter
```

结果：

```
# tracer: function
#
# entries-in-buffer/entries-written: 897/897   #P:4
#
#                              _-----=> irqs-off
#                             / _----=> need-resched
#                            | / _---=> hardirq/softirq
#                            || / _--=> preempt-depth
#                            ||| /     delay
#           TASK-PID   CPU#  ||||    TIMESTAMP  FUNCTION
#              | |       |   ||||       |         |
          <idle>-0     [003] dN.1  4228.547803: hrtimer_cancel <-tick_nohz_idle_exit
          <idle>-0     [003] dN.1  4228.547804: hrtimer_try_to_cancel <-hrtimer_cancel
          <idle>-0     [003] dN.2  4228.547805: hrtimer_force_reprogram <-__remove_hrtimer
          <idle>-0     [003] dN.1  4228.547805: hrtimer_forward <-tick_nohz_idle_exit
          <idle>-0     [003] dN.1  4228.547805: hrtimer_start_range_ns <-hrtimer_start_expires.constprop.11
          <idle>-0     [003] d..1  4228.547858: hrtimer_get_next_event <-get_next_timer_interrupt
          <idle>-0     [003] d..1  4228.547859: hrtimer_start <-__tick_nohz_idle_enter
          <idle>-0     [003] d..2  4228.547860: hrtimer_force_reprogram <-__rem
```

注意sys_nanosleep的丢失：

```
# cat set_ftrace_filter
hrtimer_run_queues
hrtimer_run_pending
hrtimer_init
hrtimer_cancel
hrtimer_try_to_cancel
hrtimer_forward
hrtimer_start
hrtimer_reprogram
hrtimer_force_reprogram
hrtimer_get_next_event
hrtimer_interrupt
hrtimer_nanosleep
hrtimer_wakeup
hrtimer_get_remaining
hrtimer_get_res
hrtimer_init_sleeper
```

‘>’ 和 ‘>>’ 作用和在bash中相同。重写filter配置使用‘>’，追加filter配置使用‘>>’。
 
清除filter配置，所有的函数都将会被跟踪：

```
# echo > set_ftrace_filter
# cat set_ftrace_filter
#
```

使用追加方式：

```
# echo sys_nanosleep > set_ftrace_filter
# cat set_ftrace_filter
sys_nanosleep
# echo 'hrtimer_*' >> set_ftrace_filter
# cat set_ftrace_filter
hrtimer_run_queues
hrtimer_run_pending
hrtimer_init
hrtimer_cancel
hrtimer_try_to_cancel
hrtimer_forward
hrtimer_start
hrtimer_reprogram
hrtimer_force_reprogram
hrtimer_get_next_event
hrtimer_interrupt
sys_nanosleep
hrtimer_nanosleep
hrtimer_wakeup
hrtimer_get_remaining
hrtimer_get_res
hrtimer_init_sleeper
```

配置set_ftrace_notrace防止这些函数被跟踪：

```
# echo '*preempt*' '*lock*' > set_ftrace_notrace
```

结果：

```
# tracer: function
#
# entries-in-buffer/entries-written: 39608/39608   #P:4
#
#                              _-----=> irqs-off
#                             / _----=> need-resched
#                            | / _---=> hardirq/softirq
#                            || / _--=> preempt-depth
#                            ||| /     delay
#           TASK-PID   CPU#  ||||    TIMESTAMP  FUNCTION
#              | |       |   ||||       |         |
            bash-1994  [000] ....  4342.324896: file_ra_state_init <-do_dentry_open
            bash-1994  [000] ....  4342.324897: open_check_o_direct <-do_last
            bash-1994  [000] ....  4342.324897: ima_file_check <-do_last
            bash-1994  [000] ....  4342.324898: process_measurement <-ima_file_check
            bash-1994  [000] ....  4342.324898: ima_get_action <-process_measurement
            bash-1994  [000] ....  4342.324898: ima_match_policy <-ima_get_action
            bash-1994  [000] ....  4342.324899: do_truncate <-do_last
            bash-1994  [000] ....  4342.324899: should_remove_suid <-do_truncate
            bash-1994  [000] ....  4342.324899: notify_change <-do_truncate
            bash-1994  [000] ....  4342.324900: current_fs_time <-notify_change
            bash-1994  [000] ....  4342.324900: current_kernel_time <-current_fs_time
            bash-1994  [000] ....  4342.324900: timespec_trunc <-current_fs_time
```



## 15.1、Dynamic ftrace with the function graph tracer

如果你想看某个函数和他所有孩子的graph trace，可以使用set_graph_function来配置：

```
echo __do_fault > set_graph_function
```

结果，查看 __do_fault()扩展开的trace：

```
0)               |  __do_fault() {
0)               |    filemap_fault() {
0)               |      find_lock_page() {
0)   0.804 us    |        find_get_page();
0)               |        __might_sleep() {
0)   1.329 us    |        }
0)   3.904 us    |      }
0)   4.979 us    |    }
0)   0.653 us    |    _spin_lock();
0)   0.578 us    |    page_add_file_rmap();
0)   0.525 us    |    native_set_pte_at();
0)   0.585 us    |    _spin_unlock();
0)               |    unlock_page() {
0)   0.541 us    |      page_waitqueue();
0)   0.639 us    |      __wake_up_bit();
0)   2.786 us    |    }
0) + 14.237 us   |  }
0)               |  __do_fault() {
0)               |    filemap_fault() {
0)               |      find_lock_page() {
0)   0.698 us    |        find_get_page();
0)               |        __might_sleep() {
0)   1.412 us    |        }
0)   3.950 us    |      }
0)   5.098 us    |    }
0)   0.631 us    |    _spin_lock();
0)   0.571 us    |    page_add_file_rmap();
0)   0.526 us    |    native_set_pte_at();
0)   0.586 us    |    _spin_unlock();
0)               |    unlock_page() {
0)   0.533 us    |      page_waitqueue();
0)   0.638 us    |      __wake_up_bit();
0)   2.793 us    |    }
0) + 14.012 us   |  }
```

你也可以一次跟踪多个函数：

```
echo sys_open > set_graph_function
echo sys_close >> set_graph_function
```

如果你想跟踪所有的函数，清除filter配置：

```
echo > set_graph_function
```

# 16、ftrace_enabled

proc sysctl ftrace_enable是 function tracer的大开关。默认是enable，如果被disable所有相关的trace都会被disable，包括 (perf, kprobes, stack tracing, profiling, etc)。

请非常小心的disbale。

disbale和enbale动作如下：

```
 sysctl kernel.ftrace_enabled=0
 sysctl kernel.ftrace_enabled=1

or

 echo 0 > /proc/sys/kernel/ftrace_enabled
 echo 1 > /proc/sys/kernel/ftrace_enabled
```


# 17、Filter commands

支持通过一系列的command来设置set_ftrace_filter，配置filter。格式如下：

```
<function>:<command>:<parameter>
```

支持以下的command：

- mod: 该命令使能某个模块的过滤。parameter用来定义模块。例如，追踪ext3模块的write*函数：

    ```
    echo ‘write*:mod:ext3’ > set_ftrace_filter
    ```
    
    追加配置使用'>>'，移除特定模块的函数使用'!'前缀：
    
    ```
    echo '!writeback*:mod:ext3' >> set_ftrace_filter
    ```
    
    支持模块通配符。例如去掉所有的函数追踪除了某个模块：
    
    ```
    echo '!*:mod:!ext3' >> set_ftrace_filter
    ```
    
    去掉所有的模块追踪，但是非模块的kernel部分继续追踪：
    
    ```
    echo '!*:mod:*' >> set_ftrace_filter
    ```
    
    仅仅使能kernel部分的追踪：
    
    ```
    echo '*write*:mod:!*' >> set_ftrace_filter
    ```
    
    用mod通配符使能filter：
    
    ```
    echo '*write*:mod:*snd*' >> set_ftrace_filter
    ```
    
- traceon/traceoff: 这个命令在制定的函数被调用时打开/关闭tracing。parameter 定义函数命中多少次以后打开/关闭tracing，如果没有描述则不做限制。

    例如，disable tracing当schedule bug命中前5次：
    
    ```
    echo '__schedule_bug:traceoff:5' > set_ftrace_filter
    ```
    
    当__schedule_bug被命中时，一直关闭tracing：
    
    ```
    echo '__schedule_bug:traceoff' > set_ftrace_filter
    ```
    
    这些命令是累积的，无论你是否使用追加方式配置到set_ftrace_filter。如果要移除某个命令，使用‘!’前缀并且parameter次数drop到0：
    
    ```
    echo '!__schedule_bug:traceoff:0' > set_ftrace_filter
    ```
    
    移除没有counter的命令：
    
    ```
    echo '!__schedule_bug:traceoff' > set_ftrace_filter
    ```

- snapshot: 当函数命中时将会导致一个快照被触发：

    ```
    echo 'native_flush_tlb_others:snapshot' > set_ftrace_filter
    ```
    
    仅仅触发一次：
    
    ```
    echo 'native_flush_tlb_others:snapshot:1' > set_ftrace_filter
    ```
    
    移除上述的配置：
    
    ```
    echo '!native_flush_tlb_others:snapshot' > set_ftrace_filter
    echo '!native_flush_tlb_others:snapshot:0' > set_ftrace_filter
    ```
    
- enable_event/disable_event: 这些命令可以enable/disable trace event。因为function tracing回调都是非常敏感的，当这些命令注册，这些函数的tracepoint被active但是处于“soft disable”状态，它会被调用但是不会产生记录，这些tracepoint只是用来判断条件是否被触发。

    ```
    echo 'try_to_wake_up:enable_event:sched:sched_switch:2' > \
      set_ftrace_filter
    ```
    
    格式如下：
    
    ```
    <function>:enable_event:<system>:<event>[:count]
    <function>:disable_event:<system>:<event>[:count]
    ```
    
    移除配置：
    
    ```
    echo '!try_to_wake_up:enable_event:sched:sched_switch:0' > \
          set_ftrace_filter
    echo '!schedule:disable_event:sched:sched_switch' > \
          set_ftrace_filter
    ```
    
- dump: 当函数被命中会dump ringbuffer中所有内容到console。
- cpudump: 当函数被命中会dump当前cpu ringbuffer中所有内容到console。

# 18、trace_pipe

trace_pipe对比trace文件输出同样的内容，但是对tracing的影响不同。每次的trace_pipe读时消耗型的，连续读的内容是不同的，不会中止tracing。

```
# echo function > current_tracer
# cat trace_pipe > /tmp/trace.out &
[1] 4153
# echo 1 > tracing_on
# usleep 1
# echo 0 > tracing_on
# cat trace
# tracer: function
#
# entries-in-buffer/entries-written: 0/0   #P:4
#
#                              _-----=> irqs-off
#                             / _----=> need-resched
#                            | / _---=> hardirq/softirq
#                            || / _--=> preempt-depth
#                            ||| /     delay
#           TASK-PID   CPU#  ||||    TIMESTAMP  FUNCTION
#              | |       |   ||||       |         |

#
# cat /tmp/trace.out
           bash-1994  [000] ....  5281.568961: mutex_unlock <-rb_simple_write
           bash-1994  [000] ....  5281.568963: __mutex_unlock_slowpath <-mutex_unlock
           bash-1994  [000] ....  5281.568963: __fsnotify_parent <-fsnotify_modify
           bash-1994  [000] ....  5281.568964: fsnotify <-fsnotify_modify
           bash-1994  [000] ....  5281.568964: __srcu_read_lock <-fsnotify
           bash-1994  [000] ....  5281.568964: add_preempt_count <-__srcu_read_lock
           bash-1994  [000] ...1  5281.568965: sub_preempt_count <-__srcu_read_lock
           bash-1994  [000] ....  5281.568965: __srcu_read_unlock <-fsnotify
           bash-1994  [000] ....  5281.568967: sys_dup2 <-system_call_fastpath
```

注意，读trace_pipe将会阻塞直到更多的内容到来。


# 19、trace entries

数据过多或者不够在诊断内核问题时都是很麻烦的。buffer_size_kb 用来修改内部tracing buffer的大小，这个数字展示了每个cpu上的buffer大小，如果需要知道buffer的总和，乘以系统中cpu的数量。

```
# cat buffer_size_kb
1408 (units kilobytes)
```

读总大小：

```
# cat buffer_total_size_kb
5632
```

修改buffer大小：

```
# echo 10000 > buffer_size_kb
# cat buffer_size_kb
10000 (units kilobytes)
```

可以尽可能的分配的更多，但是如果你分配的过多，有可能会引起Out-Of-Memory：

```
# echo 1000000000000 > buffer_size_kb
-bash: echo: write error: Cannot allocate memory
# cat buffer_size_kb
85
```

per_cpu的buffer大小，可以独立的修改：

```
# echo 10000 > per_cpu/cpu0/buffer_size_kb
# echo 100 > per_cpu/cpu1/buffer_size_kb
```

当per_cpu的buffer大小不一致，buffer_size_kb 会显示X：

```
# cat buffer_size_kb
X
```

这种情况下，buffer_total_size_kb继续是有用的：

```
# cat buffer_total_size_kb
12916
```

给顶级的buffer_size_kb文件写值，将会重新把per_cpu buffer配置成相同。


# 20、Snapshot

配置CONFIG_TRACER_SNAPSHOT 将会使快照特性有效对于所有的non latency tracers。(Latency tracers仅仅记录最大延迟，例如“irqsoff” or “wakeup”，不能使用这个特性，因为它们已经在内部使用快照机制)

快照在一个特定时间点保留当前trace buffer而不停止跟踪。ftrace交换当前缓存区和备用缓存区，在新的当前缓存区(之前的备用缓存区)中继续跟踪。

以下是tracefs中关于这个特性的相关配置文件：

- snapshot:

    它用来拿到快照并且读出快照。Echo 1到文件会分配一个备份的缓存区并且进行交换，然后从快照中读内容使用和trace文件同样的格式输出。读快照和系统tracing并行进行。Echo 0到文件会释放备份缓存区，Echo其他的正值数会清除快照的内容。
    
    status\input | 0 | 1 | else
    ---|---|---|---
    not allocated | (do nothing) | alloc+swap | (do nothing)
    allocated | free | swap | clear
    
以下是snapshot的一个使用实例：

```
# echo 1 > events/sched/enable
# echo 1 > snapshot
# cat snapshot
# tracer: nop
#
# entries-in-buffer/entries-written: 71/71   #P:8
#
#                              _-----=> irqs-off
#                             / _----=> need-resched
#                            | / _---=> hardirq/softirq
#                            || / _--=> preempt-depth
#                            ||| /     delay
#           TASK-PID   CPU#  ||||    TIMESTAMP  FUNCTION
#              | |       |   ||||       |         |
          <idle>-0     [005] d...  2440.603828: sched_switch: prev_comm=swapper/5 prev_pid=0 prev_prio=120   prev_state=R ==> next_comm=snapshot-test-2 next_pid=2242 next_prio=120
           sleep-2242  [005] d...  2440.603846: sched_switch: prev_comm=snapshot-test-2 prev_pid=2242 prev_prio=120   prev_state=R ==> next_comm=kworker/5:1 next_pid=60 next_prio=120
[...]
        <idle>-0     [002] d...  2440.707230: sched_switch: prev_comm=swapper/2 prev_pid=0 prev_prio=120 prev_state=R ==> next_comm=snapshot-test-2 next_pid=2229 next_prio=120

# cat trace
# tracer: nop
#
# entries-in-buffer/entries-written: 77/77   #P:8
#
#                              _-----=> irqs-off
#                             / _----=> need-resched
#                            | / _---=> hardirq/softirq
#                            || / _--=> preempt-depth
#                            ||| /     delay
#           TASK-PID   CPU#  ||||    TIMESTAMP  FUNCTION
#              | |       |   ||||       |         |
          <idle>-0     [007] d...  2440.707395: sched_switch: prev_comm=swapper/7 prev_pid=0 prev_prio=120 prev_state=R ==> next_comm=snapshot-test-2 next_pid=2243 next_prio=120
 snapshot-test-2-2229  [002] d...  2440.707438: sched_switch: prev_comm=snapshot-test-2 prev_pid=2229 prev_prio=120 prev_state=S ==> next_comm=swapper/2 next_pid=0 next_prio=120
[...]
```

当你在latency tracers下尝试使用快照，将会得到以下结果：

```
# echo wakeup > current_tracer
# echo 1 > snapshot
bash: echo: write error: Device or resource busy
# cat snapshot
cat: snapshot: Device or resource busy
```
    

# 21、Instances

在tracefs中有个“instances”文件夹，这个文件夹可以使用mkdir创建新的子文件夹、使用rmdir删除子文件夹。如果子文件夹被创建，它默认包含以下文件和文件夹：

```
# mkdir instances/foo
# ls instances/foo
buffer_size_kb  buffer_total_size_kb  events  free_buffer  per_cpu
set_event  snapshot  trace  trace_clock  trace_marker  trace_options
trace_pipe  tracing_on
```

如你所见，新的文件夹类似于tracing文件夹本身。实际上，它是非常类似的，除了buffer和events 是不可知的也许来自主文件夹或者是来自其他创建的实例。

在新文件夹中的文件拥有和tracing中文件一样的名字，除了它使用独立的新的buffer。这些文件影响自己的buffer不影响主buffer，除了trace_options，当前trace_options的配置会影响所有的新实例和top buffer都会保持一样，以后会改进这一点。

注意文件夹中没有“function tracer”文件，也没有“current_tracer”和“available_tracers”文件，这是因为这个buffer当前只会给trace event使用。

```
# mkdir instances/foo
# mkdir instances/bar
# mkdir instances/zoot
# echo 100000 > buffer_size_kb
# echo 1000 > instances/foo/buffer_size_kb
# echo 5000 > instances/bar/per_cpu/cpu1/buffer_size_kb
# echo function > current_trace
# echo 1 > instances/foo/events/sched/sched_wakeup/enable
# echo 1 > instances/foo/events/sched/sched_wakeup_new/enable
# echo 1 > instances/foo/events/sched/sched_switch/enable
# echo 1 > instances/bar/events/irq/enable
# echo 1 > instances/zoot/events/syscalls/enable
# cat trace_pipe
CPU:2 [LOST 11745 EVENTS]
            bash-2044  [002] .... 10594.481032: _raw_spin_lock_irqsave <-get_page_from_freelist
            bash-2044  [002] d... 10594.481032: add_preempt_count <-_raw_spin_lock_irqsave
            bash-2044  [002] d..1 10594.481032: __rmqueue <-get_page_from_freelist
            bash-2044  [002] d..1 10594.481033: _raw_spin_unlock <-get_page_from_freelist
            bash-2044  [002] d..1 10594.481033: sub_preempt_count <-_raw_spin_unlock
            bash-2044  [002] d... 10594.481033: get_pageblock_flags_group <-get_pageblock_migratetype
            bash-2044  [002] d... 10594.481034: __mod_zone_page_state <-get_page_from_freelist
            bash-2044  [002] d... 10594.481034: zone_statistics <-get_page_from_freelist
            bash-2044  [002] d... 10594.481034: __inc_zone_state <-zone_statistics
            bash-2044  [002] d... 10594.481034: __inc_zone_state <-zone_statistics
            bash-2044  [002] .... 10594.481035: arch_dup_task_struct <-copy_process
[...]

# cat instances/foo/trace_pipe
            bash-1998  [000] d..4   136.676759: sched_wakeup: comm=kworker/0:1 pid=59 prio=120 success=1 target_cpu=000
            bash-1998  [000] dN.4   136.676760: sched_wakeup: comm=bash pid=1998 prio=120 success=1 target_cpu=000
          <idle>-0     [003] d.h3   136.676906: sched_wakeup: comm=rcu_preempt pid=9 prio=120 success=1 target_cpu=003
          <idle>-0     [003] d..3   136.676909: sched_switch: prev_comm=swapper/3 prev_pid=0 prev_prio=120 prev_state=R ==> next_comm=rcu_preempt next_pid=9 next_prio=120
     rcu_preempt-9     [003] d..3   136.676916: sched_switch: prev_comm=rcu_preempt prev_pid=9 prev_prio=120 prev_state=S ==> next_comm=swapper/3 next_pid=0 next_prio=120
            bash-1998  [000] d..4   136.677014: sched_wakeup: comm=kworker/0:1 pid=59 prio=120 success=1 target_cpu=000
            bash-1998  [000] dN.4   136.677016: sched_wakeup: comm=bash pid=1998 prio=120 success=1 target_cpu=000
            bash-1998  [000] d..3   136.677018: sched_switch: prev_comm=bash prev_pid=1998 prev_prio=120 prev_state=R+ ==> next_comm=kworker/0:1 next_pid=59 next_prio=120
     kworker/0:1-59    [000] d..4   136.677022: sched_wakeup: comm=sshd pid=1995 prio=120 success=1 target_cpu=001
     kworker/0:1-59    [000] d..3   136.677025: sched_switch: prev_comm=kworker/0:1 prev_pid=59 prev_prio=120 prev_state=S ==> next_comm=bash next_pid=1998 next_prio=120
[...]

# cat instances/bar/trace_pipe
     migration/1-14    [001] d.h3   138.732674: softirq_raise: vec=3 [action=NET_RX]
          <idle>-0     [001] dNh3   138.732725: softirq_raise: vec=3 [action=NET_RX]
            bash-1998  [000] d.h1   138.733101: softirq_raise: vec=1 [action=TIMER]
            bash-1998  [000] d.h1   138.733102: softirq_raise: vec=9 [action=RCU]
            bash-1998  [000] ..s2   138.733105: softirq_entry: vec=1 [action=TIMER]
            bash-1998  [000] ..s2   138.733106: softirq_exit: vec=1 [action=TIMER]
            bash-1998  [000] ..s2   138.733106: softirq_entry: vec=9 [action=RCU]
            bash-1998  [000] ..s2   138.733109: softirq_exit: vec=9 [action=RCU]
            sshd-1995  [001] d.h1   138.733278: irq_handler_entry: irq=21 name=uhci_hcd:usb4
            sshd-1995  [001] d.h1   138.733280: irq_handler_exit: irq=21 ret=unhandled
            sshd-1995  [001] d.h1   138.733281: irq_handler_entry: irq=21 name=eth0
            sshd-1995  [001] d.h1   138.733283: irq_handler_exit: irq=21 ret=handled
[...]

# cat instances/zoot/trace
# tracer: nop
#
# entries-in-buffer/entries-written: 18996/18996   #P:4
#
#                              _-----=> irqs-off
#                             / _----=> need-resched
#                            | / _---=> hardirq/softirq
#                            || / _--=> preempt-depth
#                            ||| /     delay
#           TASK-PID   CPU#  ||||    TIMESTAMP  FUNCTION
#              | |       |   ||||       |         |
            bash-1998  [000] d...   140.733501: sys_write -> 0x2
            bash-1998  [000] d...   140.733504: sys_dup2(oldfd: a, newfd: 1)
            bash-1998  [000] d...   140.733506: sys_dup2 -> 0x1
            bash-1998  [000] d...   140.733508: sys_fcntl(fd: a, cmd: 1, arg: 0)
            bash-1998  [000] d...   140.733509: sys_fcntl -> 0x1
            bash-1998  [000] d...   140.733510: sys_close(fd: a)
            bash-1998  [000] d...   140.733510: sys_close -> 0x0
            bash-1998  [000] d...   140.733514: sys_rt_sigprocmask(how: 0, nset: 0, oset: 6e2768, sigsetsize: 8)
            bash-1998  [000] d...   140.733515: sys_rt_sigprocmask -> 0x0
            bash-1998  [000] d...   140.733516: sys_rt_sigaction(sig: 2, act: 7fff718846f0, oact: 7fff71884650, sigsetsize: 8)
            bash-1998  [000] d...   140.733516: sys_rt_sigaction -> 0x0
```

可以看到，top trace buffer只显示function tracing，foo 实例显示wakeups和task switches。

移除实例，只需简单的删除文件夹：

```
# rmdir instances/foo
# rmdir instances/bar
# rmdir instances/zoot
```

如果实例中的文件正在open状态，rmdir将会返回EBUSY失败。

# 22、Stack trace

因为kernel拥有固定的堆栈大小，所以在函数中不浪费堆栈是非常重要的。内核开发者必须小心在堆栈上分配内存，如果分配过多，系统可能会有堆栈溢出的危险，并且会发生出错，通常导致系统panic。

有一些工具用来检查这个，但是通常是中断周期性的检查使用率。但是如果你能在每个函数调用中执行这个检查，那将变得非常有用。由于fTrace提供了function trace，因此在每个函数调用中检查堆栈大小是方便的。通过stack tracer来启用。

配置CONFIG_STACK_TRACER 将会包含ftrace stack tracing功能。写 ‘1’ 到 /proc/sys/kernel/stack_tracer_enabled，使能：

```
# echo 1 > /proc/sys/kernel/stack_tracer_enabled
```

也可以在kernel启动命令行中使能，在cmdline中增加“stacktrace” 参数。

运行一段时间后，看看输出：

```
# cat stack_max_size
2928

# cat stack_trace
        Depth    Size   Location    (18 entries)
        -----    ----   --------
  0)     2928     224   update_sd_lb_stats+0xbc/0x4ac
  1)     2704     160   find_busiest_group+0x31/0x1f1
  2)     2544     256   load_balance+0xd9/0x662
  3)     2288      80   idle_balance+0xbb/0x130
  4)     2208     128   __schedule+0x26e/0x5b9
  5)     2080      16   schedule+0x64/0x66
  6)     2064     128   schedule_timeout+0x34/0xe0
  7)     1936     112   wait_for_common+0x97/0xf1
  8)     1824      16   wait_for_completion+0x1d/0x1f
  9)     1808     128   flush_work+0xfe/0x119
 10)     1680      16   tty_flush_to_ldisc+0x1e/0x20
 11)     1664      48   input_available_p+0x1d/0x5c
 12)     1616      48   n_tty_poll+0x6d/0x134
 13)     1568      64   tty_poll+0x64/0x7f
 14)     1504     880   do_select+0x31e/0x511
 15)      624     400   core_sys_select+0x177/0x216
 16)      224      96   sys_select+0x91/0xb9
 17)      128     128   system_call_fastpath+0x16/0x1b
```


# 参考资料

[1、ftrace - Function Tracer](https://www.kernel.org/doc/html/latest/trace/ftrace.html)
