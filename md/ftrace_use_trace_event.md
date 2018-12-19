

参考原文：[Event Tracing](https://www.kernel.org/doc/html/latest/trace/events.html)

# 1、Introduction：

[Tracepoints](https://www.kernel.org/doc/Documentation/trace/tracepoints.txt)用来创建event tracing框架，而不需要使用创建模块来注册probe函数。

不是所有的tracpoint都能够使用event tracing系统来跟踪。内核开发者必须提供代码定义信息怎么保存到tracing buffer、已经信息怎么打印出来。

# 2、 Using Event Tracing

## 2.1、Via the ‘set_event’ interface

有哪些有效的trace event，可以查看“/sys/kernel/debug/tracing/available_events”文件。

启用特定event，如‘sched_wakeup’，简单的echo到 /sys/kernel/debug/tracing/set_event。例如：

```
# echo sched_wakeup >> /sys/kernel/debug/tracing/set_event
```

注意：需要使用‘>>’，否则会首先disable所有的events。

Disable event，在echo event name到set_event之前设置一个‘！’前缀：

```
# echo '!sched_wakeup' >> /sys/kernel/debug/tracing/set_event
```

Disable all events，echo一个空行到set_event中：

```
# echo > /sys/kernel/debug/tracing/set_event
```

Enable all events，echo *:* or *:到set_event中：

```
# echo *:* > /sys/kernel/debug/tracing/set_event
```

events被组织成subsystems，类似ext4, irq, sched,等等。一个完整的event name类似这样：<subsystem>:<event>。subsystem name是可选的，但是它显示在available_events文件中。一个subsystem钟所有的events可以通过 <subsystem>:*语法来表示，例如：enable所有的irq event：

```
# echo 'irq:*' > /sys/kernel/debug/tracing/set_event
```

## 2.2、Via the ‘enable’ toggle

所有有效的trace event同时会在“/sys/kernel/debug/tracing/events/”层次文件夹中列出。

enable event ‘sched_wakeup’:

```
# echo 1 > /sys/kernel/debug/tracing/events/sched/sched_wakeup/enable
```

disable:

```
# echo 0 > /sys/kernel/debug/tracing/events/sched/sched_wakeup/enable
```

enable sched subsystem中所有的events：

```
# echo 1 > /sys/kernel/debug/tracing/events/sched/enable
```

enable所有的events：

```
# echo 1 > /sys/kernel/debug/tracing/events/enable
```

当读enable文件时，可能会有以下4种结果：

```
0 - all events this file affects are disabled
1 - all events this file affects are enabled
X - there is a mixture of events enabled and disabled
? - this file does not affect any event
```

## 2.3、Boot option

为了早期启动时调试，可以使用以下boot选项：

```
trace_event=[event-list]
```

event-list是逗号分隔的event列表。

# 3、Defining an event-enabled tracepoint

怎么样定义一个event-enabled的tracepoint，可以参考内核代码：samples/trace_events

# 4、Event formats

每个trace event都有一个与它相关联的“format”文件，该文件包含log event中每个字段的描述。这个信息用来解析二进制的trace流，其中的字段也可以在event filter中找到对它的使用。

它还显示用于在文本模式下打印事件的格式字符串，以及用于分析的事件名称和ID。

每个event都有一系列通用的字段，全部都以“common_”作为前缀。其他的字段都需要在TRACE_EVENT()中定义。

format中的每个字段都有如下形式：

```
field:field-type field-name; offset:N; size:N;
```

offset是字段在trace record中的offset，size是数据项的size，都是byte单位。

举例，‘sched_wakeup’ event的format信息：

```
# cat /sys/kernel/debug/tracing/events/sched/sched_wakeup/format

name: sched_wakeup
ID: 60
format:
        field:unsigned short common_type;       offset:0;       size:2;
        field:unsigned char common_flags;       offset:2;       size:1;
        field:unsigned char common_preempt_count;       offset:3;       size:1;
        field:int common_pid;   offset:4;       size:4;
        field:int common_tgid;  offset:8;       size:4;

        field:char comm[TASK_COMM_LEN]; offset:12;      size:16;
        field:pid_t pid;        offset:28;      size:4;
        field:int prio; offset:32;      size:4;
        field:int success;      offset:36;      size:4;
        field:int cpu;  offset:40;      size:4;

print fmt: "task %s:%d [%d] success=%d [%03d]", REC->comm, REC->pid,
           REC->prio, REC->success, REC->cpu
```

这个event包含10个字段，5个通用字段5个自定义字段。此事件的所有字段都是数字的，除了“COMM”是一个字符串，这对于事件过滤非常重要。


# 5、Event filtering

trace event支持 ‘filter expressions’ 式的过滤。一旦trace event被记录到trace buffer中，其字段就针对与该event类型相关联的‘filter expressions’进行检查。如果event匹配filter将会被记录，否则将会被丢弃。如果event没有filter配置任何时刻都是匹配的，event默认就是no filter配置。

## 5.1、Expression syntax

一个filter expression由多个 ‘predicates’组成，它们使用逻辑操作符 ‘&&’、‘||’组合在一起。谓词只是一个子句，它将日志事件中包含的字段的值与常量值进行比较，并根据字段值匹配（1）或不匹配（0）返回0或1：

```
field-name relational-operator value
```

圆括号可以用来提供任意的逻辑分组，并且可以使用双引号防止shell将操作符解释为shell元字符。 

filter可以的字段名可以在对应event的‘format’文件中查看。

relational-operators依赖于需要测试的字段类型。

- 数字类的操作符包括：

    ```
    ==, !=, <, <=, >, >=, &
    ```

- 字符类的操作符包括：

    ```
    ==, !=, ~
    ```
    
    约等于操作符(~)接受通配符形式 (*,?)和字符类 ([)。举例：
    
    ```
    prev_comm ~ "*sh"
    prev_comm ~ "sh*"
    prev_comm ~ "*sh*"
    prev_comm ~ "ba*sh"
    ```

## 5.2、Setting filters

通过将filter expressions写入给定event的filter”文件，来设置单个event的filter。

举例：

```
# cd /sys/kernel/debug/tracing/events/sched/sched_wakeup
# echo "common_preempt_count > 4" > filter
```

一个涉及更多的例子：

```
# cd /sys/kernel/debug/tracing/events/signal/signal_generate
# echo "((sig >= 10 && sig < 15) || sig == 17) && comm != bash" > filter
```

如果表达式中存在错误，则在设置时会得到一个“Invalid argument”错误，错误的字符串连同错误消息可以通过查看过滤器来查看，例如：

```
# cd /sys/kernel/debug/tracing/events/signal/signal_generate
# echo "((sig >= 10 && sig < 15) || dsig == 17) && comm != bash" > filter
-bash: echo: write error: Invalid argument
# cat filter
((sig >= 10 && sig < 15) || dsig == 17) && comm != bash
^
parse_error: Field not found
```

目前，错误的插入符号（‘^’）总是出现在过滤器字符串的开头；即使没有更精确的位置信息，错误消息仍然应该是有用的。

## 5.3、Clearing filters

清除某个event的filter，echo 0 到对应event的filter文件。

清除某个subsystem中所有events的filter，echo 0 到对应subsystem的filter文件。

## 5.4、Subsystem filters

为了方便起见，可以将子系统中的每个事件的过滤器作为一个组来设置或清除，将一个过滤器表达式写入子系统根目录下的过滤器文件中。但是请注意，如果子系统内的任何事件的过滤器缺少子系统过滤器中指定的字段，或者如果过滤器不能应用于任何其他原因，则该事件的过滤器将保留其以前的设置。这可能导致过滤器的意外混合，这可能导致混淆（对可能认为不同的过滤器有效的用户）跟踪输出。只有引用公共字段的过滤器才能保证成功地传播到所有事件。

下面是几个子系统过滤器示例，也说明了以上几点：

清除sched subsystem中所有events的filter：

```
# cd /sys/kernel/debug/tracing/events/sched
# echo 0 > filter
# cat sched_switch/filter
none
# cat sched_wakeup/filter
none
```

使用sched subsystem中所有events都有的通用字段来设置filter(所有event将以同样的filter结束)：

```
# cd /sys/kernel/debug/tracing/events/sched
# echo common_pid == 0 > filter
# cat sched_switch/filter
common_pid == 0
# cat sched_wakeup/filter
common_pid == 0
```

尝试使用sched subsystem中非所有events通用字段来配置filter(所有没有prev_pid字段的event将保留原有的filter)：

```
# cd /sys/kernel/debug/tracing/events/sched
# echo prev_pid == 0 > filter
# cat sched_switch/filter
prev_pid == 0
# cat sched_wakeup/filter
common_pid == 0
```

## 5.5、 PID filtering

顶级文件夹下的set_event_pid 文件，可以给所有event配置PID过滤：

```
# cd /sys/kernel/debug/tracing
# echo $$ > set_event_pid
# echo 1 > events/enable
```

以上配置将会只追踪当前进程。

追加PID使用 ‘>>’：

```
# echo 123 244 1 >> set_event_pid
```

# 6、Event triggers

跟踪事件可以有条件地调用trigger ‘commands’，它可以采取各种形式并在下面详细描述；示例将enabling or disabling其他trace event，或者在trace event命中时调用stack trace。每当调用具有附加触发器的trace event时，就会调用与该event相关联的 trigger commands。任何给定的触发器还可以具有与它相关联的第5节（事件过滤）中描述的相同形式的事件过滤器。如果调用的事件通过关联的筛选器，则该命令将被调用。如果没有与触发器关联的过滤器，它总是通过。

Triggers将会从event上增加或者移除，通过将触发表达式写入给定event的“trigger”文件。

给定的event可以有任意数量的trigger与它相关联，个别命令可能在这方面有所限制。

Event triggers是在“soft”模式上实现的，这意味如果一个event有一个或者多个trigger与之相关联，即使该event是disable状态但实质上已经被actived，然后在“soft”模式中被disable。也就是说，tracepoint 将被调用，但将不会被跟踪，除非它被正式的enable。该方案允许即使disable的event也可以调用trigger，并且还允许当前event filter实现用于有条件地调用trigger。


设置event triggers的语法大约基于设置set_ftrace_filter ‘ftrace filter commands’ 的语法（可以参考‘Filter commands’ section of [Documentation/trace/ftrace.txt](https://www.kernel.org/doc/html/latest/trace/ftrace.html)），但存在很大的差异，并且实现目前并没有以任何方式与之联系，因此要小心在两者之间进行相等。 

## 6.1、Expression syntax

使用echo command 到‘trigger’文件的形式来增加Trigger：

```
# echo 'command[:count] [if filter]' > trigger
```

移除Trigger使用同样的命令，但是加上了 ‘!’ 前缀：

```
# echo '!command[:count] [if filter]' > trigger
```

在移除Trigger时 [if filter]部分不参与匹配，所以可以让其在‘!’ command中缺席也可以完成同样的功能。

filter部分的语法和上一节 ‘Event filtering’ 中描述的相同。

为了方便使用，当前filter只支持使用‘>’增加或删除单条trigger，没有明确的 ‘>>’ 支持(实际上‘>’的作用就相当于‘>>’)或者截短支持移除所有的trigger(必须使用‘!’命令逐条移除)。

## 6.2、Supported trigger commands

支持以下命令：

- enable_event/disable_event

    这些命令可以enable or disable其他的trace event，当triggering event被命中时。当这些命令被注册，其他的trace event变为active，但是在“soft” mode下disable。这时，tracepoint会被调用但是不会被trace。这些event tracepoint一直呆在这种模式中一直到trigger被触发。
    
    举例，以下的trigger导致kmalloc events被trace当一个read系统调用进入，:1 表明该行为只发生一次：
    
    ```
    # echo 'enable_event:kmem:kmalloc:1' > \
    /sys/kernel/debug/tracing/events/syscalls/sys_enter_read/trigger
    ```
    
    以下的trigger导致kmalloc events被disable trace当一个read系统调用退出，每次退出都会调用：
    
    ```
    # echo 'disable_event:kmem:kmalloc' > \
    /sys/kernel/debug/tracing/events/syscalls/sys_exit_read/trigger
    ```
    
    命令格式如下：
    
    ```
    enable_event:<system>:<event>[:count]
    disable_event:<system>:<event>[:count]
    ```
    
    移除命令：
    
    ```
    # echo '!enable_event:kmem:kmalloc:1' > \
        /sys/kernel/debug/tracing/events/syscalls/sys_enter_read/trigger
    
    # echo '!disable_event:kmem:kmalloc' > \
        /sys/kernel/debug/tracing/events/syscalls/sys_exit_read/trigger
    ```
    
    注意：每个 triggering event可以有任意多个触发动作，但是每种触发动作只能有一个。例如，sys_enter_read可以触发enable kmem:kmalloc和sched:sched_switch，但是kmem:kmalloc不能有两个版本kmem:kmalloc and kmem:kmalloc:1或者是‘kmem:kmalloc if bytes_req == 256’ and ‘kmem:kmalloc if bytes_alloc == 256’(他们开源组合成单个filter在kmem:kmalloc event中)
    
- stacktrace

    这个命令在trace buffer中dump出堆栈调用，在triggering event发生时。
    
    举例，以下的trigger dump出堆栈调用，在每次kmalloc tracepoint被命中：
    
    ```
    # echo 'stacktrace' > \
      /sys/kernel/debug/tracing/events/kmem/kmalloc/trigger
    ```
    
    以下的trigger dump出堆栈调用，在kmalloc请求bytes_req >= 65536的前5次
    
    ```
    # echo 'stacktrace:5 if bytes_req >= 65536' > \
        /sys/kernel/debug/tracing/events/kmem/kmalloc/trigger
    ```
    
    命令格式如下：
    
    ```
    stacktrace[:count]
    ```
    
    移除命令：
    
    ```
    # echo '!stacktrace' > \
          /sys/kernel/debug/tracing/events/kmem/kmalloc/trigger
    
    # echo '!stacktrace:5 if bytes_req >= 65536' > \
          /sys/kernel/debug/tracing/events/kmem/kmalloc/trigger
    ```
    
    后者也可以通过下面的（没有过滤器）更简单地去除：
    
    ```
    # echo '!stacktrace:5' > \
      /sys/kernel/debug/tracing/events/kmem/kmalloc/trigger
    ```
    
    注意：每个trace event只能有一个stacktrace触发器。
    
- snapshot

    这个命令导致snapshot被触发当triggering event发生时。
    
    以下命令每次创建一个snapshot当block request queue被unplugged并且depth > 1。如果你想trace一系列的events or functions，快照trace buffer将会抓住这些events，在 trigger event发生时：
    
    ```
    # echo 'snapshot if nr_rq > 1' > \
      /sys/kernel/debug/tracing/events/block/block_unplug/trigger
    ```
    
    只snapshot一次：
    
    ```
    # echo 'snapshot:1 if nr_rq > 1' > \
      /sys/kernel/debug/tracing/events/block/block_unplug/trigger
    ```
    
    移除命令：
    
    ```
    # echo '!snapshot if nr_rq > 1' > \
          /sys/kernel/debug/tracing/events/block/block_unplug/trigger
    
    # echo '!snapshot:1 if nr_rq > 1' > \
          /sys/kernel/debug/tracing/events/block/block_unplug/trigger
    ```
    
    注意：每个trace event只能有一个snapshot触发器。
    
- traceon/traceoff
    
    这个命令将会把整个trace tracing on/off当event被命中。parameter 决定了系统 turned on/off 多少次。没有描述就是无限制。

    以下命令将 turns tracing off 在block request queue第一次unplugged并且depth > 1，如果您当时正在跟踪一组事件或函数，则可以检查跟踪缓冲区，以查看导致触发事件的事件序列：
    
    ```
    # echo 'traceoff:1 if nr_rq > 1' > \
      /sys/kernel/debug/tracing/events/block/block_unplug/trigger
    ```
    
    一直disable tracing 当nr_rq > 1:
    
    ```
    # echo 'traceoff if nr_rq > 1' > \
          /sys/kernel/debug/tracing/events/block/block_unplug/trigger
    ```
    
    移除命令：
    
    ```
    # echo '!traceoff:1 if nr_rq > 1' > \
          /sys/kernel/debug/tracing/events/block/block_unplug/trigger
    
    # echo '!traceoff if nr_rq > 1' > \
          /sys/kernel/debug/tracing/events/block/block_unplug/trigger
    ```
    
    注意：每个trace event只能有一个traceon or traceoff触发器。
    
- hist

    组合触发。这个命令聚合多个trace event的字段到一个hash表中。

    查看[Documentation/trace/histogram.txt](https://www.kernel.org/doc/Documentation/trace/histogram.txt)更多的细节和用例。
    


# 参考资料

[1、Event Tracing](https://www.kernel.org/doc/html/latest/trace/events.html)