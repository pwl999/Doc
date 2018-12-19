关于bpf最早是应用于network的filter，后续才被应用到trace，所以kernel中关于bpf的文档是"Documentation/networking/filter.txt"。

参考原文：[Linux Socket Filtering aka Berkeley Packet Filter (BPF)](https://www.kernel.org/doc/Documentation/networking/filter.txt)

# 1、简介：

LSF(Linux Socket Filtering)是从BPF(Berkeley Packet Filter)派生而来。尽管BSD和Linux kernel的过滤(filter)有一些明显的区别，但是当我们在linux环境中谈到BPF或LSF时，我们指的在Linux kernel中完全相同的过滤机制。

BPF允许用户空间程序将一个过滤(filter)附加到任何的套接字(socket)上面用来允许或不允许某些类型的数据通过socket。LSF遵循和BSD's BPF相同的filter代码架构，所以参考BSD bpf.4的man手册在创建filter时非常有帮助。

在Linux上，BPF比在BSD上简单的多。不需要担心devices之类的事情。你只需要简单的创建你的filter代码，通过SO_ATTTACH_FILTER选项发送到内核，并且你的filter代码能通过内核的检查，这样你就可以立即过滤socket上面的数据了。

你还可以通过SO_DETACH_FILTER选项把filter从socket上移除。这可能不会被经常使用，因为当你关闭socket的时候如果有filter会被自动移除。另外一个不太常见的情况是在同一个socket上添加不同的filter，当你还有另一个filter正在运行：如果你的新filter代码能够通过内核检查，内核小心的把旧的filter移除把新的filter换上，如果检查失败旧的filter将继续保留在socket上。

SO_LOCK_FILTER选项运行锁定附加到socket上的filter。一旦设置，filter不能被移除或者改变。这种允许一个进程设置一个socket、附加一个filter、锁定它们并放弃特权，确保这个filter保持到socket的关闭。

这个构造最大的用户是libpcap。发布一个高级别的filter命令类似'tcpdump -i em1 port 22'，通过libpcap内部的编译器生成一个结构，最终通过SO_ATTACH_FILTER加载到内核。'tcpdump -i em1 port 22 -ddd'命令能够显示放到这个结构中的内容。

尽管我们这里只是讨论了soket，BPF在linux中应用到了很多地方。xt_bpf对netfilter，cls_bpf在内核的qdisk层，SECCOMP-BPF(SECure COMPuting[^seccomp_filter])，以及一系列其他地方例如：team driver、PTP code等BPF都被用到。

[^seccomp_filter]: [Documentation/userspace-api/seccomp_filter.rst](Documentation/userspace-api/seccomp_filter.rst)

原始的BPF论文：  
Steven McCanne和Van Jacobson, 1993。“The BSD packet filter: a new
architecture for user-level packet capture. ”。在USENIX冬季1993会议论文集会议论文集(USENIX ' 93)。USENIX协会伯克利分校美国CA,2 - 2。[http://www.tcpdump.org/papers/bpf-usenix93.pdf](http://www.tcpdump.org/papers/bpf-usenix93.pdf)

# 2、filter code结构

用户空间的应用include <linux/filter.h>头文件包含以下的相关结构：

```
struct sock_filter {	/* Filter block */
	__u16	code;   /* Actual filter code */
	__u8	jt;	/* Jump true */
	__u8	jf;	/* Jump false */
	__u32	k;      /* Generic multiuse field */
};
```

这样的结构被组装成一个4元数组，包含：code、jt、jf和K值。jt和jf是跳转偏移量，k是一个通用值提供给code使用。

```
struct sock_fprog {			/* Required for SO_ATTACH_FILTER. */
	unsigned short		   len;	/* Number of filter blocks */
	struct sock_filter __user *filter;
};
```

对socket过滤，一个指向上述结构的指针通过setsockopt(2)系统调用传递给内核。

## 2.1、filter实例

```
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
/* ... */

/* From the example above: tcpdump -i em1 port 22 -dd */
struct sock_filter code[] = {
	{ 0x28,  0,  0, 0x0000000c },
	{ 0x15,  0,  8, 0x000086dd },
	{ 0x30,  0,  0, 0x00000014 },
	{ 0x15,  2,  0, 0x00000084 },
	{ 0x15,  1,  0, 0x00000006 },
	{ 0x15,  0, 17, 0x00000011 },
	{ 0x28,  0,  0, 0x00000036 },
	{ 0x15, 14,  0, 0x00000016 },
	{ 0x28,  0,  0, 0x00000038 },
	{ 0x15, 12, 13, 0x00000016 },
	{ 0x15,  0, 12, 0x00000800 },
	{ 0x30,  0,  0, 0x00000017 },
	{ 0x15,  2,  0, 0x00000084 },
	{ 0x15,  1,  0, 0x00000006 },
	{ 0x15,  0,  8, 0x00000011 },
	{ 0x28,  0,  0, 0x00000014 },
	{ 0x45,  6,  0, 0x00001fff },
	{ 0xb1,  0,  0, 0x0000000e },
	{ 0x48,  0,  0, 0x0000000e },
	{ 0x15,  2,  0, 0x00000016 },
	{ 0x48,  0,  0, 0x00000010 },
	{ 0x15,  0,  1, 0x00000016 },
	{ 0x06,  0,  0, 0x0000ffff },
	{ 0x06,  0,  0, 0x00000000 },
};

struct sock_fprog bpf = {
	.len = ARRAY_SIZE(code),
	.filter = code,
};

sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
if (sock < 0)
	/* ... bail out ... */

ret = setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf));
if (ret < 0)
	/* ... bail out ... */

/* ... */
close(sock);
```

上述实例代码附加一个socket filter到一个PF_PACKET socket上，为了让所有IPv4/IPv6 port 22的包通过。这个socket上所有其他的包将会被丢弃。

setsockopt(2)调用SO_DETACH_FILTER不需要任何参数，调用SO_LOCK_FILTER来预防filter被解绑附带一个整数参数0或1.

注意socket filter没有限制仅仅用在PF_PACKET socket上，也可以用于其他socket家族。

相关系统调用概要：

```
 * setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_FILTER, &val, sizeof(val));
 * setsockopt(sockfd, SOL_SOCKET, SO_DETACH_FILTER, &val, sizeof(val));
 * setsockopt(sockfd, SOL_SOCKET, SO_LOCK_FILTER,   &val, sizeof(val));
```

通常，大多数对包socket上socket filter的使用已经被libpcap高层次的语法所覆盖，作为应用开发人员应当坚持使用。libpcap wraps是它的封装层。

除非：

- i) 使用/链接libpcap不是选项；  
- ii) 需要的BPF filter使用了linux扩展，libpcap的编译器不支持；  
- iii) filter可能更复杂，不能由libpcap编译器清晰的实现；  
- iv) 特定的filter代码需要被优化成和libpcap内部编译器不同，在这种情况下“手工”编写filter可能是一种选择。例如，xt_bpf和cls_bpf用户有可能产生的需求需要更复杂的filter代码或者不能使用libpcap表达(例如不同代码路径对应不同返回码)。此外，BPF JIT实现者希望手工写测试用例，因此需要低层次的访问BPF代码。

# 3、BPF引擎和指令集

在/tools/bpf路径下有个小的辅助工具叫做bpf_asm，它可以用来写低层次的filter例如上一节提到的实例场景。这里提到的asm类似的语法在bsp_asm中实现，并且会用来做进一步的解析(用来替代直接操作可读性差的opcodes，原理上是相同的)。语法以 Steven McCanne's和Van Jacobson's的BPF论文为原型。

BPF架构以下列基本的元素组成：

<table border="1">
<caption> BPF architecture element </caption>

<tr>
<th style="width: 200px;">Element</th>
<th style="width: 600px;">Description</th>
</tr>

<tr>
<td> A </td>
<td>
32 bit wide accumulator
</td>
</tr>

<tr>
<td> X </td>
<td>
32 bit wide X register
</td>
</tr>

<tr>
<td> M[] </td>
<td>
16 x 32 bit wide misc registers aka "scratch memory store", addressable from 0 to 15
</td>
</tr>

</table>

一个程序可以被bpf_asm翻译成"opcodes"，即一个由下列元素组成的数组：

```
op:16, jt:8, jf:8, k:32
```

其中op元素是一个16位宽的操作码，具有特定的指令编码。jt和jf是两个8位宽的跳转目标，一个用于条件“跳转如果真”，另一个“跳转如果假”。最后k元素包含一个可以用不同方式解析的杂项参数，依赖于op给定的指令。

指令集由load、store、branch、alu、misc和return几种类型的指令组成，这些指令也使用bpf_asm语法表示。这个表列出了bpf_asm所有的指令。他们的底层opcode在linux/filter.h中定义：

<table border="1">
<caption> BPF instruction set </caption>

<tr>
<th style="width: 200px;">Instruction</th>
<th style="width: 200px;">Addressing mode</th>
<th style="width: 400px;">Description</th>
</tr>

<tr>
<td> ld </td>
<td>
1, 2, 3, 4, 10
</td>
<td>
Load word into A
</td>
</tr>

<tr>
<td> ldi </td>
<td>
4
</td>
<td>
Load word into A
</td>
</tr>

<tr>
<td> ldh </td>
<td>
1, 2
</td>
<td>
Load half-word into A
</td>
</tr>

<tr>
<td> ldb </td>
<td>
1, 2
</td>
<td>
Load byte into A
</td>
</tr>

<tr>
<td> ldx </td>
<td>
3, 4, 5, 10
</td>
<td>
Load word into X
</td>
</tr>

<tr>
<td> ldxi </td>
<td>
4
</td>
<td>
Load word into X
</td>
</tr>

<tr>
<td> ldxb </td>
<td>
5
</td>
<td>
Load word into X
</td>
</tr>

<tr>
<td>   </td>
<td>
</td>
<td>
</td>
</tr>

<tr>
<td> st </td>
<td>
3
</td>
<td>
Store A into M[]
</td>
</tr>

<tr>
<td> stx </td>
<td>
3
</td>
<td>
Store X into M[]
</td>
</tr>

<tr>
<td>   </td>
<td>
</td>
<td>
</td>
</tr>

<tr>
<td> jmp </td>
<td>
6
</td>
<td>
Jump to label
</td>
</tr>

<tr>
<td> ja </td>
<td>
6
</td>
<td>
Jump to label
</td>
</tr>

<tr>
<td> jeq </td>
<td>
7, 8
</td>
<td>
Jump on A == k
</td>
</tr>

<tr>
<td> jneq </td>
<td>
8
</td>
<td>
Jump on A != k
</td>
</tr>

<tr>
<td> jne </td>
<td>
8
</td>
<td>
Jump on A != k
</td>
</tr>

<tr>
<td> jlt </td>
<td>
8
</td>
<td>
Jump on A <  k
</td>
</tr>

<tr>
<td> jle </td>
<td>
8
</td>
<td>
Jump on A <= k
</td>
</tr>

<tr>
<td> jgt </td>
<td>
7, 8
</td>
<td>
Jump on A >  k
</td>
</tr>

<tr>
<td> jge </td>
<td>
7, 8
</td>
<td>
Jump on A >= k
</td>
</tr>

<tr>
<td> jset </td>
<td>
7, 8
</td>
<td>
Jump on A &  k
</td>
</tr>

<tr>
<td>   </td>
<td>
</td>
<td>
</td>
</tr>

<tr>
<td> add </td>
<td>
0, 4
</td>
<td>
A + <x>
</td>
</tr>

<tr>
<td> sub </td>
<td>
0, 4
</td>
<td>
A - <x>
</td>
</tr>

<tr>
<td> mul </td>
<td>
0, 4
</td>
<td>
A * <x>
</td>
</tr>

<tr>
<td> div </td>
<td>
0, 4
</td>
<td>
A / <x>
</td>
</tr>

<tr>
<td> mod </td>
<td>
0, 4
</td>
<td>
A % <x>
</td>
</tr>

<tr>
<td> neg </td>
<td>
 
</td>
<td>
!A
</td>
</tr>

<tr>
<td> and </td>
<td>
0, 4
</td>
<td>
A & <x>
</td>
</tr>

<tr>
<td> or </td>
<td>
0, 4
</td>
<td>
A | <x>
</td>
</tr>

<tr>
<td> xor </td>
<td>
0, 4
</td>
<td>
A ^ <x>
</td>
</tr>

<tr>
<td> lsh </td>
<td>
0, 4
</td>
<td>
A << <x>
</td>
</tr>

<tr>
<td> rsh </td>
<td>
0, 4
</td>
<td>
A >> <x>
</td>
</tr>

<tr>
<td>   </td>
<td>
</td>
<td>
</td>
</tr>

<tr>
<td> tax </td>
<td>

</td>
<td>
Copy A into X
</td>
</tr>

<tr>
<td> txa </td>
<td>

</td>
<td>
Copy X into A
</td>
</tr>

<tr>
<td>   </td>
<td>
</td>
<td>
</td>
</tr>

<tr>
<td> ret </td>
<td>
4, 9
</td>
<td>
Return
</td>
</tr>

</table>

下表用来解释第二列的寻址格式：

<table border="1">
<caption> BPF Addressing mode </caption>

<tr>
<th style="width: 200px;">Addressing mode</th>
<th style="width: 200px;">Syntax</th>
<th style="width: 400px;">Description</th>
</tr>

<tr>
<td> 0 </td>
<td>
x/%x
</td>
<td>
Register X
</td>
</tr>

<tr>
<td> 1 </td>
<td>
[k]
</td>
<td>
BHW at byte offset k in the packet
</td>
</tr>

<tr>
<td> 2 </td>
<td>
[x + k]
</td>
<td>
BHW at the offset X + k in the packet
</td>
</tr>

<tr>
<td> 3 </td>
<td>
M[k]
</td>
<td>
Word at offset k in M[]
</td>
</tr>

<tr>
<td> 4 </td>
<td>
#k
</td>
<td>
Literal value stored in k
</td>
</tr>

<tr>
<td> 5 </td>
<td>
4*([k]&0xf)
</td>
<td>
Lower nibble * 4 at byte offset k in the packet
</td>
</tr>

<tr>
<td> 6 </td>
<td>
L
</td>
<td>
Jump label L
</td>
</tr>

<tr>
<td> 7 </td>
<td>
#k,Lt,Lf
</td>
<td>
Jump to Lt if true, otherwise jump to Lf
</td>
</tr>

<tr>
<td> 8 </td>
<td>
#k,Lt
</td>
<td>
Jump to Lt if predicate is true
</td>
</tr>

<tr>
<td> 9 </td>
<td>
a/%a
</td>
<td>
Accumulator A
</td>
</tr>

<tr>
<td> 10 </td>
<td>
extension
</td>
<td>
BPF extension
</td>
</tr>

</table>

Linux内核也有一些BPF扩展和load类的指令一起使用，用负偏移量+特定扩展偏移来“重载”k参数。这些BPF扩展的结构被加载到A中。

可能的BPF扩展如下表：

<table border="1">
<caption> BPF extensions </caption>

<tr>
<th style="width: 200px;">Extension</th>
<th style="width: 400px;">Description</th>
</tr>

<tr>
<td> len </td>
<td>
skb->len
</td>
</tr>

<tr>
<td> proto </td>
<td>
skb->protocol
</td>
</tr>

<tr>
<td> type </td>
<td>
skb->pkt_type
</td>
</tr>

<tr>
<td> poff </td>
<td>
Payload start offset
</td>
</tr>

<tr>
<td> ifidx </td>
<td>
skb->dev->ifindex
</td>
</tr>

<tr>
<td> nla </td>
<td>
Netlink attribute of type X with offset A
</td>
</tr>

<tr>
<td> nlan </td>
<td>
Nested Netlink attribute of type X with offset A
</td>
</tr>

<tr>
<td> mark </td>
<td>
skb->mark
</td>
</tr>

<tr>
<td> queue </td>
<td>
skb->queue_mapping
</td>
</tr>

<tr>
<td> hatype </td>
<td>
skb->dev->type
</td>
</tr>

<tr>
<td> rxhash </td>
<td>
skb->hash
</td>
</tr>

<tr>
<td> cpu </td>
<td>
raw_smp_processor_id()
</td>
</tr>

<tr>
<td> vlan_tci </td>
<td>
skb_vlan_tag_get(skb)
</td>
</tr>

<tr>
<td> vlan_avail </td>
<td>
skb_vlan_tag_present(skb)
</td>
</tr>

<tr>
<td> vlan_tpid </td>
<td>
skb->vlan_proto
</td>
</tr>

<tr>
<td> rand </td>
<td>
prandom_u32()
</td>
</tr>

</table>

这些扩展也使用'#'前缀。

以下是低层级BPF的实例：

- ARP packets:

```
  ldh [12]
  jne #0x806, drop
  ret #-1
  drop: ret #0
```

- IPv4 TCP packets:

```
  ldh [12]
  jne #0x800, drop
  ldb [23]
  jneq #6, drop
  ret #-1
  drop: ret #0
```

- Accelerated) VLAN w/ id 10:

```
  ld vlan_tci
  jneq #10, drop
  ret #-1
  drop: ret #0
```

- icmp random packet sampling, 1 in 4

```
  ldh [12]
  jne #0x800, drop
  ldb [23]
  jneq #1, drop
  # get a random uint32 number
  ld rand
  mod #4
  jneq #1, drop
  ret #-1
  drop: ret #0
```

- SECCOMP filter example:

```
  ld [4]                  /* offsetof(struct seccomp_data, arch) */
  jne #0xc000003e, bad    /* AUDIT_ARCH_X86_64 */
  ld [0]                  /* offsetof(struct seccomp_data, nr) */
  jeq #15, good           /* __NR_rt_sigreturn */
  jeq #231, good          /* __NR_exit_group */
  jeq #60, good           /* __NR_exit */
  jeq #0, good            /* __NR_read */
  jeq #1, good            /* __NR_write */
  jeq #5, good            /* __NR_fstat */
  jeq #9, good            /* __NR_mmap */
  jeq #14, good           /* __NR_rt_sigprocmask */
  jeq #13, good           /* __NR_rt_sigaction */
  jeq #35, good           /* __NR_nanosleep */
  bad: ret #0             /* SECCOMP_RET_KILL_THREAD */
  good: ret #0x7fff0000   /* SECCOMP_RET_ALLOW */
```

上述实例代码可以放进一个文件(这里称为“foo”)，然后传递给bpf_asm工具生成操作码，输出xt_bpf和cls_bpf可以理解的并加载。例如上述的ARP代码：

```
$ ./bpf_asm foo
4,40 0 0 12,21 0 1 2054,6 0 0 4294967295,6 0 0 0,
```

拷贝并粘贴成类似C的输出：

```
$ ./bpf_asm -c foo
{ 0x28,  0,  0, 0x0000000c },
{ 0x15,  0,  1, 0x00000806 },
{ 0x06,  0,  0, 0xffffffff },
{ 0x06,  0,  0, 0000000000 },
```

特别是在使用xt_bpf或cls_bpf会导致更复杂的BPF filter，这种起先可能并不明显，在连接到活动系统前先进行测试时非常好的。为此，在tools/bpf路径下有个名为bpd_dbg的小工具。这个调试器运行测试BPF filter针对给定的pcap文件，在pcap包上单步执行BPF代码并且进行BPF虚拟机的寄存器dump。

启动bpf_dbg很简单，只需要发出:

```
# ./bpf_dbg
```

如果输入和输出不等于stdin/stdout, bpf_dbg将一个可选的stdin源作为第一个参数，另一个可选的stdout sink作为第二个参数，例如:`./bpf_dbg test_in.txt test_out.txt`

除此之外，还可以通过文件“~/”设置特定的libreadline配置。命令历史存储在文件~/.bpf_dbg_history中。

bpf_dbg中的交互是通过一个具有自动完成支持的shell进行的(以'>'开头的后续示例命令表示bpf_dbg shell)。

- 通常的工作流程是……

```
> load bpf 6,40 0 0 12,21 0 3 2048,48 0 0 23,21 0 1 1,6 0 0 65535,6 0 0 0
```

加载一个BPF filter通过bpf_asm的标准输出，或者类似`tcpdump -iem1 -ddd port 22 | tr '\n' ','`命令的转换。注意对JIT调试来说，该命令创建一个临时socket并且加载BPF代码到内核。因此对JIT开发人员也是很有用的。

```
> load pcap foo.pcap
```

加载标准的tcpdump pcap文件。

```
> run [<n>]
bpf passes:1 fails:9
```

运行pcap中的所有包，以计算过滤器将生成多少次传递和失败。可以给出要遍历的包的限制。

```
> disassemble
l0:	ldh [12]
l1:	jeq #0x800, l2, l5
l2:	ldb [23]
l3:	jeq #0x1, l4, l5
l4:	ret #0xffff
l5:	ret #0
```

打印出BPF反汇编代码。

```
> dump
/* { op, jt, jf, k }, */
{ 0x28,  0,  0, 0x0000000c },
{ 0x15,  0,  3, 0x00000800 },
{ 0x30,  0,  0, 0x00000017 },
{ 0x15,  0,  1, 0x00000001 },
{ 0x06,  0,  0, 0x0000ffff },
{ 0x06,  0,  0, 0000000000 },
```

打印出C风格的BPF code dump。

```
> dump
/* { op, jt, jf, k }, */
{ 0x28,  0,  0, 0x0000000c },
{ 0x15,  0,  3, 0x00000800 },
{ 0x30,  0,  0, 0x00000017 },
{ 0x15,  0,  1, 0x00000001 },
{ 0x06,  0,  0, 0x0000ffff },
{ 0x06,  0,  0, 0000000000 },
```

在特定BPF指令上设置断点。发出' run '命令将遍历pcap文件，从当前包继续执行，并在断点被击中时中断(另一个' run '将继续从当前活动的断点执行下一条指令):

```
  > run
  -- register dump --
  pc:       [0]                       <-- program counter
  code:     [40] jt[0] jf[0] k[12]    <-- plain BPF code of current instruction
  curr:     l0:	ldh [12]              <-- disassembly of current instruction
  A:        [00000000][0]             <-- content of A (hex, decimal)
  X:        [00000000][0]             <-- content of X (hex, decimal)
  M[0,15]:  [00000000][0]             <-- folded content of M (hex, decimal)
  -- packet dump --                   <-- Current packet from pcap (hex)
  len: 42
    0: 00 19 cb 55 55 a4 00 14 a4 43 78 69 08 06 00 01
   16: 08 00 06 04 00 01 00 14 a4 43 78 69 0a 3b 01 26
   32: 00 00 00 00 00 00 0a 3b 01 01
  (breakpoint)
  >
```

```
> breakpoint
breakpoints: 0 1
```

打印出当前设置的断点。

```
> step [-<n>, +<n>]
```

从当前pc偏移量执行单步通过BPF程序。因此，在每个step调用上，都会发出上面的寄存器转储。这可以向前和向后的时间，一个普通的'step'将中断对下一个BPF指令，因此+1。(这里不需要发布‘run’。)

```
> select <n>
```

从pcap文件中选择要继续的给定数据包。因此，在下一个“run”或“step”中，BPF程序将根据用户预先选择的包进行评估。编号从Wireshark的索引1开始。

```
> quit
#
```

退出bpf_dbg。


# 4、JIT compiler

Linux内核拥有内建的BPF JIT compiler针对x86_64, SPARC, PowerPC,ARM, ARM64, MIPS and s390架构，可以通过CONFIG_BPF_JIT选项来使能。(对于其他架构，没有提供JIT compiler，只能通过in-kernel interpreter来解析BPF，效率比较低)

JIT compiler会透明的被调用，当用户空间或者内核空间的filter绑定时。如果它事先已经被root使能：

```
  echo 1 > /proc/sys/net/core/bpf_jit_enable
```

对于JIT开发人员做审核等，每一次编译运行都可以通过以下方式将生成的操作码映像输出到内核日志中:

```
  echo 2 > /proc/sys/net/core/bpf_jit_enable

Example output from dmesg:

[ 3389.935842] flen=6 proglen=70 pass=3 image=ffffffffa0069c8f
[ 3389.935847] JIT code: 00000000: 55 48 89 e5 48 83 ec 60 48 89 5d f8 44 8b 4f 68
[ 3389.935849] JIT code: 00000010: 44 2b 4f 6c 4c 8b 87 d8 00 00 00 be 0c 00 00 00
[ 3389.935850] JIT code: 00000020: e8 1d 94 ff e0 3d 00 08 00 00 75 16 be 17 00 00
[ 3389.935851] JIT code: 00000030: 00 e8 28 94 ff e0 83 f8 01 75 07 b8 ff ff 00 00
[ 3389.935852] JIT code: 00000040: eb 02 31 c0 c9 c3
```

当启用CONFIG_BPF_JIT_ALWAYS_ON时，bpf_jit_enable被永久设置为1，并设置任何其他值将返回失败。这甚至适用于将bpf_jit_enable设置为2，因为不鼓励将最终的JIT映像转储到内核日志中，而通过bpftool(在tools/bpf/bpftool/下)进行自省是通常推荐的方法。

在tools/bpf/下的内核源代码树中，有bpf_jit_disasm用于从内核日志的hexdump生成反汇编代码:

```
# ./bpf_jit_disasm
70 bytes emitted from JIT compiler (pass:3, flen:6)
ffffffffa0069c8f + <x>:
   0:	push   %rbp
   1:	mov    %rsp,%rbp
   4:	sub    $0x60,%rsp
   8:	mov    %rbx,-0x8(%rbp)
   c:	mov    0x68(%rdi),%r9d
  10:	sub    0x6c(%rdi),%r9d
  14:	mov    0xd8(%rdi),%r8
  1b:	mov    $0xc,%esi
  20:	callq  0xffffffffe0ff9442
  25:	cmp    $0x800,%eax
  2a:	jne    0x0000000000000042
  2c:	mov    $0x17,%esi
  31:	callq  0xffffffffe0ff945e
  36:	cmp    $0x1,%eax
  39:	jne    0x0000000000000042
  3b:	mov    $0xffff,%eax
  40:	jmp    0x0000000000000044
  42:	xor    %eax,%eax
  44:	leaveq
  45:	retq
```

发布选项“-o”将“注释”操作码到生成的汇编指令，这对JIT开发人员非常有用:

```
# ./bpf_jit_disasm -o
70 bytes emitted from JIT compiler (pass:3, flen:6)
ffffffffa0069c8f + <x>:
   0:	push   %rbp
	55
   1:	mov    %rsp,%rbp
	48 89 e5
   4:	sub    $0x60,%rsp
	48 83 ec 60
   8:	mov    %rbx,-0x8(%rbp)
	48 89 5d f8
   c:	mov    0x68(%rdi),%r9d
	44 8b 4f 68
  10:	sub    0x6c(%rdi),%r9d
	44 2b 4f 6c
  14:	mov    0xd8(%rdi),%r8
	4c 8b 87 d8 00 00 00
  1b:	mov    $0xc,%esi
	be 0c 00 00 00
  20:	callq  0xffffffffe0ff9442
	e8 1d 94 ff e0
  25:	cmp    $0x800,%eax
	3d 00 08 00 00
  2a:	jne    0x0000000000000042
	75 16
  2c:	mov    $0x17,%esi
	be 17 00 00 00
  31:	callq  0xffffffffe0ff945e
	e8 28 94 ff e0
  36:	cmp    $0x1,%eax
	83 f8 01
  39:	jne    0x0000000000000042
	75 07
  3b:	mov    $0xffff,%eax
	b8 ff ff 00 00
  40:	jmp    0x0000000000000044
	eb 02
  42:	xor    %eax,%eax
	31 c0
  44:	leaveq
	c9
  45:	retq
	c3
```

对于BPF JIT开发人员来说，bpf_jit_disasm、bpf_asm和bpf_dbg为开发和测试内核的JIT编译器提供了一个有用的工具链。

# 5、BPF在kernel内的实现(eBPF)

在kernel内部解析器，使用了一套和BPF不同的指令集，即基本原理和前几段描述的BPF类似。但是这个指令集的模型更加接近底层架构更能模仿原生指令，因此可以获得更好的性能。这种新的ISA(Instruction-Set Architecture)被称作'eBP'F(extened BPF)或'internal BPF'。注意：extened BPF和BPF extension是不一样的，eBPF是一种ISA，而BPF extension指的是classic BPF的BPF_LD | BPF_{B,H,W} | BPF_ABS 指令的重载。

它被设计成可被JITed的一对一映射，这也为GCC/LLVM编译器通过一个eBPF后端生成优化的eBPF代码打开了可能性，它的执行速度几乎与本地编译的代码一样快。

新指令集原始设计可能的目的是使用“受限C”来写程序并且通过“GCC/LLVM”来编译成eBPF，所以它可以在即时(JIT just-in-time)映射的两步C -> eBPF -> native code中获得最小的开销。

目前，新格式用于运行用户BPF程序，其中包括seccomp BPF、classic socket filters, cls_bpf traffic classifier, team driver's classifier for its load-balancing mode, netfilter's xt_bpf extension, PTP dissector/classifier，和更多。它们都是由内核内部的转成成新指令，并在eBPF解析器中运行。对于内核内部处理，使用bpf_prog_create()来创建filter和使用bpf_prog_destroy()来销毁filter所有的工作都是透明的。宏BPF_PROG_RUN(filter, ctx)透明的调用eBPF解析器或者JITed代码来运行filter。'filter'指向struct bpf_prog结构的指针由bpf_prog_create()创建，'ctx'给定上下文(例如skb指针)。bpf_check_classic()的所有约束和限制在转换到新布局之前都在幕后执行!

目前，大多数32位体系结构都使用classic  BPF格式，而x86-64、aarch64、s390x、powerpc64、sparc64、arm32则使用eBPF指令集执行JIT编译。

新内部格式的一些核心变化:

- 寄存器数量由2增加到10：

旧的格式拥有两个寄存器A和X，以及一个隐藏的堆栈指针(frame pointer)。新的布局10个内部寄存器和一个只读的堆栈指针。由于64位cpu通过寄存器将参数传递给函数，因此从eBPF程序到内核函数的args数量限制为5个，一个寄存器用于接受内核函数的返回值。原生的，x86_64在寄存器中传递前6个参数，aarch64/sparcv9/mips64有7 - 8个寄存器作为参数;x86_64有6个被调用者保存寄存器，aarch64/sparcv9/mips64有11个或更多被调用者保存寄存器。

因此，eBPF调用约定定义为:

<table border="1">
<caption> BPF calling convention </caption>

<tr>
<th style="width: 200px;">Register</th>
<th style="width: 400px;">Description</th>
</tr>

<tr>
<td> R0 </td>
<td>
return value from in-kernel function, and exit value for eBPF program
</td>
</tr>

<tr>
<td> R1 - R5 </td>
<td>
arguments from eBPF program to in-kernel function
</td>
</tr>

<tr>
<td> R6 - R9 </td>
<td>
callee saved registers that in-kernel function will preserve
</td>
</tr>

<tr>
<td> R10 </td>
<td>
read-only frame pointer to access stack
</td>
</tr>

</table>

因此，所有eBPF寄存器都在x86_64、aarch64等架构上可以一比一的映射到HW寄存器，而eBPF调用约定映射直接映射到64位体系结构上内核使用的ABIs。

在32位体系结构上，JIT映射程序只使用32位运算，并可能让更复杂的程序被解释。

R0 - R5是草稿寄存器，eBPF程序需要在调用之间spill/fill它们。注意，只有一个eBPF程序(==一个eBPF主例程)，它不能调用其他eBPF函数，但只能调用预定义的内核函数。


- 寄存器宽度由32bit增加到64bit：

尽管如此，最初的32位ALU操作的语义仍然通过32位子寄存器保存。所有eBPF寄存器都是64位的，低32位为子寄存器高32位为零扩展。该行为直接映射到x86_64和arm64子寄存器定义，但使其他架构JITs变得更加困难。

32位体系结构通过解释器运行64位BPF程序。他们的JITs可以将只使用32位子寄存器的BPF程序转换为本机指令集，其余的只能被解释。

操作是64位的,因为在64位架构,指针也64位宽。如果我们想通过64位值来和内核函数交换数据，32位eBPF寄存器需要定义寄存器对ABI，因此它不能使用eBPF寄存器到HW寄存器的直接映射，并且JIT需要使用combine/split/move等操作寄存器来和内核函数交换数据，这是又复杂又容易出bug和缓慢。另一个原因是使用原子64位计数器。


- 条件jt/jf目标替换为jt/fall-through:

最初的设计是如下构造"if (cond) jump_true;  else jump_false;"，它们正被替换成类似的构造"if (cond) jump_true; /* else fall-through */"。

- 介绍bpf_call指令和寄存器传递约定，用于调用来自/到其他内核函数：

在调用一个内核函数之前，内部BPF程序需要将函数参数放入R1到R5寄存器以满足调用约定，然后解释器将从寄存器中取出它们并传递给内核函数。给定体系结构上如果R1 - R5寄存器被映射到CPU寄存器用参数于传递，JIT编译器不需要额外的动作。函数参数将在正确的寄存器中，BPF_CALL指令将被JIT翻译成单个'call' HW指令。这个调用约定是用来覆盖通用的调用场景而没有性能损失。

在内核函数调用之后，R1 - R5被重置为不可读，R0有函数的返回值。因为R6 - R9是被调用保护，它们的状态在整个调用中需要被保护。

例如，考虑三个C函数:

```
  u64 f1() { return (*_f2)(1); }
  u64 f2(u64 a) { return f3(a + 1, a); }
  u64 f3(u64 a, u64 b) { return a - b; }
```

GCC可以将f1, f3编译成x86_64:

```
  f1:
    movl $1, %edi
    movq _f2(%rip), %rax
    jmp  *%rax
  f3:
    movq %rdi, %rax
    subq %rsi, %rax
    ret
```

eBPF中的函数f2如下:

```
  f2:
    bpf_mov R2, R1
    bpf_add R1, 1
    bpf_call f3
    bpf_exit
```

如果f2是JITed并且指针存储到'_f2'，调用f1 -> f2 -> f3和返回将是无缝的。如果没有JIT， 需要使用__bpf_prog_run()解释器来调用f2。

出于实际原因，所有eBPF程序只有一个参数“ctx”，该参数已经被放置到R1中(例如在__bpf_prog_run()启动时)，并且程序最多可以调用5个参数的内核函数。目前不支持带有6个或更多参数的调用，但如果将来有必要，可以取消这些限制。

在64位体系结构上，所有到HW的寄存器映射都是一对一的。例如，x86_64 JIT编译器可以将它们映射为…

```
    R0 - rax
    R1 - rdi
    R2 - rsi
    R3 - rdx
    R4 - rcx
    R5 - r8
    R6 - rbx
    R7 - r13
    R8 - r14
    R9 - r15
    R10 - rbp
```

因为x86_64 ABI要求rdi、rsi、rdx、rcx、r8、r9作为参数传递，rbx、 r12 - r15作为 被调用保存。


下面BPF伪程序:

```
    bpf_mov R6, R1 /* save ctx */
    bpf_mov R2, 2
    bpf_mov R3, 3
    bpf_mov R4, 4
    bpf_mov R5, 5
    bpf_call foo
    bpf_mov R7, R0 /* save foo() return value */
    bpf_mov R1, R6 /* restore ctx for next call */
    bpf_mov R2, 6
    bpf_mov R3, 7
    bpf_mov R4, 8
    bpf_mov R5, 9
    bpf_call bar
    bpf_add R0, R7
    bpf_exit
```

经过JIT到x86_64的转换后：

```
    push %rbp
    mov %rsp,%rbp
    sub $0x228,%rsp
    mov %rbx,-0x228(%rbp)
    mov %r13,-0x220(%rbp)
    mov %rdi,%rbx
    mov $0x2,%esi
    mov $0x3,%edx
    mov $0x4,%ecx
    mov $0x5,%r8d
    callq foo
    mov %rax,%r13
    mov %rbx,%rdi
    mov $0x2,%esi
    mov $0x3,%edx
    mov $0x4,%ecx
    mov $0x5,%r8d
    callq bar
    add %r13,%rax
    mov -0x228(%rbp),%rbx
    mov -0x220(%rbp),%r13
    leaveq
    retq
```

该例子等于以下C代码：

```
    u64 bpf_filter(u64 ctx)
    {
        return foo(ctx, 2, 3, 4, 5) + bar(ctx, 6, 7, 8, 9);
    }
```

内核函数foo()和bar()的原型为:u64 (*)(u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5);将在适当的寄存器中接收参数，并将其返回值放入“%rax”，在eBPF中为R0。  
序言和结语由JIT发出，在解释器中是隐式的。R0-R5是暂存寄存器，所以eBPF程序需要在两次调用之间保护它们。

以下实例程序时无效的：

```
    bpf_mov R1, 1
    bpf_call foo
    bpf_mov R0, R1
    bpf_exit
```

在函数调用之后，寄存器R1-R5包含垃圾值不能读取。一个内部eBPF校验器会用来验证eBPF程序。

在新的设计中，eBPF被限制为4096 指令，这意味着任何程序都会快速终止，并且只调用固定数量的内核函数。原始的BPF和新的格式都是两个操作数指令，这有助于在JIT期间在eBPF insn和x86 insn之间进行一对一的映射。

输入的上下文指针对调用解释器函数来说是同一的，其内容由特定的用例决定。对于seccomp寄存器R1指向seccomp_data，对于转换后的BPF filter寄存器R1指向skb。

程序的内部翻译由以下元素组成:

```
  op:16, jt:8, jf:8, k:32    ==>    op:8, dst_reg:4, src_reg:4, off:16, imm:32
```

到目前为止，已经实现了87条内部BPF指令。8位“op”操作码字段有新的指令空间。其中一些可能使用16/24/32字节编码。新指令必须是8字节的倍数，以保持向后兼容性。

内部BPF是一个通用的RISC指令集，并不是所有的寄存器和指令都在从原始BPF转换到新格式的过程中被使用。  
例如，socket filter不使用'exclusive add'指令，但是tracing filter可以用来维护事件计数器。socket filter也不使用寄存器R9，但是更复杂的过滤器可能会耗尽寄存器，并且不得不求助于 spill/fill到堆栈中。

Internal BPF可以作为通用汇编器用于最后一步的性能优化，socket filter和seccomp使用它作为汇编程序。tracing filter可以使用它作为汇编程序从内核生成代码。在内核使用中，可能不会受到安全考虑的限制，因为生成的内部BPF代码可能会优化内部代码路径，而不会暴露给用户空间。  
内部BPF的安全性可以通过验证器(TBD)来实现。在这样的用例中所述，可作为安全指令集使用。

就像最初的BPF一样，新的格式在受控环境中运行，是确定性的，内核可以很容易地证明这一点。程序的安全性可以通过两个步骤确定:第一步是深度优先搜索，禁止循环和其他CFG验证;第二步从第一个insn开始，向下延伸所有可能的路径。它模拟了每个insn的执行，并观察了寄存器和堆栈的状态变化。

## 5.1、eBPF opcode编码

eBPF重用了大部分经典操作码编码，简化了经典BPF到eBPF的转换。

1、对于arithmetic 和jump指令，8位“code”字段分为三个部分:

```
  +----------------+--------+--------------------+
  |   4 bits       |  1 bit |   3 bits           |
  | operation code | source | instruction class  |
  +----------------+--------+--------------------+
  (MSB)                                      (LSB)
```

最后3bit的LSB存储指令类别如下：

```
  Classic BPF classes:    eBPF classes:

  BPF_LD    0x00          BPF_LD    0x00
  BPF_LDX   0x01          BPF_LDX   0x01
  BPF_ST    0x02          BPF_ST    0x02
  BPF_STX   0x03          BPF_STX   0x03
  BPF_ALU   0x04          BPF_ALU   0x04
  BPF_JMP   0x05          BPF_JMP   0x05
  BPF_RET   0x06          [ class 6 unused, for future if needed ]
  BPF_MISC  0x07          BPF_ALU64 0x07
```

当BPF_CLASS(code) == BPF_ALU or BPF_JMP，第4bit表示源操作：

```
  BPF_K     0x00
  BPF_X     0x08
```

在classic BPF中表示：

```
  BPF_SRC(code) == BPF_X - use register X as source operand
  BPF_SRC(code) == BPF_K - use 32-bit immediate as source operand
```

在eBPF中表示：

```
  BPF_SRC(code) == BPF_X - use 'src_reg' register as source operand
  BPF_SRC(code) == BPF_K - use 32-bit immediate as source operand
```

4bit的MSB用来存储操作码。

- 如果BPF_CLASS(code) == BPF_ALU or BPF_ALU64 [ in eBPF ], BPF_OP(code) is one of:

```
  BPF_ADD   0x00
  BPF_SUB   0x10
  BPF_MUL   0x20
  BPF_DIV   0x30
  BPF_OR    0x40
  BPF_AND   0x50
  BPF_LSH   0x60
  BPF_RSH   0x70
  BPF_NEG   0x80
  BPF_MOD   0x90
  BPF_XOR   0xa0
  BPF_MOV   0xb0  /* eBPF only: mov reg to reg */
  BPF_ARSH  0xc0  /* eBPF only: sign extending shift right */
  BPF_END   0xd0  /* eBPF only: endianness conversion */
```

- 如果BPF_CLASS(code) == BPF_JMP, BPF_OP(code) is one of:

```
  BPF_JA    0x00
  BPF_JEQ   0x10
  BPF_JGT   0x20
  BPF_JGE   0x30
  BPF_JSET  0x40
  BPF_JNE   0x50  /* eBPF only: jump != */
  BPF_JSGT  0x60  /* eBPF only: signed '>' */
  BPF_JSGE  0x70  /* eBPF only: signed '>=' */
  BPF_CALL  0x80  /* eBPF only: function call */
  BPF_EXIT  0x90  /* eBPF only: function return */
  BPF_JLT   0xa0  /* eBPF only: unsigned '<' */
  BPF_JLE   0xb0  /* eBPF only: unsigned '<=' */
  BPF_JSLT  0xc0  /* eBPF only: signed '<' */
  BPF_JSLE  0xd0  /* eBPF only: signed '<=' */
```

所以指令'BPF_ADD | BPF_X | BPF_ALU'意味着32bit的加法在cBPF和eBPF中都是。在cBPF中只有两个寄存器，意味着A += X。在eBPF中意味着dst_reg = (u32) dst_reg + (u32) src_reg；类似'BPF_XOR | BPF_K | BPF_ALU'在cBPF中意味着A ^= imm32，在eBPF中src_reg = (u32) src_reg ^ (u32) imm32。

cBPF使用BPF_MISC类来表示移动指令A = X and X = A。eBPF使用'BPF_MOV | BPF_X | BPF_ALU'来替代。因为在eBPF中没有BPF_MISC这个类，对应的class 7用作BPF_ALU64，表示与BPF_ALU操作完全相同，但是使用64位操作数。所以'BPF_ADD | BPF_X | BPF_ALU64'意味着64bit的加例如：dst_reg = dst_reg + src_reg。

cBPF浪费了整个BPF_RET类来表示单个'ret'指令，典型的'BPF_RET | BPF_K'表示拷贝imm32到返回寄存器并进行函数退出。eBPF的模型更匹配CPU，所以'BPF_JMP | BPF_EXIT'在eBPF中仅表示函数退出。eBPF程序需要在BPF_EXIT之前把返回值存入到R0寄存器。eBPF中的class 6当前没有使用保留到将来使用。

2、load和store指令，8位“code”字段分为:

```
  +--------+--------+-------------------+
  | 3 bits | 2 bits |   3 bits          |
  |  mode  |  size  | instruction class |
  +--------+--------+-------------------+
  (MSB)                             (LSB)
```

size字段含义如以下：

```
  BPF_W   0x00    /* word */
  BPF_H   0x08    /* half word */
  BPF_B   0x10    /* byte */
  BPF_DW  0x18    /* eBPF only, double word */
```

在load/store操作中的size如下：

```
 B  - 1 byte
 H  - 2 byte
 W  - 4 byte
 DW - 8 byte (eBPF only)
```

mode字段含义如下：

```
  BPF_IMM  0x00  /* used for 32-bit mov in classic BPF and 64-bit in eBPF */
  BPF_ABS  0x20
  BPF_IND  0x40
  BPF_MEM  0x60
  BPF_LEN  0x80  /* classic BPF only, reserved in eBPF */
  BPF_MSH  0xa0  /* classic BPF only, reserved in eBPF */
  BPF_XADD 0xc0  /* eBPF only, exclusive add */
```

eBPF有两个不通用的指令： (BPF_ABS | <size> | BPF_LD) and (BPF_IND | <size> | BPF_LD) 其用来存取包数据。

为了在eBPF解释器中具有强大的socket filter性能，它们必须从classic版本中继承下来。只有当解释器上下文是指向'struct sk_buff'的指针，并且具有7个隐式操作数时，才能使用这些指令。寄存器R6是一个隐式输入，必须包含指向sk_buff的指针。寄存器R0是一个隐式输出，它包含从数据包中获取的数据。寄存器R1-R5是暂存寄存器，不能用于BPF_ABS | BPF_LD或BPF_IND | BPF_LD指令存储数据。

这些指令也有隐式程序退出条件。当eBPF程序试图访问数据包边界以外的数据时，解释器将中止程序的执行。因此，JIT编译器必须保留这个属性。src_reg和imm32字段是这些指令的显式输入。

举例：

```
  BPF_IND | BPF_W | BPF_LD means:

    R0 = ntohl(*(u32 *) (((struct sk_buff *) R6)->data + src_reg + imm32))
    and R1 - R5 were scratched.
```

与cBPF不同，eBPF拥有通用的load/store操作：

```
BPF_MEM | <size> | BPF_STX:  *(size *) (dst_reg + off) = src_reg
BPF_MEM | <size> | BPF_ST:   *(size *) (dst_reg + off) = imm32
BPF_MEM | <size> | BPF_LDX:  dst_reg = *(size *) (src_reg + off)
BPF_XADD | BPF_W  | BPF_STX: lock xadd *(u32 *)(dst_reg + off16) += src_reg
BPF_XADD | BPF_DW | BPF_STX: lock xadd *(u64 *)(dst_reg + off16) += src_reg
```

其中size为:BPF_B或BPF_H或BPF_W或BPF_DW。注意，不支持1和2字节原子增量。

eBPF拥有一个16字节的指令：'BPF_LD | BPF_DW | BPF_IMM'，它由两个连续的“struct bpf_insn”8字节块组成，解释为将64位立即值加载到dst_reg的单个指令。  
cBPF有类似的指令:BPF_LD | BPF_W | BPF_IMM，它将32位立即值加载到寄存器中。


## 5.2、eBPF verifier

eBPF程序的安全性由两个步骤决定：

第一步做DAG检查以禁止循环和其他CFG验证。特别它将检测程序，有不可到达的指令。(虽然经典的BPF检查器允许这样做)

第二步从第一个insn开始，向下延伸所有可能的路径。它模拟了每一个insn的执行过程，观察寄存器和堆栈的状态变化。

- rule 1、在程序的开始R1包含指向context的指针类型为PTR_TO_CTX。如果verifier看到的指令为R2=R1，那么R2现有也有了类型PTR_TO_CTX，并且可以在表达式右侧使用。如果是 R1=PTR_TO_CTX and R2=R1+R1, 那么R2=SCALAR_VALUE，因为两个指针相加导致无效指针。(在'secure'模式verifier拒绝任何类型的指针算术计算以确保内核地址不会泄露给没有权限的用户)

- rule 2、如果寄存器从来没被写过，那它是不可读的：

```
  bpf_mov R0 = R2
  bpf_exit
```

将被拒绝，因为R2在程序开始时不可读。

- rule 3、在内核函数调用以后，R1-R5重置成不可读状态，R0拥有一个函数的返回类型。

因为R6-R9是对被调用者保护的，所以它们的状态在函数调用后不变。

```
  bpf_mov R6 = 1
  bpf_call foo
  bpf_mov R0 = R6
  bpf_exit
```

上述是一个正确的例子。如果把R6替换成R1，将会被拒绝。

- rule 4、load/store指令只有在寄存器类型有效时才被运行，包含PTR_TO_CTX, PTR_TO_MAP, PTR_TO_STACK类型。它们还有边界和对齐检查。例如：

```
 bpf_mov R1 = 1
 bpf_mov R2 = 2
 bpf_xadd *(u32 *)(R1 + 3) += R2
 bpf_exit
```

将会被拒绝，因为在执行指令bpf_xadd时R1没有有效的指针类型。

- rule 5、在开始R1类型是PTR_TO_CTX(一个指向'struct bpf_context'的指针)。一个回调用于自定义验证程序，以限制eBPF程序仅对具有指定大小和对齐方式的ctx结构中的某些字段进行访问。

举例，以下的指令：

```
  bpf_ld R0 = *(u32 *)(R6 + 8)
```

打算从地址R6 + 8加载一个word并将其存储到R0中。  
如果R6=PTR_TO_CTX，通过is_valid_access()回调，验证者将知道偏移量为8的4字节成员是否可读，否则验证者将拒绝程序。  
如果R6=PTR_TO_STACK，那么访问应该对齐并在堆栈边界内，即[-MAX_BPF_STACK, 0] 。在这个例子中偏移量是8，因此验证失败，因为它超出了界限。

- rule 6、只有在已经被写入的情况下verifier才允许eBPF程序从堆栈中读数据。  
cBPF verifier对M[0-15]也有类似的检查。例如：

```
  bpf_ld R0 = *(u32 *)(R10 - 4)
  bpf_exit
```

是一段无效的程序。  
景观R0是正确PTR_TO_STACK类型的只读寄存器，并且R10 - 4也在堆栈范围内，但是那个位置没有被存储过。

- rule 7、指针寄存器spill/fill也被被追踪(spill/fill就是寄存器push/pop堆栈)，因为4个被调用者保护寄存器(R6-R9)对某些程序来说不够用。

- rule 8、使用pf_verifier_ops->get_func_proto()来决定是否允许函数调用，eBPF  verifier将检查寄存器是否匹配参数约束。在函数调用以后寄存器R0江北设置为函数返回类型。

- rule 9、函数调用是扩展eBPF程序功能的主要机制。Socket filter可以让程序调用同一系列的函数，然而tracing filter可以运行调用完全不同系列的函数。

- rule 10、如果一个函数可以被eBPF程序访问，它需要从安全的角度考虑。verifier将确保使用有效的参数调用函数。

- rule 11、cBPF中seccomp和socket filters拥有不同的安全限制。seccomp使用两个阶段的verifier来保证：cBPF verifier、随后是seccomp verifier。对于eBPF，所有情况共享一个可配置的verifier。

请参阅内核/bpf/verifier.c中关于eBPF verifier的更多细节。


## 5.3、Register value tracking

为了确定eBPF程序的安全性verifier必须跟踪每个寄存器和每个堆栈槽中可能的值的范围。  
这是通过在include/linux/bpf_verifier.h中定义的'struct bpf_reg_state'来完成的，它统一了跟踪的标量和指针值。  
寄存器状态有一个类型，它要么是NOT_INIT(寄存器还没有被写入)，要么是SCALAR_VALUE(一些不能用作指针的值)，要么是指针类型。指针类型描述它们的基址，如下所示:

```
    PTR_TO_CTX          Pointer to bpf_context.
    CONST_PTR_TO_MAP    Pointer to struct bpf_map.  "Const" because arithmetic
                        on these pointers is forbidden.
    PTR_TO_MAP_VALUE    Pointer to the value stored in a map element.
    PTR_TO_MAP_VALUE_OR_NULL
                        Either a pointer to a map value, or NULL; map accesses
                        (see section 'eBPF maps', below) return this type,
                        which becomes a PTR_TO_MAP_VALUE when checked != NULL.
                        Arithmetic on these pointers is forbidden.
    PTR_TO_STACK        Frame pointer.
    PTR_TO_PACKET       skb->data.
    PTR_TO_PACKET_END   skb->data + headlen; arithmetic forbidden.
```

然而，一个指针可以从这个基址上偏移(作为指针运算的结果)，跟踪分为两部分:'fixed offset' and 'variable offset'。前者是一个确切知道的值(例如一个立即数)，后者使用的值没有明确知道。variable offset也用于SCALAR_VALUEs，用于跟踪寄存器中可能的值的范围。

verifier关于variable offset的知识包括:

```
* minimum and maximum values as unsigned
* minimum and maximum values as signed
* 每个独立bit值的信息，以'tnum'的形式表示：a u64 'mask' and a u64 'value'。
在mask中为1的bit的值为unknown，在value中为1的bit为已知1，bit已知为0则在mask和value中都为0，没有bit在mask和value中同时为1。
例如，如果一个字节从内存读到寄存器中，寄存器的前56位已知为零，而低8位未知，它表示为tnum (0x0;0 xff)。如果是0x40，就得到(0x40;0xbf)，如果我们加上1，就得到(0x0;0x1ff),因为潜在的进位。这个格式应该是(value:mask)。
```

除了算术运算，寄存器状态还可以通过条件分支来更新。例如，如果对SCALAR_VALUE进行比较> 8，那么在'true'分支中，它将有一个 minimum值(unsigned minimum value)为9，而在'false'分支中，它将有一个umax_值为8。一个有符号的比较(使用BPF_JSGT或BPF_JSGE)将更新有符号的最小/最大值。来自有符号和无符号边界的信息可以组合;例如，如果首先测试一个值< 8，然后测试s> 4，verifier将得出这个值也是> 4和s< 8的结论，因为边界防止越过符号边界。

PTR_TO_PACKET的 variable offset部分拥有一个'id'，它对于共享同一个变量偏移的所有指针都是通用的。这是一个重要的包范围检查：在加上一个变量到包指针寄存器A以后，如果你然后拷贝A到另一寄存器B，然后再加上一个常量4到A，这两个寄存器有同样的变量'id'，但A还有一个固定的偏移量+4。然后如果A的边界检查小于PTR_TO_PACKET_END，那么寄存器B的安全范围至少为4字节。  
有关PTR_TO_PACKET范围的更多信息，请参阅下面的“Direct packet access”。

“id”字段也用于PTR_TO_MAP_VALUE_OR_NULL，对于map查找返回的指针的所有副本都是通用的。这意味着当检查一个副本并发现它是非null时，所有副本都可以变成PTR_TO_MAP_VALUEs。  
除了范围检查之外，跟踪信息还用于强制指针访问的对齐。例如，在大多数系统中，包指针是4字节对齐后的2字节。如果一个程序增加了14个字节跳过以太网报头,然后读取IHL并加上(IHL * 4),其结果指向一个变量等于4n+2对于n，所以添加2字节(NET_IP_ALIGN)给出了一个4字节对齐,所以word-sized通过该指针来访问是安全的。

## 5.4、Direct packet access

在cls_bpf和act_bpf程序中verifier允许直接访问包数据通过skb->data和 skb->data_end指针。例如：

```
1:  r4 = *(u32 *)(r1 +80)  /* load skb->data_end */
2:  r3 = *(u32 *)(r1 +76)  /* load skb->data */
3:  r5 = r3
4:  r5 += 14
5:  if r5 > r4 goto pc+16
R1=ctx R3=pkt(id=0,off=0,r=14) R4=pkt_end R5=pkt(id=0,off=14,r=14) R10=fp
6:  r0 = *(u16 *)(r3 +12) /* access 12 and 13 bytes of the packet */
```

这个从包中load 2字节是安全的，因为程序作者在第5行指令'if (skb->data + 14 > skb->data_end) goto err'中做了检查，意味着在失败的条件下寄存器R3(指向skb->data)拥有至少14字节的可访问空间。  
verifier将其标记为R3=pkt(id=0,off=0,r=14)。  
id=0表示没有向寄存器添加额外的变量偏移。  
off=0表示没有添加额外的常量偏移。  
r=14是安全访问的范围，这意味着字节[R3, R3 + 14]是可以的。  
注意，R5被标记为R5=pkt(id=0,off=14,r=14)。它也指向包数据，但是常量偏移14被添加到寄存器中，所以它现在指向'skb->data + 14'，可访问范围是[R5, R5 + 14 - 14]即0字节。

更复杂的包存取如下：

```
 R0=inv1 R1=ctx R3=pkt(id=0,off=0,r=14) R4=pkt_end R5=pkt(id=0,off=14,r=14) R10=fp
 6:  r0 = *(u8 *)(r3 +7) /* load 7th byte from the packet */
 7:  r4 = *(u8 *)(r3 +12)
 8:  r4 *= 14
 9:  r3 = *(u32 *)(r1 +76) /* load skb->data */
10:  r3 += r4
11:  r2 = r1
12:  r2 <<= 48
13:  r2 >>= 48
14:  r3 += r2
15:  r2 = r3
16:  r2 += 8
17:  r1 = *(u32 *)(r1 +80) /* load skb->data_end */
18:  if r2 > r1 goto pc+2
 R0=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R1=pkt_end R2=pkt(id=2,off=8,r=8) R3=pkt(id=2,off=0,r=8) R4=inv(id=0,umax_value=3570,var_off=(0x0; 0xfffe)) R5=pkt(id=0,off=14,r=14) R10=fp
19:  r1 = *(u8 *)(r3 +4)
```

寄存器R3的状态为R3=pkt(id=2,off=0,r=8)，id=2意味着看到两个'r3 += rX'这样的指令，所以r3指向包内的某个偏移量，因为程序作者在18行指令做了'if (r3 + 8 > r1) goto err'的判断所以安全范围为[r3, r3 + 8]。  
verifier值运行对包寄存器进行'add'/'sub'操作，任何其他的操作将会把寄存器状态设置成'SCALAR_VALUE'将不能进行包的存取。  
操作'r3 += rX'将可能会溢出并变得比原来的skb->数据少，因此验证者必须防止这种情况发生。因此，当它看到‘r3 += rX’指令，并且rX大于16-bit值时，任何后续的对skb->data_end的限制检查都不会给我们‘范围’信息，所以试图读取指针将会给出‘无效访问包’错误。  
例如：在指令'r4 = *(u8 *)(r3 +12)'(上述第7行指令)以后，r4的状态为R4=R4=inv(id=0,umax_value=255,var_off=(0x0; 0xff))，这意味着寄存器的上56位被保证为0，对于下8位则一无所知。  
在'r4 *= 14' 指令以后状态变为R4=inv(id=0,umax_value=3570,var_off=(0x0; 0xfffe))，因为将一个8位的值乘以常数14将使上面的52位保持为零，并且最小有效位也将为零，因为14是偶数。  
类似的 'r2 >>= 48'使R2=inv(id=0,umax_value=65535,var_off=(0x0; 0xffff))，因为移位不是符号扩展。这个逻辑是在adjust_reg_min_max_vals()函数中实现，它调用adjust_ptr_min_max_vals()来加指针到scalar(反之亦然)，以及使用adjust_scalar_min_max_vals()函数操作两个scalar。

最终的结果是bpf程序的作者可以直接使用正常的C代码访问包，为:

```
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  struct eth_hdr *eth = data;
  struct iphdr *iph = data + sizeof(*eth);
  struct udphdr *udp = data + sizeof(*eth) + sizeof(*iph);

  if (data + sizeof(*eth) + sizeof(*iph) + sizeof(*udp) > data_end)
          return 0;
  if (eth->h_proto != htons(ETH_P_IP))
          return 0;
  if (iph->protocol != IPPROTO_UDP || iph->ihl != 5)
          return 0;
  if (udp->dest == 53 || udp->source == 9)
          ...;
```

这和直接写LD_ABS指令比较起来更容易、速度快得多。


## 5.5、eBPF maps

“map”是用于在内核和用户空间之间共享不同类型数据的通用存储机制。

map的存取通过BPF系统调用，它拥有以下命令：

```
- create a map with given type and attributes
  map_fd = bpf(BPF_MAP_CREATE, union bpf_attr *attr, u32 size)
  using attr->map_type, attr->key_size, attr->value_size, attr->max_entries
  returns process-local file descriptor or negative error

- lookup key in a given map
  err = bpf(BPF_MAP_LOOKUP_ELEM, union bpf_attr *attr, u32 size)
  using attr->map_fd, attr->key, attr->value
  returns zero and stores found elem into value or negative error

- create or update key/value pair in a given map
  err = bpf(BPF_MAP_UPDATE_ELEM, union bpf_attr *attr, u32 size)
  using attr->map_fd, attr->key, attr->value
  returns zero or negative error

- find and delete element by key in a given map
  err = bpf(BPF_MAP_DELETE_ELEM, union bpf_attr *attr, u32 size)
  using attr->map_fd, attr->key

- to delete map: close(fd)
  Exiting process will delete maps automatically
```

用户空间程序使用这个syscall create/access map，eBPF程序也可以并发的更新map。

map拥有以下不同的类型：hash, array, bloom filter, radix-tree, etc。

map的定义如下：

```
  . type
  . max number of elements
  . key size in bytes
  . value size in bytes

```

## 5.6、Pruning(修剪)

verifier实际上并没有遍历程序中所有可能的路径。对于要分析的每个新分支，verifier将查看在此指令下它以前所处的所有状态。如果它们中的任何一个包含当前状态作为一个子集，分支就被“修剪”了——也就是说，之前的状态被接受的事实意味着当前状态也是如此。  
例如，如果在以前的状态中，r1持有一个包指针，而在当前状态中，r1持有一个包指针，它的范围是一样长或更长，并且至少有一样严格的对齐，那么r1是安全的。  
类似地，如果r2之前是NOT_INIT，则从此点开始的任何路径都不能使用它，因此r2中的任何值(包括另一个NOT_INIT)都是安全的。实现在函数regsafe()中。  
修剪不仅考虑寄存器，而且考虑堆栈(以及它可能包含的任何溢出寄存器)。要把树枝修剪掉，它们都必须是安全的。这是在states_equal()中实现的。

## 5.7、Understanding eBPF verifier messages

以下是一些eBPF程序无效和验证错误消息的示例，如日志所示:

Program with unreachable instructions:

```
static struct bpf_insn prog[] = {
  BPF_EXIT_INSN(),
  BPF_EXIT_INSN(),
};
Error:
  unreachable insn 1
```

Program that reads uninitialized register:

```
  BPF_MOV64_REG(BPF_REG_0, BPF_REG_2),
  BPF_EXIT_INSN(),
Error:
  0: (bf) r0 = r2
  R2 !read_ok
```

Program that doesn't initialize R0 before exiting:

```
  BPF_MOV64_REG(BPF_REG_2, BPF_REG_1),
  BPF_EXIT_INSN(),
Error:
  0: (bf) r2 = r1
  1: (95) exit
  R0 !read_ok
```

Program that accesses stack out of bounds:

```
  BPF_ST_MEM(BPF_DW, BPF_REG_10, 8, 0),
  BPF_EXIT_INSN(),
Error:
  0: (7a) *(u64 *)(r10 +8) = 0
  invalid stack off=8 size=8
```

Program that doesn't initialize stack before passing its address into function:

```
  BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
  BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
  BPF_LD_MAP_FD(BPF_REG_1, 0),
  BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
  BPF_EXIT_INSN(),
Error:
  0: (bf) r2 = r10
  1: (07) r2 += -8
  2: (b7) r1 = 0x0
  3: (85) call 1
  invalid indirect read from stack off -8+0 size 8
```

Program that uses invalid map_fd=0 while calling to map_lookup_elem() function:

```
  BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
  BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
  BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
  BPF_LD_MAP_FD(BPF_REG_1, 0),
  BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
  BPF_EXIT_INSN(),
Error:
  0: (7a) *(u64 *)(r10 -8) = 0
  1: (bf) r2 = r10
  2: (07) r2 += -8
  3: (b7) r1 = 0x0
  4: (85) call 1
  fd 0 is not pointing to valid bpf_map
```

Program that doesn't check return value of map_lookup_elem() before accessing map element:

```
  BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
  BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
  BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
  BPF_LD_MAP_FD(BPF_REG_1, 0),
  BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
  BPF_ST_MEM(BPF_DW, BPF_REG_0, 0, 0),
  BPF_EXIT_INSN(),
Error:
  0: (7a) *(u64 *)(r10 -8) = 0
  1: (bf) r2 = r10
  2: (07) r2 += -8
  3: (b7) r1 = 0x0
  4: (85) call 1
  5: (7a) *(u64 *)(r0 +0) = 0
  R0 invalid mem access 'map_value_or_null'
```

Program that correctly checks map_lookup_elem() returned value for NULL, but accesses the memory with incorrect alignment:

```
  BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
  BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
  BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
  BPF_LD_MAP_FD(BPF_REG_1, 0),
  BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
  BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 1),
  BPF_ST_MEM(BPF_DW, BPF_REG_0, 4, 0),
  BPF_EXIT_INSN(),
Error:
  0: (7a) *(u64 *)(r10 -8) = 0
  1: (bf) r2 = r10
  2: (07) r2 += -8
  3: (b7) r1 = 1
  4: (85) call 1
  5: (15) if r0 == 0x0 goto pc+1
   R0=map_ptr R10=fp
  6: (7a) *(u64 *)(r0 +4) = 0
  misaligned access off 4 size 8
```

Program that correctly checks map_lookup_elem() returned value for NULL and accesses memory with correct alignment in one side of 'if' branch, but fails to do so in the other side of 'if' branch:

```
  BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
  BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
  BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
  BPF_LD_MAP_FD(BPF_REG_1, 0),
  BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
  BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 2),
  BPF_ST_MEM(BPF_DW, BPF_REG_0, 0, 0),
  BPF_EXIT_INSN(),
  BPF_ST_MEM(BPF_DW, BPF_REG_0, 0, 1),
  BPF_EXIT_INSN(),
Error:
  0: (7a) *(u64 *)(r10 -8) = 0
  1: (bf) r2 = r10
  2: (07) r2 += -8
  3: (b7) r1 = 1
  4: (85) call 1
  5: (15) if r0 == 0x0 goto pc+2
   R0=map_ptr R10=fp
  6: (7a) *(u64 *)(r0 +0) = 0
  7: (95) exit

  from 5 to 8: R0=imm0 R10=fp
  8: (7a) *(u64 *)(r0 +0) = 1
  R0 invalid mem access 'imm'
```

## 5.8、Testing

在BPF工具链旁边，内核还附带了一个测试模块，该模块包含用于classic和internal BPF的各种测试用例，可针对BPF解释器和JIT编译器执行。它可以在lib/test_bpf.c中找到。通过Kconfig启用:

CONFIG_TEST_BPF = m

在构建和安装模块之后，测试套件执行可以通过insmod或modprobe“test_bpf”模块。测试用例的结果包含nsec计时在内可以在内核日志(dmesg)中找到。

## 5.9、Misc

此外，linux系统调用fuzzer，也内建支持BPF and SECCOMP-BPF kernel fuzzing。


# 6、Written by

编写该文档的目的是希望它有用，并为潜在的BPF黑客或安全审核员更好地概述底层架构。

Jay Schulist <jschlst@samba.org>
Daniel Borkmann <daniel@iogearbox.net>
Alexei Starovoitov <ast@kernel.org>
