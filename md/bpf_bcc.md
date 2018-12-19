bcc全称为(BPF Compiler Collection)，它是模仿gcc(GNU Compiler Collection)的命名风格。 

BPF是运行在内核态的一种虚拟机语言，我们在用户态可以通过Clang+LLVM把c语言编译成BPF目标码，然后通过加载器loader(bcc/perf/iproute2)将BPF目标码通过bpf()系统调用加载到内核当中，最后通过perf的ioctl命令PERF_EVENT_IOC_SET_BPF将加载到内核中的BPF程序和对应子模块(tracing/networking)的钩子绑定起来。(具体参考[3.2、BPF and XDP Reference Guide](https://blog.csdn.net/pwl999/article/details/82706679))   

bcc把上述用户态编译、加载、绑定的功能都集成了起来，方便用户使用，对用户的接口更友好。它使用了(python + lua + c++)的混合架构，底层操作封装到c++ 库中，lua提供一些辅助功能，对用户的接口使用python提供，python和c++之间的调用使用[ctypes](https://www.cnblogs.com/gaowengang/p/7919219.html)连接。因为使用了python，所有抓回来的数据分析和数据呈现也都非常方便。  

有了bcc以后用户就不需要一步步手工的写c代码、编译、加载、绑定、数据分析、数据呈现，只要按照bcc的规则编写一个python文件，bcc帮你一键搞定。

# 1、背景介绍

说到bcc，就不得不提到[Brendan Gregg](http://www.brendangregg.com/linuxperf.html)，他是perfermance届的大神。他开发了很多perf相关的工具和脚本：[perf_events](http://www.brendangregg.com/perf.html)、[perf-tools](https://github.com/brendangregg/perf-tools)、[bcc](https://github.com/iovisor/bcc#tools)、[Flame Graphs](http://www.brendangregg.com/flamegraphs.html)。相关的文档都可以在他的博客上找到，本文bcc的文档也引用自它的博客。

# 2、bcc安装

原文：[Installing BCC](https://github.com/iovisor/bcc/blob/master/INSTALL.md)

首先确保你的内核版本是4.1或者以上的版本(推荐4.9以上)，并且打开了以下配置：(查看/proc/config.gz or /boot/config-<kernel-version>)

```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
# [optional, for tc filters]
CONFIG_NET_CLS_BPF=m
# [optional, for tc actions]
CONFIG_NET_ACT_BPF=m
CONFIG_BPF_JIT=y
CONFIG_HAVE_BPF_JIT=y
# [optional, for kprobes]
CONFIG_BPF_EVENTS=y
```

如果运行bcc网络示例需要打开一些可选的内核选项:

```
CONFIG_NET_SCH_SFQ=m
CONFIG_NET_ACT_POLICE=m
CONFIG_NET_ACT_GACT=m
CONFIG_DUMMY=m
CONFIG_VXLAN=m
```

在ubuntu环境下，我们可以使用以下简单的命令来安装bcc工具：

```
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 4052245BD4284CDD
echo "deb https://repo.iovisor.org/apt/xenial xenial main" | sudo tee /etc/apt/sources.list.d/iovisor.list
sudo apt-get update
sudo apt-get install bcc-tools libbcc-examples linux-headers-$(uname -r)
```


# 3、bcc的使用入门

原文：[bcc Tutorial](https://github.com/iovisor/bcc/blob/master/docs/tutorial.md) ([中文翻译](https://yq.aliyun.com/articles/590865?spm=a2c4e.11153940.blogcont590484.17.46b2520brFy4OK))。

安装完bcc以后，我们可以进入"/usr/share/bcc/tools"和"/usr/share/bcc/examples/tracing"路径下执行bcc已经提供的性能分析命令，关于命令的基本使用可以参考上面的入门指导。

```
/usr/share/bcc/tools$ ls
argdist              doc             mdflush         pythonflow   tcpconnlat
bashreadline         execsnoop       memleak         pythongc     tcpdrop
biolatency           ext4dist        mountsnoop      pythonstat   tcplife
biosnoop             ext4slower      mysqld_qslower  reset-trace  tcpretrans
biotop               filelife        nfsdist         rubycalls    tcpstates
bitesize             fileslower      nfsslower       rubyflow     tcpsubnet
bpflist              filetop         nodegc          rubygc       tcptop
btrfsdist            funccount       nodestat        rubyobjnew   tcptracer
btrfsslower          funclatency     offcputime      rubystat     tplist
cachestat            funcslower      offwaketime     runqlat      trace
cachetop             gethostlatency  old             runqlen      ttysnoop
capable              hardirqs        oomkill         runqslower   vfscount
cobjnew              inject          opensnoop       slabratetop  vfsstat
cpudist              javacalls       perlcalls       softirqs     wakeuptime
cpuunclaimed         javaflow        perlflow        solisten     xfsdist
criticalstat         javagc          perlstat        sslsniff     xfsslower
dbslower             javaobjnew      phpcalls        stackcount   zfsdist
dbstat               javastat        phpflow         statsnoop    zfsslower
dcsnoop              javathreads     phpstat         syncsnoop
dcstat               killsnoop       pidpersec       syscount
deadlock_detector    lib             profile         tcpaccept
deadlock_detector.c  llcstat         pythoncalls     tcpconnect

/usr/share/bcc/examples/tracing$ ls
bitehist_example.txt            strlen_count.py
bitehist.py                     strlen_hist.py
CMakeLists.txt                  strlen_snoop.py
disksnoop_example.txt           sync_timing.py
disksnoop.py                    task_switch.py
hello_fields.py                 tcpv4connect_example.txt
hello_perf_output.py            tcpv4connect.py
kvm_hypercall.py                trace_fields.py
kvm_hypercall.txt               trace_perf_output.py
mallocstacks.py                 urandomread_example.txt
mysqld_query_example.txt        urandomread-explicit.py
mysqld_query.py                 urandomread.py
nodejs_http_server_example.txt  vfsreadlat.c
nodejs_http_server.py           vfsreadlat_example.txt
stacksnoop_example.txt          vfsreadlat.py
stacksnoop.py
```

如果bcc提供的专用命令不能满足你，bcc还提供了几个通用自定义命令：trace、argdist、funccount。可以详细看一下这几个命令的用法。

# 4、bcc python脚本的编写

原文：[bcc Python Developer Tutorial](https://github.com/iovisor/bcc/blob/master/docs/tutorial_bcc_python_developer.md) ([中文翻译](https://yq.aliyun.com/articles/591412?spm=a2c4e.11153940.blogcont591411.14.6275182dhqtUpz))、[bcc Reference Guide](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md)。

如果bcc自带脚本不能满足你，你可以仿照bcc的语法规则自己开发python脚本，自定义自己要采集的数据，自定义自己的数据处理和呈现规则。因为是python接口，我们可以进行二次开发把数据进行更详尽的分析、用图形呈现等等。

# 5、bcc源码结构

我们也可以从github上下载bcc的[源代码](https://github.com/iovisor/bcc)进行分析和调试。

我们在配置pycharm工程的时候需要注意：
- 1、bcc的脚本需要以root的权限来运行：[参考](https://www.jianshu.com/p/df0733491918)；
- 2、需要把bcc/src/python的路径加入到python库的搜索路径中，工程才能正确运行：[参考](https://www.cnblogs.com/softidea/p/6707910.html)；

我们查看cc的python脚本，核心部分是BPF python库:

```
bcc/examples$ cat hello_world.py 
#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

# run in project examples directory with:
# sudo ./hello_world.py"
# see trace_fields.py for a longer example

from bcc import BPF

# This may not work for 4.17 on x64, you need replace kprobe__sys_clone with kprobe____x64_sys_clone
BPF(text='int kprobe__sys_clone(void *ctx) { bpf_trace_printk("Hello, World!\\n"); return 0; }').trace_print()
```

BPF python库是在路径bcc/src/python/bcc/中实现的，在libbcc.py中通过[ctypes](https://www.cnblogs.com/gaowengang/p/7919219.html)导入了libbcc.so.0：

```
bcc/src/python/bcc$ cat libbcc.py
# Copyright 2015 PLUMgrid
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import ctypes as ct

lib = ct.CDLL("libbcc.so.0", use_errno=True)

# keep in sync with bpf_common.h
lib.bpf_module_create_b.restype = ct.c_void_p
lib.bpf_module_create_b.argtypes = [ct.c_char_p, ct.c_char_p, ct.c_uint]
lib.bpf_module_create_c.restype = ct.c_void_p
```

libbcc.so.0是c++的底层实现，源码在bcc/src/cc路径下。

本来是想写一篇bcc内核代码分析的文章，后来发现整个代码规模太大，还是分析个大致框架有问题再追踪修改吧。

