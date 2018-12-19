

## 1、内核态解析:

# [1.1、bpf内核框架](./bpf_kernel.md)


## 2、用户态(前端)解析:

# [2.1、bcc](./bpf_bcc.md)


## 3、参考资料：

# [3.1、Berkeley Packet Filter (BPF) (Kernel Document) ](./bpf_kernel_doc.md)

# [3.2、BPF and XDP Reference Guide](./bpf_reference_guide.md)

[3.3、DTrace for Linux 2016](http://www.brendangregg.com/blog/2016-10-27/dtrace-for-linux-2016.html)

[3.4、bcc/BPF Tool End-User Tutorial](https://github.com/iovisor/bcc/blob/master/docs/tutorial.md)

[3.5、bcc Python Developer's Tutorial](https://github.com/iovisor/bcc/blob/master/docs/tutorial_bcc_python_developer.md)

[3.6、bcc Reference Guide](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md)

[3.7、Installing BCC](https://github.com/iovisor/bcc/blob/master/INSTALL.md)

[3.8、Linux未来监控tracing框架——eBPF](https://yq.aliyun.com/articles/590479?spm=a2c4e.11153940.blogcont591413.15.21012a00Ygpo0b)

[3.9、Linux 中的 DTrace ：BPF 进入 4.9 内核](https://linux.cn/article-8038-1.html)

[3.10、Linux内核工程导论——网络：Filter（LSF、BPF、eBPF）](https://blog.csdn.net/ljy1988123/article/details/50444693)

[3.11、LLVM和GCC的区别](https://www.cnblogs.com/zuopeng/p/4141467.html)

[3.12、底层虚拟机（LLVM）中间语言（IR）基本语法简介](http://blog.sina.com.cn/s/blog_49b6b6d001011gik.html)

> 因为bpf功能在4.9以后的kernel才完善，本文采用kernel 4.9的代码进行解析。

