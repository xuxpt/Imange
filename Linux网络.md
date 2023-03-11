## Linux收发包过程

内核和网络设备驱动是通过中断的方式来处理的。当设备上有数据到达的时候，会给CPU的相关引脚上触发一个电压变化，以通知CPU来处理数据。

Linux中断处理函数是分上半部和下半部的。上半部是只进行最简单的工作，快速处理然后释放CPU，接着CPU就可以允许其它中断进来。剩下将绝大部分的工作都放到下半部中，可以慢慢从容处理。下半部实现方式是软中断，由ksoftirqd内核线程全权处理。和硬中断不同的是，硬中断是通过给CPU物理引脚施加电压变化，而软中断是通过给内存中的一个变量的二进制值以通知软中断处理程序。

https://github.com/xuxpt/Imange/blob/main/Internet/image-20230306092259163.png

DMA：直接存储器存储。skb：待处理队列。RingBuff：环形缓冲区。

当网卡上收到数据以后，首先会以DMA的方式把网卡上收到的帧写到内存里。再向CPU发起一个中断，以通知CPU有数据到达。当CPU收到中断请求后，会去调用网络驱动注册的中断处理函数。 网卡的中断处理函数并不做过多工作，发出软中断请求，然后尽快释放CPU。ksoftirqd检测到有软中断请求到达，调用poll开始轮询收包，收到后交由各级协议栈处理。对于UDP包来说，会被放到用户socket的接收队列中。

#### 收包前的初始化处理

Linux驱动，内核协议栈等等模块在具备接收网卡数据包之前，要做很多的准备工作才行。比如要提前创建好ksoftirqd内核线程，要注册好各个协议对应的处理函数，网络设备子系统要提前初始化好，网卡要启动好。只有这些都Ready之后，我们才能真正开始接收数据包。

##### 创建ksoftirqd内核线程

Linux的软中断都是在专门的内核线程（ksoftirqd）中进行的，系统初始化的时候在kernel/smpboot.c中调用了smpboot_register_percpu_thread， 该函数进一步会执行到spawn_ksoftirqd（位于kernel/softirq.c）来创建出softirqd进程。

<img src="C:\Users\张小航\AppData\Roaming\Typora\typora-user-images\image-20230306093401175.png" alt="image-20230306093401175" style="zoom:80%;" />

当ksoftirqd被创建出来以后，它就会进入自己的线程循环函数ksoftirqd_should_run和run_ksoftirqd了。不停地判断有没有软中断需要被处理。

##### 网络子系统初始化

在网络子系统的初始化过程中，会为每个CPU初始化softnet_data，也会为RX_SOFTIRQ和TX_SOFTIRO注册处理函数。

<img src="C:\Users\张小航\AppData\Roaming\Typora\typora-user-images\image-20230306094411205.png" alt="image-20230306094411205" style="zoom: 67%;" />

softnet_data队列层，在网络收发包的过程中，需要维护一个缓冲区队列，来缓存可能存在的突发数据。

linux内核通过调用`subsys_initcall`来初始化各个子系统。

会为每个CPU都申请一个`softnet_data`数据结构，在这个数据结构里的`poll_list`是等待驱动程序将其poll函数注册进来。poll的作用是把当前的文件指针挂到等待队列。

open_softirq注册了每一种软中断都注册一个处理函数。 NET_TX_SOFTIRQ的处理函数为net_tx_action，NET_RX_SOFTIRQ的为net_rx_action。继续跟踪`open_softirq`后发现这个注册的方式是记录在`softirq_vec`变量里的。

##### 协议栈注册

内核实现了网络层的ip协议，也实现了传输层的tcp协议和udp协议。 这些协议对应的实现函数分别是ip_rcv(),tcp_v4_rcv()和udp_rcv()。和我们平时写代码的方式不一样的是，内核是通过注册的方式来实现的。 Linux内核中的fs_initcall和subsys_initcall类似，也是初始化模块的入口。fs_initcall调用inet_init后开始网络协议栈注册。 通过inet_init，将这些函数注册到了inet_protos和ptype_base数据结构中了。

<img src="C:\Users\张小航\AppData\Roaming\Typora\typora-user-images\image-20230306095637886.png" alt="image-20230306095637886" style="zoom:67%;" />

inet_protos哈希表存储了传输层协议的处理函数地址。（UDP、TCP）

ptype_base存储着网络数据报协议地址。

udp_protocol结构体中的handler是udp_rcv，tcp_protocol结构体中的handler是tcp_v4_rcv，通过inet_add_protocol被初始化了进来。

##### 网卡驱动初始化

每一个驱动程序（不仅仅只是网卡驱动）会使用 module_init 向内核注册一个初始化函数，当驱动被加载时，内核会调用这个函数。igb网卡驱动的代码位于 drivers/net/ethernet/intel/igb/igb_main.c

驱动的pci_register_driver调用完成后，Linux内核就知道了该驱动的相关信息，比如igb网卡驱动的igb_driver_name 和 igb_probe 函数地址等等。当网卡设备被识别以后，内核会调用其驱动的probe方法（igb_driver的probe方法是igb_probe）。驱动probe方法执行的目的就是让设备ready。

<img src="C:\Users\张小航\AppData\Roaming\Typora\typora-user-images\image-20230306101535091.png" alt="image-20230306101535091" style="zoom:67%;" />

ethtool 是用于查询及设置网卡参数的命令。

NAPI 是 Linux 上采用的一种提高网络处理效率的技术，它的核心概念就是不采用中断的方式读取数据，而代之以首先采用中断唤醒数据接收的服务程序，然后 POLL 的方法来轮询数据。

网卡驱动实现了ethtool所需要的接口，也在这里注册完成函数地址的注册。当 ethtool 发起一个系统调用之后，内核会找到对应操作的回调函数。ethtool命令之所以能查看网卡收发包统计、能修改网卡自适应模式、能调整RX 队列的数量和大小，是因为ethtool命令最终调用到了网卡驱动的相应方法，而不是ethtool本身有这个超能力。

第6步注册的igb_netdev_ops中包含的是igb_open等函数，该函数在网卡被启动的时候会被调用。

第7步中，在igb_probe初始化过程中，还调用到了`igb_alloc_q_vector`。他注册了一个NAPI机制所必须的poll函数，对于igb网卡驱动来说，这个函数就是igb_poll。

##### 启动网卡

前面网卡驱动初始化时，我们提到了驱动向内核注册了 structure net_device_ops 变量，它包含着网卡启用、发包、设置mac 地址等回调函数（函数指针）。当启用一个网卡时，net_device_ops 中的 igb_open方法会被调用。它通常会做以下事情：

<img src="C:\Users\张小航\AppData\Roaming\Typora\typora-user-images\image-20230306102946572.png" alt="image-20230306102946572" style="zoom:67%;" />

`__igb_open`函数调用了igb_setup_all_tx_resources,和igb_setup_all_rx_resources。在`igb_setup_all_rx_resources`这一步操作中，分配了RingBuffer，并建立内存和Rx队列的映射关系。（Rx Tx 队列的数量和大小可以通过 ethtool 进行配置）。

#### 收包

##### 硬中断处理

首先当数据帧从网线到达网卡上的时候，第一站是网卡的接收队列。网卡在分配给自己的RingBuffer中寻找可用的内存位置，找到后DMA引擎会把数据DMA到网卡之前关联的内存里，这个时候CPU都是无感的。当DMA操作完成以后，网卡会像CPU发起一个硬中断，通知CPU有数据到达。

<img src="C:\Users\张小航\AppData\Roaming\Typora\typora-user-images\image-20230306103322446.png" alt="image-20230306103322446" style="zoom:67%;" />

注意：当RingBuffer满的时候，新来的数据包将给丢弃。ifconfig查看网卡的时候，可以里面有个overruns，表示因为环形队列满被丢弃的包。如果发现有丢包，可能需要通过ethtool命令来加大环形队列的长度。

![image-20230306103532441](C:\Users\张小航\AppData\Roaming\Typora\typora-user-images\image-20230306103532441.png)

Linux在硬中断里只完成简单必要的工作，剩下的大部分的处理都是转交给软中断的。通过上面代码可以看到，硬中断处理过程真的是非常短。只是记录了一个寄存器，修改了一下下CPU的poll_list，然后发出个软中断。就这么简单，硬中断工作就算是完成了。

##### ksoftirqd内核线程处理软中断

网络包的接受过程主要都在ksoftirqd内核线程中完成，软中断都是在这里处理。

<img src="C:\Users\张小航\AppData\Roaming\Typora\typora-user-images\image-20230306105514001.png" alt="image-20230306105514001" style="zoom:80%;" />

内核线程初始化的时候，ksoftirqd中两个线程函数`ksoftirqd_should_run`和`run_ksoftirqd`。

ksoftirqd_should_run 和硬中断中调用了同一个函数`local_softirq_pending`。使用方式不同的是硬中断位置是为了写入标记，这里仅仅只是读取。如果硬中断中设置了`NET_RX_SOFTIRQ`,这里自然能读取的到。

这里需要注意一个细节，硬中断中设置软中断标记，和ksoftirq的判断是否有软中断到达，都是基于smp_processor_id()的。这意味着只要硬中断在哪个CPU上被响应，那么软中断也是在这个CPU上处理的。所以说，如果你发现你的Linux软中断CPU消耗都集中在一个核上的话，做法是要把调整硬中断的CPU亲和性，来将硬中断打散到不通的CPU核上去。

##### 网络协议栈处理

netif_receive_skb函数会根据包的协议，假如是udp包，会将包依次送到ip_rcv(),udp_rcv()协议处理函数中进行处理。如图

<img src="C:\Users\张小航\AppData\Roaming\Typora\typora-user-images\image-20230306134553836.png" alt="image-20230306134553836" style="zoom:80%;" />

__netif_receive_skb_core取出protocol，它会从数据包中取出协议信息，然后遍历注册在这个协议上的回调函数列表。ptype_base是一个 hash table，在协议注册小节我们提到过。ip_rcv 函数地址就是存在这个 hash table中的。

##### IP层处理

linux在ip协议层都做了什么，包又是怎么样进一步被送到udp或tcp协议处理函数中的。

```
//file: net/ipv4/ip_input.c
int ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
    ......

    return NF_HOOK(NFPROTO_IPV4, NF_INET_PRE_ROUTING, skb, dev, NULL,
               ip_rcv_finish);
```

这里`NF_HOOK`是一个钩子函数，当执行完注册的钩子后就会执行到最后一个参数指向的函数`ip_rcv_finish`。

```
static int ip_rcv_finish(struct sk_buff *skb)
{
    ......

    if (!skb_dst(skb)) {
        int err = ip_route_input_noref(skb, iph->daddr, iph->saddr,
                           iph->tos, skb->dev);
        ...
    }

    ......

    return dst_input(skb);
}
```

跟踪`ip_route_input_noref` 后看到它又调用了 `ip_route_input_mc`。 在`ip_route_input_mc`中，函数`ip_local_deliver`被赋值给了`dst.input`, 如下：

```
//file: net/ipv4/route.c
static int ip_route_input_mc(struct sk_buff *skb, __be32 daddr, __be32 saddr,
                u8 tos, struct net_device *dev, int our)
{
    if (our) {
        rth->dst.input= ip_local_deliver;
        rth->rt_flags |= RTCF_LOCAL;
    }
}
```

所以回到`ip_rcv_finish`中的`return dst_input(skb);`。

```
/* Input packet from network to transport.  */
static inline int dst_input(struct sk_buff *skb)
{
    return skb_dst(skb)->input(skb);
}
```

`skb_dst(skb)->input`调用的input方法就是路由子系统赋的ip_local_deliver。

如协议注册小节看到inet_protos中保存着tcp_rcv()和udp_rcv()的函数地址。这里将会根据包中的协议类型选择进行分发,在这里skb包将会进一步被派送到更上层的协议中，udp和tcp。

#### 收包总结

首先在开始收包之前，Linux要做许多的准备工作：

1. 创建ksoftirqd线程，为它设置好它自己的线程函数，后面就指望着它来处理软中断呢。

2. 协议栈注册，linux要实现许多协议，比如arp，icmp，ip，udp，tcp，每一个协议都会将自己的处理函数注册一下，方便包来了迅速找到对应的处理函数

3. 网卡驱动初始化，每个驱动都有一个初始化函数，内核会让驱动也初始化一下。在这个初始化过程中，把自己的DMA准备好，把NAPI的poll函数地址告诉内核

4. 启动网卡，分配RX，TX队列，注册中断对应的处理函数

当数据到来了以后，第一个迎接它的是网卡

1. 网卡将数据帧DMA到内存的RingBuffer中，然后向CPU发起中断通知

2. CPU响应中断请求，调用网卡启动时注册的中断处理函数

3. 中断处理函数几乎没干啥，就发起了软中断请求

4. 内核线程ksoftirqd线程发现有软中断请求到来，先关闭硬中断

5. ksoftirqd线程开始调用驱动的poll函数收包

6. poll函数将收到的包送到协议栈注册的ip_rcv函数中

7. ip_rcv函数再讲包送到udp_rcv函数中（对于tcp包就送到tcp_rcv）

## Linux网络发包过程

#### 网络发包过程总览

<img src="C:\Users\张小航\AppData\Roaming\Typora\typora-user-images\image-20230306142948232.png" alt="image-20230306142948232" style="zoom:67%;" />

可以看到用户数据被拷贝到内核态，然后经过协议栈（添加报头）处理后进入到了 RingBuffer 中。随后网卡驱动真正将数据发送了出去。当发送完成的时候，是通过硬中断来通知 CPU，然后清理 RingBuffer。

从源码角度来分析网络包发送的过程：

<img src="https://pic2.zhimg.com/v2-b511a062c2803ecfc6931bfdcf3f2b51_r.jpg" alt="img" style="zoom: 67%;" />

虽然数据这时已经发送完毕，但是其实还有一件重要的事情没有做，那就是释放缓存队列等内存。

内核是如何知道什么时候才能释放内存的呢，当然是等网络发送完毕之后。网卡在发送完毕的时候，会给 CPU 发送一个硬中断来通知 CPU。更完整的流程看图：

<img src="https://pic3.zhimg.com/v2-4040c1e92f7b492c522848b786285e96_r.jpg" alt="img" style="zoom:67%;" />

注意，虽然是发送数据，但是硬中断最终触发的软中断却是 NET_RX_SOFTIRQ，而并不是 NET_TX_SOFTIRQ ！！！

网卡启动

现在的服务器上的网卡一般都是支持多队列的。每一个队列上都是由一个 RingBuffer 表示的，开启了多队列以后的的网卡就会对应有多个 RingBuffer。

<img src="https://pic4.zhimg.com/80/v2-ce24c3abe8e58f9fd4d269bd64291347_1440w.webp" alt="img" style="zoom: 67%;" />

在网卡启动的时候，会调用到 __igb_open 函数，RingBuffer 就是在这里分配的。

__igb_open 函数调用 igb_setup_all_tx_resources 分配所有的传输 RingBuffer, 调用 igb_setup_all_rx_resources 创建所有的接收 RingBuffer。

真正的 RingBuffer 构造过程是在 igb_setup_tx_resources 中完成的。

```
//file: drivers/net/ethernet/intel/igb/igb_main.c
int igb_setup_tx_resources(struct igb_ring *tx_ring)
{
 //1.申请 igb_tx_buffer 数组内存
 size = sizeof(struct igb_tx_buffer) * tx_ring->count;
 tx_ring->tx_buffer_info = vzalloc(size);

 //2.申请 e1000_adv_tx_desc DMA 数组内存
 tx_ring->size = tx_ring->count * sizeof(union e1000_adv_tx_desc);
 tx_ring->size = ALIGN(tx_ring->size, 4096);
 tx_ring->desc = dma_alloc_coherent(dev, tx_ring->size,
        &tx_ring->dma, GFP_KERNEL);

 //3.初始化队列成员
 tx_ring->next_to_use = 0;
 tx_ring->next_to_clean = 0;
}
```

从上述源码可以看到，实际上一个 RingBuffer 的内部不仅仅是一个环形队列数组，而是有两个。

1）igb_tx_buffer 数组：这个数组是内核使用的，通过 vzalloc 申请的。
2）e1000_adv_tx_desc 数组：这个数组是网卡硬件使用的，硬件是可以通过 DMA 直接访问这块内存，通过 dma_alloc_coherent 分配。

这个时候它们之间还没有啥联系。将来在发送的时候，这两个环形数组中相同位置的指针将都将指向同一个 skb。这样，内核和硬件就能共同访问同样的数据了，内核往 skb 里写数据，网卡硬件负责发送。

<img src="https://pic1.zhimg.com/v2-3385217f1469def5689fc0057739df64_r.jpg" alt="img" style="zoom:67%;" />

#### 数据从用户进程到网卡的详细过程

##### send系统调用实现

send 系统调用的源码位于文件 net/socket.c 中。在这个系统调用里，内部其实真正使用的是 sendto 系统调用。整个调用链条虽然不短，但其实主要只干了两件简单的事情，

第一是在内核中把真正的 socket 找出来，在这个对象里记录着各种协议栈的函数地址。

第二是构造一个 struct msghdr 对象，把用户传入的数据，比如 buffer地址、数据长度啥的，统统都装进去.

剩下的事情就交给下一层，协议栈里的函数 inet_sendmsg 了，其中 inet_sendmsg 函数的地址是通过 socket 内核对象里的 ops 成员找到的。大致流程如图。

<img src="https://pic4.zhimg.com/v2-33dbbf07ba4846e60c8edb671d00c07f_r.jpg" alt="img" style="zoom:67%;" />

可以看到，我们在用户态使用的 send 函数和 sendto 函数其实都是 sendto 系统调用实现的。send 只是为了方便，封装出来的一个更易于调用的方式而已。

在 sendto 系统调用里，首先根据用户传进来的 socket 句柄号来查找真正的 socket 内核对象。接着把用户请求的 buff、len、flag 等参数都统统打包到一个 struct msghdr 对象中。

接着调用了 sock_sendmsg => ___sock_sendmsg ==>__sock_sendmsg_nosec。在__sock_sendmsg_nosec 中，调用将会由系统调用进入到协议栈。

##### 传输层处理

1）传输层拷贝

在进入到协议栈 inet_sendmsg 以后，内核接着会找到 socket 上的具体协议发送函数。对于 TCP 协议来说，那就是 tcp_sendmsg（同样也是通过 socket 内核对象找到的）。

在这个函数中，内核会申请一个内核态的 skb 内存，将用户待发送的数据拷贝进去。注意这个时候不一定会真正开始发送，如果没有达到发送条件的话很可能这次调用直接就返回了。大概过程如图：

<img src="https://pic2.zhimg.com/v2-ffad55e8c65199c7c6604bd394088e41_r.jpg" alt="img" style="zoom: 67%;" />

 inet_sendmsg 函数的源码。

```
//file: net/ipv4/af_inet.c
int inet_sendmsg(......)
{
 ......
 return sk->sk_prot->sendmsg(iocb, sk, msg, size);
}
```

在这个函数中会调用到具体协议的发送函数。同样参考第三节里的 socket 内核对象结构图，我们看到对于 TCP 协议下的 socket 来说，来说 sk->sk_prot->sendmsg 指向的是 tcp_sendmsg

tcp_sendmsg 这个函数源码

```
//file: net/ipv4/tcp.c
int tcp_sendmsg(...)
{
 while(...){
  while(...){
   //获取发送队列
   skb = tcp_write_queue_tail(sk);

   //申请skb 并拷贝
   ......
  }
 }
}

//file: include/net/tcp.h
static inline struct sk_buff *tcp_write_queue_tail(const struct sock *sk)
{
 return skb_peek_tail(&sk->sk_write_queue);
}
```

这个函数是在获取 socket 发送队列中的最后一个 skb。 skb 是 struct sk_buff 对象的简称，用户的发送队列就是该对象组成的一个链表。

![img](https://pic2.zhimg.com/v2-bb693e4a2fdae5870609d9b76133c0ad_r.jpg)

 tcp_sendmsg 的其它部分。

```
//file: net/ipv4/tcp.c
int tcp_sendmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
  size_t size)
{
 //获取用户传递过来的数据和标志
 iov = msg->msg_iov; //用户数据地址
 iovlen = msg->msg_iovlen; //数据块数为1
 flags = msg->msg_flags; //各种标志

 //遍历用户层的数据块
 while (--iovlen >= 0) {

  //待发送数据块的地址
  unsigned char __user *from = iov->iov_base;

  while (seglen > 0) {

   //需要申请新的 skb
   if (copy <= 0) {

    //申请 skb，并添加到发送队列的尾部
    skb = sk_stream_alloc_skb(sk,
         select_size(sk, sg),
         sk->sk_allocation);

    //把 skb 挂到socket的发送队列上
    skb_entail(sk, skb);
   }

   // skb 中有足够的空间
   if (skb_availroom(skb) > 0) {
    //拷贝用户空间的数据到内核空间，同时计算校验和
    //from是用户空间的数据地址 
    skb_add_data_nocache(sk, skb, from, copy);
   } 
   ......
```

其中 msg->msg_iov 存储的是用户态内存的要发送的数据的 buffer。接下来在内核态申请内核内存，比如 skb，并把用户内存里的数据拷贝到内核态内存中。这就会涉及到一次或者几次内存拷贝的开销。

![img](https://pic3.zhimg.com/v2-cbd951cef795058fe8379ac46765d172_r.jpg)

内核什么时候真正把 skb 发送出去。在 tcp_sendmsg 中会进行一些判断。

```
//file: net/ipv4/tcp.c
int tcp_sendmsg(...)
{
 while(...){
  while(...){
   //申请内核内存并进行拷贝

   //发送判断
   if (forced_push(tp)) {
    tcp_mark_push(tp, skb);
    __tcp_push_pending_frames(sk, mss_now, TCP_NAGLE_PUSH);
   } else if (skb == tcp_send_head(sk))
    tcp_push_one(sk, mss_now);  
   }
   continue;
  }
 }
}
```

只有满足 forced_push(tp) 或者 skb == tcp_send_head(sk) 成立的时候，内核才会真正启动发送数据包。条件都不满足的话，这次的用户要发送的数据只是拷贝到内核就算完事了！

##### 传输层发送

当满足真正发送条件的时候，无论调用的是 __tcp_push_pending_frames 还是 tcp_push_one 最终都实际会执行到 tcp_write_xmit。直接从 tcp_write_xmit 看起，这个函数处理了传输层的拥塞控制、滑动窗口相关的工作。满足窗口要求的时候，设置一下 TCP 头然后将 skb 传到更低的网络层进行处理。

<img src="https://pic2.zhimg.com/v2-18f6157c989ac8838e7048941260809d_r.jpg" alt="img" style="zoom:80%;" />

发送主过程 tcp_transmit_skb。

```
//file: net/ipv4/tcp_output.c
static int tcp_transmit_skb(struct sock *sk, struct sk_buff *skb, int clone_it,
    gfp_t gfp_mask)
{
 //1.克隆新 skb 出来
 if (likely(clone_it)) {
  skb = skb_clone(skb, gfp_mask);
  ......
 }

 //2.封装 TCP 头
 th = tcp_hdr(skb);
 th->source  = inet->inet_sport;
 th->dest  = inet->inet_dport;
 th->window  = ...;
 th->urg   = ...;
 ......

 //3.调用网络层发送接口
 err = icsk->icsk_af_ops->queue_xmit(skb, &inet->cork.fl);
}
```

第一件事是先克隆一个新的 skb，为什么要复制一个 skb ？

是因为 skb 后续在调用网络层，最后到达网卡发送完成的时候，这个 skb 会被释放掉。而我们知道 TCP 协议是支持丢失重传的，在收到对方的 ACK 之前，这个 skb 不能被删除。所以内核的做法就是每次调用网卡发送的时候，实际上传递出去的是 skb 的一个拷贝。等收到 ACK 再真正删除。

第二件事是修改 skb 中的 TCP header，根据实际情况把 TCP 头设置好。skb 内部其实包含了网络协议中所有的 header。在设置 TCP 头的时候，只是把指针指向 skb 的合适位置。后面再设置 IP 头的时候，在把指针挪一挪就行，避免频繁的内存申请和拷贝，效率很高。

![img](https://pic4.zhimg.com/v2-cfce7d6f807c3325de9ef21df529e4c3_r.jpg)

tcp_transmit_skb 是发送数据位于传输层的最后一步，接下来就可以进入到网络层进行下一层的操作了。调用了网络层提供的发送接口icsk->icsk_af_ops->queue_xmit()。

queue_xmit 其实指向的是 ip_queue_xmit 函数。

```
//file: net/ipv4/tcp_ipv4.c
const struct inet_connection_sock_af_ops ipv4_specific = {
 .queue_xmit    = ip_queue_xmit,
 .send_check    = tcp_v4_send_check,
 ...
}
```

##### 网络层发送处理

Linux 内核网络层的发送的实现位于 net/ipv4/ip_output.c 这个文件。传输层调用到的 ip_queue_xmit 也在这里。

在网络层里主要处理路由项查找、IP 头设置、netfilter 过滤、skb 切分等几项工作，处理完这些工作后会交给更下层的邻居子系统来处理。

<img src="https://pic1.zhimg.com/v2-0070e8bac1946baba239c56a27555a00_r.jpg" alt="img" style="zoom:67%;" />

网络层入口函数 ip_queue_xmit 的源码：

```
//file: net/ipv4/ip_output.c
int ip_queue_xmit(struct sk_buff *skb, struct flowi *fl)
{
 //检查 socket 中是否有缓存的路由表
 rt = (struct rtable *)__sk_dst_check(sk, 0);
 if (rt == NULL) {
  //没有缓存则展开查找
  //则查找路由项， 并缓存到 socket 中
  rt = ip_route_output_ports(...);
  sk_setup_caps(sk, &rt->dst);
 }

 //为 skb 设置路由表
 skb_dst_set_noref(skb, &rt->dst);

 //设置 IP header
 iph = ip_hdr(skb);
 iph->protocol = sk->sk_protocol;
 iph->ttl      = ip_select_ttl(inet, &rt->dst);
 iph->frag_off = ...;

 //发送
 ip_local_out(skb);
}
```

ip_queue_xmit 已经到了网络层，在这个函数看到了网络层相关的功能路由项查找，如果找到了则设置到 skb 上（没有路由的话就直接报错返回了）。

在 Linux 上通过 route 命令可以看到你本机的路由配置。

接着把路由表地址也放到 skb 里去。

```text
//file: include/linux/skbuff.h
struct sk_buff {
 //保存了一些路由相关信息
 unsigned long  _skb_refdst;
}
```

接下来就是定位到 skb 里的 IP 头的位置上，然后开始按照协议规范设置 IP header。

![img](https://pic3.zhimg.com/80/v2-f75b423219d405ff7c6885b10ee11c0a_1440w.webp)

再通过 ip_local_out 进入到下一步的处理。

```text
//file: net/ipv4/ip_output.c  
int ip_local_out(struct sk_buff *skb)
{
 //执行 netfilter 过滤
 err = __ip_local_out(skb);

 //开始发送数据
 if (likely(err == 1))
  err = dst_output(skb);
 ......
```

在 ip_local_out => __ip_local_out => nf_hook 会执行 netfilter 过滤。如果你使用 iptables 配置了一些规则，那么这里将检测是否命中规则。 如果你设置了非常复杂的 netfilter 规则，在这个函数这里将会导致你的进程 CPU 开销会极大增加。

发送有关的过程 dst_output。

```text
//file: include/net/dst.h
static inline int dst_output(struct sk_buff *skb)
{
 return skb_dst(skb)->output(skb);
}
```

此函数找到到这个 skb 的路由表（dst 条目） ，然后调用路由表的 output 方法。这又是一个函数指针，指向的是 ip_output 方法。

```text
//file: net/ipv4/ip_output.c
int ip_output(struct sk_buff *skb)
{
 //统计
 .....

 //再次交给 netfilter，完毕后回调 ip_finish_output
 return NF_HOOK_COND(NFPROTO_IPV4, NF_INET_POST_ROUTING, skb, NULL, dev,
    ip_finish_output,
    !(IPCB(skb)->flags & IPSKB_REROUTED));
}
```

在 ip_output 中进行一些简单的，统计工作，再次执行 netfilter 过滤。过滤通过之后回调 ip_finish_output。

```text
//file: net/ipv4/ip_output.c
static int ip_finish_output(struct sk_buff *skb)
{
 //大于 mtu 的话就要进行分片了
 if (skb->len > ip_skb_dst_mtu(skb) && !skb_is_gso(skb))
  return ip_fragment(skb, ip_finish_output2);
 else
  return ip_finish_output2(skb);
}
```

在 ip_finish_output2 中，终于发送过程会进入到下一层，邻居子系统中。

```text
//file: net/ipv4/ip_output.c
static inline int ip_finish_output2(struct sk_buff *skb)
{
 //根据下一跳 IP 地址查找邻居项，找不到就创建一个
 nexthop = (__force u32) rt_nexthop(rt, ip_hdr(skb)->daddr);  
 neigh = __ipv4_neigh_lookup_noref(dev, nexthop);
 if (unlikely(!neigh))
  neigh = __neigh_create(&arp_tbl, &nexthop, dev, false);

 //继续向下层传递
 int res = dst_neigh_output(dst, neigh, skb);
}
```

##### 邻居子系统

邻居子系统是位于网络层和数据链路层中间的一个系统，其作用是对网络层提供一个封装，让网络层不必关心下层的地址信息，让下层来决定发送到哪个 MAC 地址。

![img](https://pic2.zhimg.com/80/v2-980285236de5b4b2efcf7176d1d6f9d9_1440w.webp)

在邻居子系统里主要是查找或者创建邻居项，在创造邻居项的时候，有可能会发出实际的 arp 请求。然后封装一下 MAC 头，将发送过程再传递到更下层的网络设备子系统。大致流程如图。

地址解析协议，即ARP（Address Resolution Protocol），是根据IP地址获取[物理地址的一个TCP/IP协议。主机发送信息时将包含目标IP地址的ARP请求广播到局域网络上的所有主机，并接收返回消息，以此确定目标的物理地址；收到返回消息后将该IP地址和物理地址存入本机ARP缓存中并保留一定时间，下次请求时直接查询ARP缓存以节约资源。

<img src="https://pic4.zhimg.com/80/v2-c2fffa7864d22f96118c7ce39ead1057_1440w.webp" alt="img" style="zoom:67%;" />

 ip_finish_output2 源码中调用了 __ipv4_neigh_lookup_noref。它是在 arp 缓存中进行查找，其第二个参数传入的是路由下一跳 IP 信息。

```text
//file: include/net/arp.h
extern struct neigh_table arp_tbl;
static inline struct neighbour *__ipv4_neigh_lookup_noref(
 struct net_device *dev, u32 key)
{
 struct neigh_hash_table *nht = rcu_dereference_bh(arp_tbl.nht);

 //计算 hash 值，加速查找
 hash_val = arp_hashfn(......);
 for (n = rcu_dereference_bh(nht->hash_buckets[hash_val]);
   n != NULL;
   n = rcu_dereference_bh(n->next)) {
  if (n->dev == dev && *(u32 *)n->primary_key == key)
   return n;
 }
}
```

如果查找不到，则调用 __neigh_create 创建一个邻居。

```text
//file: net/core/neighbour.c
struct neighbour *__neigh_create(......)
{
 //申请邻居表项
 struct neighbour *n1, *rc, *n = neigh_alloc(tbl, dev);

 //构造赋值
 memcpy(n->primary_key, pkey, key_len);
 n->dev = dev;
 n->parms->neigh_setup(n);

 //最后添加到邻居 hashtable 中
 rcu_assign_pointer(nht->hash_buckets[hash_val], n);
 ......
```

有了邻居项以后，此时仍然还不具备发送 IP 报文的能力，因为目的 MAC 地址还未获取。 调用 dst_neigh_output 继续传递 skb。

```text
//file: include/net/dst.h
static inline int dst_neigh_output(struct dst_entry *dst, 
     struct neighbour *n, struct sk_buff *skb)
{
 ......
 return n->output(n, skb);
}
```

调用 output，实际指向的是 neigh_resolve_output。在这个函数内部有可能会发出 arp 网络请求

```text
//file: net/core/neighbour.c
int neigh_resolve_output(){

 //注意：这里可能会触发 arp 请求
 if (!neigh_event_send(neigh, skb)) {

  //neigh->ha 是 MAC 地址
  dev_hard_header(skb, dev, ntohs(skb->protocol),
           neigh->ha, NULL, skb->len);
  //发送
  dev_queue_xmit(skb);
 }
}
```

当获取到硬件 MAC 地址以后，就可以封装 skb 的 MAC 头了。最后调用 dev_queue_xmit 将 skb 传递给 Linux 网络设备子系统。

##### 网络设备子系统

<img src="https://pic4.zhimg.com/80/v2-6fa56c1f95237a49703f6a0161daa7e3_1440w.webp" alt="img" style="zoom:67%;" />

邻居子系统通过 dev_queue_xmit 进入到网络设备子系统中来。

```
//file: net/core/dev.c 
int dev_queue_xmit(struct sk_buff *skb)
{
 //选择发送队列
 txq = netdev_pick_tx(dev, skb);

 //获取与此队列关联的排队规则
 q = rcu_dereference_bh(txq->qdisc);

 //如果有队列，则调用__dev_xmit_skb 继续处理数据
 if (q->enqueue) {
  rc = __dev_xmit_skb(skb, q, dev, txq);
  goto out;
 }

 //没有队列的是回环设备和隧道设备
 ......
}
```

网卡是有多个发送队列的。对 netdev_pick_tx 函数的调用就是选择一个队列进行发送。

netdev_pick_tx 发送队列的选择受 XPS 等配置的影响，而且还有缓存，netdev_pick_tx => __netdev_pick_tx。

```text
//file: net/core/flow_dissector.c
u16 __netdev_pick_tx(struct net_device *dev, struct sk_buff *skb)
{
 //获取 XPS 配置
 int new_index = get_xps_queue(dev, skb);

 //自动计算队列
 if (new_index < 0)
  new_index = skb_tx_hash(dev, skb);}
```

大部分的设备都有队列（回环设备和隧道设备除外），所以现在进入到 __dev_xmit_skb。

```text
//file: net/core/dev.c
static inline int __dev_xmit_skb(struct sk_buff *skb, struct Qdisc *q,
     struct net_device *dev,
     struct netdev_queue *txq)
{
 //1.如果可以绕开排队系统
 if ((q->flags & TCQ_F_CAN_BYPASS) && !qdisc_qlen(q) &&
     qdisc_run_begin(q)) {
  ......
 }

 //2.正常排队
 else {

  //入队
  q->enqueue(skb, q)

  //开始发送
  __qdisc_run(q);
 }
}
```

上述代码中分两种情况，1 是可以 bypass（绕过）排队系统的，另外一种是正常排队。我们只看第二种情况先调用 q->enqueue 把 skb 添加到队列里。然后调用 __qdisc_run 开始发送。

```text
//file: net/sched/sch_generic.c
void __qdisc_run(struct Qdisc *q)
{
 int quota = weight_p;

 //循环从队列取出一个 skb 并发送
 while (qdisc_restart(q)) {
  
  // 如果发生下面情况之一，则延后处理：
  // 1. quota 用尽
  // 2. 其他进程需要 CPU
  if (--quota <= 0 || need_resched()) {
   //将触发一次 NET_TX_SOFTIRQ 类型 softirq
   __netif_schedule(q);
   break;
  }
 }
}
```

上述代码中，while 循环不断地从队列中取出 skb 并进行发送。注意，这个时候其实都占用的是用户进程的系统态时间(sy)。 只有当 quota 用尽或者其它进程需要 CPU 的时候才触发软中断进行发送。

发送过程 qdisc_restart 

```text
static inline int qdisc_restart(struct Qdisc *q)
{
 //从 qdisc 中取出要发送的 skb
 skb = dequeue_skb(q);
 ...

 return sch_direct_xmit(skb, q, dev, txq, root_lock);
}
```

qdisc_restart 从队列中取出一个 skb，并调用 sch_direct_xmit 继续发送。

```text
//file: net/sched/sch_generic.c
int sch_direct_xmit(struct sk_buff *skb, struct Qdisc *q,
   struct net_device *dev, struct netdev_queue *txq,
   spinlock_t *root_lock)
{
 //调用驱动程序来发送数据
 ret = dev_hard_start_xmit(skb, dev, txq);
}
```

##### 软中断调度

如果系统态 CPU 发送网络包不够用的时候，会调用 __netif_schedule 触发一个软中断。该函数会进入到 __netif_reschedule，由它来实际发出 NET_TX_SOFTIRQ 类型软中断。

软中断是由内核线程来运行的，该线程会进入到 net_tx_action 函数，在该函数中能获取到发送队列，并也最终调用到驱动程序里的入口函数 dev_hard_start_xmit。

<img src="https://pic2.zhimg.com/v2-7b7da5c8cebe7a05ef2fddc3b98d7ec5_r.jpg" alt="img" style="zoom:67%;" />

```text
//file: net/core/dev.c
static inline void __netif_reschedule(struct Qdisc *q)
{
 sd = &__get_cpu_var(softnet_data);
 q->next_sched = NULL;
 *sd->output_queue_tailp = q;
 sd->output_queue_tailp = &q->next_sched;

 ......
 raise_softirq_irqoff(NET_TX_SOFTIRQ);
}
```

在该函数里在软中断能访问到的 softnet_data 里设置了要发送的数据队列，添加到了 output_queue 里了。紧接着触发了 NET_TX_SOFTIRQ 类型的软中断。

用户态进程触发完软中断之后，会有一个软中断内核线程会执行到 net_tx_action。

```text
//file: net/core/dev.c
static void net_tx_action(struct softirq_action *h)
{
 //通过 softnet_data 获取发送队列
 struct softnet_data *sd = &__get_cpu_var(softnet_data);

 // 如果 output queue 上有 qdisc
 if (sd->output_queue) {

  // 将 head 指向第一个 qdisc
  head = sd->output_queue;

  //遍历 qdsics 列表
  while (head) {
   struct Qdisc *q = head;
   head = head->next_sched;

   //发送数据
   qdisc_run(q);
  }
 }
}
```

软中断这里会获取 softnet_data。前面我们看到进程内核态在调用 __netif_reschedule 的时候把发送队列写到 softnet_data 的 output_queue 里了。 软中断循环遍历 sd->output_queue 发送数据帧。

qdisc_run，它和进程用户态一样，也会调用到 __qdisc_run。

```text
//file: include/net/pkt_sched.h
static inline void qdisc_run(struct Qdisc *q)
{
 if (qdisc_run_begin(q))
  __qdisc_run(q);
}
```

然后一样就是进入 qdisc_restart => sch_direct_xmit，直到驱动程序函数 dev_hard_start_xmit。

##### igb网卡驱动发送

无论是对于用户进程的内核态，还是对于软中断上下文，都会调用到网络设备子系统中的 dev_hard_start_xmit 函数。在这个函数中，会调用到驱动里的发送函数 igb_xmit_frame。

在驱动函数里，将 skb 会挂到 RingBuffer上，驱动调用完毕后，数据包将真正从网卡发送出去。

<img src="https://pic1.zhimg.com/v2-dd72dd5d2ddcaa38bcde752bb5d073c4_r.jpg" alt="img" style="zoom: 67%;" />

```text
//file: net/core/dev.c
int dev_hard_start_xmit(struct sk_buff *skb, struct net_device *dev,
   struct netdev_queue *txq)
{
 //获取设备的回调函数集合 ops
 const struct net_device_ops *ops = dev->netdev_ops;

 //获取设备支持的功能列表
 features = netif_skb_features(skb);

 //调用驱动的 ops 里面的发送回调函数 ndo_start_xmit 将数据包传给网卡设备
 skb_len = skb->len;
 rc = ops->ndo_start_xmit(skb, dev);
}
```

其中 ndo_start_xmit 是网卡驱动要实现的一个函数，是在 net_device_ops 中定义的。

```text
//file: include/linux/netdevice.h
struct net_device_ops {
 netdev_tx_t  (*ndo_start_xmit) (struct sk_buff *skb,
         struct net_device *dev);

}
```

在 igb 网卡驱动源码中，找到了。对于网络设备层定义的 ndo_start_xmit， igb 的实现函数是 igb_xmit_frame。这个函数是在网卡驱动初始化的时候被赋值的。

网络设备层调用 ops->ndo_start_xmit 的时候，会实际上进入 igb_xmit_frame 这个函数中。

```text
//file: drivers/net/ethernet/intel/igb/igb_main.c
static netdev_tx_t igb_xmit_frame(struct sk_buff *skb,
      struct net_device *netdev)
{
 ......
 return igb_xmit_frame_ring(skb, igb_tx_queue_mapping(adapter, skb));
}

netdev_tx_t igb_xmit_frame_ring(struct sk_buff *skb,
    struct igb_ring *tx_ring)
{
 //获取TX Queue 中下一个可用缓冲区信息
 first = &tx_ring->tx_buffer_info[tx_ring->next_to_use];
 first->skb = skb;
 first->bytecount = skb->len;
 first->gso_segs = 1;

 //igb_tx_map 函数准备给设备发送的数据。
 igb_tx_map(tx_ring, first, hdr_len);
}
```

在这里从网卡的发送队列的 RingBuffer 中取下来一个元素，并将 skb 挂到元素上。

![img](https://pic1.zhimg.com/80/v2-53210da030eea44896489582bbbc13f0_1440w.webp)

igb_tx_map 函数处理将 skb 数据映射到网卡可访问的内存 DMA 区域。

```text
//file: drivers/net/ethernet/intel/igb/igb_main.c
static void igb_tx_map(struct igb_ring *tx_ring,
      struct igb_tx_buffer *first,
      const u8 hdr_len)
{
 //获取下一个可用描述符指针
 tx_desc = IGB_TX_DESC(tx_ring, i);

 //为 skb->data 构造内存映射，以允许设备通过 DMA 从 RAM 中读取数据
 dma = dma_map_single(tx_ring->dev, skb->data, size, DMA_TO_DEVICE);

 //遍历该数据包的所有分片,为 skb 的每个分片生成有效映射
 for (frag = &skb_shinfo(skb)->frags[0];; frag++) {

  tx_desc->read.buffer_addr = cpu_to_le64(dma);
  tx_desc->read.cmd_type_len = ...;
  tx_desc->read.olinfo_status = 0;
 }

 //设置最后一个descriptor
 cmd_type |= size | IGB_TXD_DCMD;
 tx_desc->read.cmd_type_len = cpu_to_le32(cmd_type);

 /* Force memory writes to complete before letting h/w know there
  * are new descriptors to fetch
  */
 wmb();
}
```

当所有需要的描述符都已建好，且 skb 的所有数据都映射到 DMA 地址后，驱动就会进入到它的最后一步，触发真实的发送。	

##### RingBuffer内存回收

当数据发送完成以后，其实工作并没有结束。因为内存还没有清理。当发送完成的时候，网卡设备会触发一个硬中断来释放内存。

在发送硬中断里，会执行 RingBuffer 内存的清理工作。

<img src="https://pic1.zhimg.com/80/v2-4a1721e48e34c50390132f018c5ad1d4_1440w.webp" alt="img" style="zoom:67%;" />

硬中断触发软中断的源码。

```text
//file: drivers/net/ethernet/intel/igb/igb_main.c
static inline void ____napi_schedule(...){
 list_add_tail(&napi->poll_list, &sd->poll_list);
 __raise_softirq_irqoff(NET_RX_SOFTIRQ);
}
```

无论硬中断是因为是有数据要接收，还是说发送完成通知，从硬中断触发的软中断都是 NET_RX_SOFTIRQ。

软中断的回调函数 igb_poll。在这个函数里，注意到有一行 igb_clean_tx_irq：

```text
//file: drivers/net/ethernet/intel/igb/igb_main.c
static int igb_poll(struct napi_struct *napi, int budget)
{
 //performs the transmit completion operations
 if (q_vector->tx.ring)
  clean_complete = igb_clean_tx_irq(q_vector);
 ...
}
```

当传输完成的时候，igb_clean_tx_irq 

```text
//file: drivers/net/ethernet/intel/igb/igb_main.c
static bool igb_clean_tx_irq(struct igb_q_vector *q_vector)
{
 //free the skb
 dev_kfree_skb_any(tx_buffer->skb);

 //clear tx_buffer data
 tx_buffer->skb = NULL;
 dma_unmap_len_set(tx_buffer, len, 0);

 // clear last DMA location and unmap remaining buffers */
 while (tx_desc != eop_desc) {
 }
}
```

igb_clean_tx_irq 无非就是清理了 skb，解除了 DMA 映射等等。

总结整个发送过程

<img src="https://pic4.zhimg.com/80/v2-ecb73e1531032fea52e21644f2aa1413_1440w.webp" alt="img" style="zoom:67%;" />
