# Startup 开始

让我们从**redis.c** 中的**main** 开始吧 [原文链接](https://www.pauladamsmith.com/articles/redis-under-the-hood.html#shared-objects)

## Begining global server state initialization 开始全局服务器状态的初始化

![redis架构图](https://www.pauladamsmith.com/articles/redis_under_the_hood/startup.png)

首先，**initServerConfig()**被调用，这部分初始化了一个有着变量**server** ，他的类型是**struct redisServer** ，作为全局服务器状态

```
// redis.h:828
struct redisServer {
    pthread_t mainthread;
    int port;
    int fd;
    redisDb *db;
    // ...
};

// redis.c:68
struct redisServer server; /* server global state */
```

这个结构中的成员数量庞大，但他们一般分为以下几类。

1. 通用服务器状态
2. 统计
3. 配置文件中的配置
4. 复制（replication）
5. 排序的参数
6. 虚拟内存配置、状态、I/O线程和统计信息
7. 压缩数据结构
8. eventloop helpers（时间循环助手，英文原文更容易理解）
9. pub/sub（订阅取消订阅相关）

举个例子，这个结构体包括了映射到配置文件（通常被叫做**redis.conf**）里面选项的成员变量，比如listen端口和日志的粗略程度，指向连接的客户端和从属Redis服务器以及Redis数据库本身的链接列表，以及自启动以来处理的命令数量等统计数据的计数器。

**initServerConfig()**提供了成员的默认值，用户可以通过**redis.conf** 配置文件来配置

### Setting up command table 设置命令表

下一件**main** 函数要干的事情是排序redis命令表，这些命令被定义在一个全局变量**redisCommandTable**，他是一个**struct redisCommands** 类型的数组

```
struct redisCommand readonlyCommandTable[] = {
    {"get",getCommand,2,REDIS_CMD_INLINE,NULL,1,1,1},
    {"set",setCommand,3,REDIS_CMD_BULK|REDIS_CMD_DENYOOM,NULL,0,0,0},
    {"setnx",setnxCommand,3,REDIS_CMD_BULK|REDIS_CMD_DENYOOM,NULL,0,0,0},
    {"setex",setexCommand,4,REDIS_CMD_BULK|REDIS_CMD_DENYOOM,NULL,0,0,0},
    {"append",appendCommand,3,REDIS_CMD_BULK|REDIS_CMD_DENYOOM,NULL,1,1,1},
    // ...
};

// redis.h:458
typedef void redisCommandProc(redisClient *c);
// ...
struct redisCommand {
    char *name;
    redisCommandProc *proc;
    int arity;
    int flags;
    // ...
};
```

这个表在源码中被排序，便于按照类别分组，比如字符串命令，列表命令，设置命令等，使程序员更容易的扫描类似的命令，这个排序的列表指向一个全局的变量**commandTable** 被用来用一个标准的二进制查找（**lookupCommand()**,返回一个指向**redisCommand**类型的指针）查找redis 命令，备注：**commandTable** 这个变量貌似没有被用到，因为译者是根据黄建宏先生的redis3.0进行翻译的，所以可能源代码有出入，本文作者应该是2.2之前的版本，现在的**lookupCommand**函数函数原型也不会传指针类型

```
struct redisCommand *lookupCommand(sds name) {
    return dictFetchValue(server.commands, name);
}
```

>  redisCommand结构记录了它的名字--助记符，即 "get"--一个指向执行命令的实际C函数的指针、命令的arity、命令标志（如是否返回批量响应）以及一些VM特定的成员）。

### Loading config file 加载配置文件

**main()** 接下来去执行redis-server被用户启动时添加的命令行选项，现在，目前，Redis只接受一个参数--除了通常的版本-v和帮助-h标志之外--就是一个配置文件的路径，如果给出了路径，Redis会加载配置文件，并通过调用loadServerConfig()覆盖initServerConfig()已经设置的任何默认值。这个函数相当简单，在配置文件的每一行中循环，并将与指令名称相匹配的值转换为服务器结构中匹配成员变量的适当类型。在这一点上，如果Redis已经被配置为这样做了，那么它将成为守护进程并从控制终端上分离。（最后一句话我也不太明白 At this point, Redis will daemonize and detach from the controlling terminal if it has been configured to do so.）

### initServer()

initServer()完成了从initServerConfig()开始的初始化**server**结构体的工作。首先，它设置了信号处理（**SIGHUP**和**SIGPIPE**信号被忽略--有机会通过增加当Redis收到**SIGHUP**时重新加载其配置文件的能力来改进Redis，就像其他守护程序一样），包括当收到一个**SIGSEGV**信号（和其他相关信号）打印一个调用栈，详情请见**segvHandler()**。

大量双链表（见**adlist.h**）被创建，用来跟踪客户端、从服务器、监视器（已发送**MONITOR**命令的客户）和一个空闲对象list。

### Shared objects

redis做的一个很有意思的事情是创建了大量的共享对象，通过全局`shared`结构体获取，例如，许多不同的命令、响应字符串和错误信息所需要的普通Redis对象可以被共享，而不必每次都分配它们，从而节省了内存，但代价是在启动时要多做一些初始化工作。

```
// redis.c:662
shared.crlf = createObject(REDIS_STRING,sdsnew("\r\n"));
shared.ok = createObject(REDIS_STRING,sdsnew("+OK\r\n"));
shared.err = createObject(REDIS_STRING,sdsnew("-ERR\r\n"));
shared.emptybulk = createObject(REDIS_STRING,sdsnew("$0\r\n\r\n"));
// ...
```

#### Shared integers

在共享对象的内存节省方面，最大的收益来自于一个大的共享整数池。

```
// redis.c:705
for (j = 0; j < REDIS_SHARED_INTEGERS; j++) {
    shared.integers[j] = createObject(REDIS_STRING,(void*)(long)j);
    shared.integers[j]->encoding = REDIS_ENCODING_INT;
}
```

`createSharedObjects()`创建了一个10000以内的非负整数作为redis对象（整数编码的字符串），大量的redis对象，像strings，sets，和包含许多小整数（用于ID或者计数器）的lists，它们可以重复使用已经在内存中分配过的相同对象，以获得大量可能的内存节省。我们可以想象，定义要创建的共享整数的常数REDIS_SHARED_INTEGERS，可以暴露在配置中（这里指的应该是``#define REDIS_SHARED_INTEGERS 10000``），让用户有机会根据对他们的应用和需求的了解，增加共享整数的数量，以节省更多的内存。这样做的好处是，Redis在启动时静态分配的内存略多，但与整个典型的数据库大小和潜在的节约相比，这还是一个小数目。

### Event loop

`initServer()`继续创建核心事件循环，调用`aeCreateEventLoop()` (see `ae.c`)并将结果分配给`server`的`el`成员变量。
`ae.h`提供了一个跨平台的封装，用于设置I/O事件通知循环，它在Linux上使用epoll，在BSD上使用kqueue，如果各自的第一选择不可用，则退回到`select`)。Redis的事件循环轮询新的连接和I/O事件（从套接字中读取请求和向套接字中写入响应），当一个新的事件到来时被触发。这就是 Redis 响应速度如此之快的原因，它可以在处理和响应单个请求时同时为数千个客户端提供服务而不会阻塞。

> Redis实现的一个关键点是使用本地提供的封装文件（其实就是把底层api诸如epoll这些封装起来）来简化和隐藏普通任务的复杂性，而无需在构建时添加依赖关系。例如，`zmalloc.h`为`*alloc()`函数家族定义了一些封装器，它跟踪Redis分配了多少内存。`sds.h`定义了一个动态字符串库的API（基本上，一个字符串会跟踪它的长度和它的内存是否可以被释放）。

### Databases

`initServer()`也初始化了大量的`redisDb`结构体，这个结构体是封装特定 Redis 数据库细节的结构，包括跟踪即将到期的键、正在阻塞的键（来自 `B{L,R}POP`（`BLPOP`/`BRPOP`） 命令或来自 `I/O`），以及正在被关注的`check-and-set`的键。(默认情况下，有16个独立的数据库，可以认为是Redis服务器中的命名空间）。

### TCP socket

initServer()是设置Redis监听连接的套接字的地方（默认情况下，绑定到6379端口）。另一个Redis`本身的封装文件anet.h`定义了`anetTcpServer()`和其他一些函数，通过这些函数简化了设置新套接字、绑定和监听端口的通常复杂性。

```
// redis.c:791
server.fd = anetTcpServer(server.neterr, server.port, server.bindaddr);
if (server.fd == -1) {
    redisLog(REDIS_WARNING, "Opening TCP port: %s", server.neterr);
    exit(1);
}
```
### Server cron

initServer()进一步为数据库和pub/sub分配各种`dict`和`list`，重置统计信息和各种标志，并记录服务器启动时间的UNIX时间戳。它将`serverCron()`注册到事件循环中作为一个时间事件，每100毫秒执行一次该函数。(这有点tricky（英语我感觉大家更能理解），因为最初，serverCron()被initServer()设置为在1毫秒内运行，以便在服务器启动时立即启动cron循环，但随后serverCron()的返回值，即100，被插入到计算下一次应该处理的时间事件进程中）。

```
//最初是1ms执行
if(aeCreateTimeEvent(server.el, 1, serverCron, NULL, NULL) == AE_ERR) {
        redisPanic("Can't create the serverCron time event.");
        exit(1);
    }
```

serverCron()为Redis执行一些周期性的任务，包括对数据库大小（键数和使用的内存数量）和连接的客户端进行粗略的记录，调整哈希表的大小，关闭空闲/超时的客户端连接，执行任何后台保存或AOF重写的清理，如果配置的保存条件得到满足（这么多键在这么多秒内改变），启动后台保存。计算LRU信息和处理过期的键（Redis在每个cron周期只过期几个超时的键，使用自适应的统计方法来避免占用服务器，但如果过期的键可以帮助避免内存不足的情况，则会变得更加积极），如果启用了虚拟内存，则将值交换到磁盘，如果该服务器是一个从服务器，则与一个主服务器同步。

### Registering connection handler with event loop用时间循环注册一个connection处理

最重要的是，initServer()通过注册套接字的描述符，将事件循环与服务器的TCP套接字挂起，注册acceptHandler()函数，当一个新的连接被接受时被调用。(在下面的 "处理请求 "部分会有更多介绍）。

```
// redis.c:821
if (aeCreateFileEvent(server.el, server.fd, AE_READABLE,
    acceptHandler, NULL) == AE_ERR) oom("creating file event");
```
### Opening the AOF

`initServer()`创建或打开仅有`append-only`的文件（AOF），如果服务器被配置为使用它。

```
// redis.c:824
if (server.appendonly) {
    server.appendfd = open(server.appendfilename,O_WRONLY|O_APPEND|O_CREAT,0644);
```

最后，如果服务器已经被配置为虚拟内存系统的话,`initServer()`将Redis的虚拟内存系统初始化，

## Back up to main()返回main函数

如果服务器被配置为守护进程，Redis 现在将尝试写一个 pid 文件（其路径是可配置的，但默认为 `/var/run/redis.pid`）。
此时，服务器已经启动了，Redis将把这一事实记录到它的日志文件中。然而，在Redis完全准备好之前，`main()`中还有一点要做。

### Restoring data

如果有一个AOF或数据库转储文件（例如，`dump.rdb`），它将被加载，将数据从以前的会话恢复到服务器。(如果两者都存在，则AOF优先）。

```
// redis.c:1452
if (server.appendonly) {
    if (loadAppendOnlyFile(server.appendfilename) == REDIS_OK)
        redisLog(REDIS_NOTICE,"DB loaded from append only file: %ld seconds",time(NULL)-start);
} else {
    if (rdbLoad(server.dbfilename) == REDIS_OK)
        redisLog(REDIS_NOTICE,"DB loaded from disk: %ld seconds",time(NULL)-start);
}
```

服务器现在已准备好开始接受请求。

### Event loop setup

最后，Redis注册了一个函数，在每次进入事件循环时被调用，即`beforeSleep()`（因为进程在等待事件通知时基本上会进入睡眠状态）。 `beforeSleep()`做了两件事：它处理那些请求键的客户端，如果虚拟内存系统被启用，这些键会被交换到磁盘上；它将AOF刷到磁盘上。AOF文件的写入是由`flushAppendOnlyFile()`处理的。该函数封装了一些tricky的逻辑，这些逻辑是关于冲刷（flushing）保存等待写入AOF的缓冲区（其频率可由用户配置）。（这一段翻译的不是很好，大家可以看看原文The function encapsulates some tricky logic about flushing the buffer that holds pending AOF writes (the frequency of which is configurable by the user).）

### Entering the event loop

Redis现在通过调用aeMain()进入主事件循环，参数为server.el（记住，这个成员变量包含一个指向aeEventLoop的指针）。如果每次通过循环时有任何时间（即服务器cron任务）或文件事件需要处理，它们各自的处理函数将被调用。 `aeProcessEvents()`封装了这个逻辑--time events由自定义逻辑处理，而file events则由底层的`epoll` 或者 `kqueue` 或者 `select` I/OI/O事件通知系统处理。

由于Redis需要对time event以及file或I/O事件做出响应，它实现了一个自定义的事件/轮询循环，即`aeMain()`。通过检查是否有任何时间事件需要处理，并利用文件事件通知，事件循环可以有效地睡眠，直到有工作要做，而不是在紧张的`while`循环中占用CPU。

# Processing a request & returning a response 处理请求并返回

我们现在在 Redis 的主事件轮询循环中，在一个端口上监听并等待客户的连接。现在是时候看看Redis如何处理一个命令请求了。

![redis请求处理过程](https://www.pauladamsmith.com/articles/redis_under_the_hood/request-response.png)

## Handling a new connection

返回`initServer()`，redis注册一个函数`acceptHandler()`，当有一个与服务器监听的套接字的文件描述符相关的I/O事件时被调用（即，该套接字有数据等待被读取或写入）。`acceptHandler()`创建一个client 对象-一个指向`redisClient`的指针，`redisClient`是一个定义在`redis.h`的结构体，- -来代表一个新的客户连接。

```
// networking.c:347
cfd = anetAccept(server.neterr, fd, cip, &cport);
if (cfd == AE_ERR) {
    redisLog(REDIS_VERBOSE,"Accepting client connection: %s", server.neterr);
    return;
}
redisLog(REDIS_VERBOSE,"Accepted %s:%d", cip, cport);
if ((c = createClient(cfd)) == NULL) {
    redisLog(REDIS_WARNING,"Error allocating resoures for the client");
    close(cfd); /* May be already closed, just ingore errors */
    return;
}
```

`createClient()`被调用来分配和初始化客户端对象。它默认选择0号数据库（因为每台服务器必须至少有一个Redis数据库），并将`acceptHandler()`中由accept(2)生成的客户端文件描述符与客户端对象相关联。初始化其他标志和成员变量，最后，客户端对象被追加到由`server.clients`跟踪的全局客户端列表中。Redis在`createClient()`中做的关键事情是在事件循环中注册一个处理程序，即函数`readQueryFromClient()`，以便在有数据要从客户端连接读取时使用。

```
// networking.c:20
if (aeCreateFileEvent(server.el,fd,AE_READABLE, readQueryFromClient, c) == AE_ERR)
{
    close(fd);
    zfree(c);
    return NULL;
}
```

## Reading a command from a client

当客户端发出命令请求时，main event loop调用 `readQueryFromClient()`。（如果您使用 GDB 进行调试，可以在这里设置断电。）它尽可能多地把命令读取到到临时缓冲区（最多 1024 个字节），然后将其附加到client-specific（客户端特定的）查询缓冲区。这允许 Redis 处理（命令名加上参数）大于 1024 字节的命令，或者由于 I/O 原因被拆分为多个读取事件。然后它调用`processInputBuffer()`，将客户端对象作为参数传递。

```
// networking.c:754
void readQueryFromClient(aeEventLoop *el, int fd, void *privdata, int mask) {
    redisClient *c = (redisClient*) privdata;
    char buf[REDIS_IOBUF_LEN];
    int nread;
    // ...

    nread = read(fd, buf, REDIS_IOBUF_LEN);
    // ...
    if (nread) {
        size_t oldlen = sdslen(c->querybuf);
        c->querybuf = sdscatlen(c->querybuf, buf, nread);
        c->lastinteraction = time(NULL);
        /* Scan this new piece of the query for the newline. We do this
         * here in order to make sure we perform this scan just one time
         * per piece of buffer, leading to an O(N) scan instead of O(N*N) */
        if (c->bulklen == -1 && c->newline == NULL)
            c->newline = strchr(c->querybuf+oldlen,'\n');
    } else {
        return;
    }
    Processinputbuffer(c);
}
```

`processInputBuffer()`为redis的命令将来自客户端的原始查询解析在参数里。它首先要处理那些可能阻塞在`B{L,R}POP`命令中的客户端，如果是这种情况，`processInputBuffer()`将提前退出。然后，该函数将原始查询缓冲区解析为参数，为每个参数创建Redis字符串对象，并将其存储在客户端对象的一个数组中。`processInputBuffer()`实际上是一个协议解析器，回调到`processCommand()`来完全解析查询。有点令人困惑的是，源代码注释描述了对 "多批量命令类型 "的解析，这是一个替代协议，最初是为MSET等命令准备的，但实际上它现在是所有命令的主要Redis协议。它是二进制安全的，易于解析和调试。(注意：这段代码已经为即将发布的2.2版本进行了重构，更容易理解了）。现在是时候通过调用客户端对象的`processCommand()`来实际执行客户端发送的命令了。

`processCommand()`从客户端接收一个命令的参数并执行它。在实际执行命令之前，它进行了一系列的检查--如果任何检查失败，它就会在客户端对象的回复列表中附加一条错误信息，然后返回给调用者，即`processInputBuffer()`。在将QUIT命令作为特殊情况处理后（为了安全地关闭客户端），`processCommand()`在`commandTable`中查找命令名，该表是之前在Redis启动周期中设置的。如果是一个未知的命令，或者客户端把命令的arity搞错了（原文or the client got the arity of the command wrong），那就是一个错误。有个功能虽然不常用，Redis可以被配置为在接受命令之前需要密码来验证客户端，这是Redis将检查客户端是否验证的阶段，如果没有密码，将设置错误。如果Redis被配置为最多使用一个最大的内存量，它将在此时尝试释放内存，如果可以的话（是释放空闲列表中的对象和删除过期的键），否则如果服务器超过了限制，它将不处理设置了`REDIS_CMD_DENYOOM`标志的命令（主要是像`SET`、`INCR`、`RPUSH`、`ZADD`等写操作），同样，设置错误。Redis做的最后一项检查是，客户端只能在有未订阅的时发出`SUBSCRIBE或`UNSUBSCRIBE命令`，否则，就是错误。如果所有的检查都通过了，命令就会被执行，方法是以客户端对象和命令对象为参数调用 `call()`。

## Executing the command and responding 执行命令并且响应

call()，从`command`对象的`proc`成员中获得一个指向`struct redisCommandProc`类型的函数的指针，它需要一个参数，即客户对象的参数。Redis命令程序被调用。

```
// redis.c:864
void call(redisClient *c, struct redisCommand *cmd) {
    long long dirty;

    dirty = server.dirty;
    cmd->proc(c);
    dirty = server.dirty-dirty;
}
// ```、
```

写入命令，如`SET`和`ZADD`，使服务器 "dirty"，换句话说，服务器被标记为内存中的页面已经改变。这对自动保存程序是很重要的，它可以跟踪在一定时期内有多少个键发生了变化，或者写到AOF中。如果启用了AOF的使用，该函数会调用`feedAppendOnlyFile()`，将命令缓冲区从客户端写到AOF文件上，这样命令就可以被重新执行一遍了。(它将设置相对密钥过期的命令翻译成绝对过期，但除此之外，它基本上是复制从客户端传来的命令，见`catAppendOnlyGenericCommand()`。) 如果有任何从服务器连接，`call()`将把命令发送给每个从机，让它们在本地执行，见replicationFeedSlaves()。同样地，如果有客户端连接并发出了`MONITOR`命令，Redis将发送该命令的表示，前缀为时间戳，见`replicationFeedMonitors()`。

> 每个Redis命令都负责为客户端设置回复。这是有可能的，因为Redis命令过程的签名是一个参数，也就是客户端对象。同样，每个命令过程负责对命令中的参数进行编码，或反序列化，以及对内存中的Redis对象进行解码，或序列化，以便对客户端进行响应。

```
// redis.c:871 (call() cont.'d)
    // ...
    if (server.appendonly && dirty)
        feedAppendOnlyFile(cmd,c->db->id,c->argv,c->argc);
    if ((dirty || cmd->flags & REDIS_CMD_FORCE_REPLICATION) &&
        listLength(server.slaves))
        replicationFeedSlaves(server.slaves,c->db->id,c->argv,c->argc);
    if (listLength(server.monitors))
        replicationFeedMonitors(server.monitors,c->db->id,c->argv,c->argc);
    server.stat_numcommands++;
}
```

控制权返回给调用者，`processCommand()`，它为后续的命令重置了客户端对象。
如前所述，每个Redis命令程序本身负责设置要发送给客户端的响应。在`readQueryFromClient()`退出后，Redis返回到`aeMain()`中的事件循环，`aeProcessEvents()`将在写缓冲区中获取等待的响应，并将其复制到客户端连接的套接字。
响应已经发送，客户端和服务器都回到了可以分别发出和处理更多Redis命令的状态。



# Summary

Redis启动时初始化一个全局服务器状态变量，并读取一个可选的配置文件来覆盖任何默认值。建立一个全局命令表，将命令名称与实现该命令的实际功能联系起来。创建一个事件循环，使用最好的底层系统库进行事件/准备就绪通知，并注册了一个处理函数为了当有新的客户端套接字连接需要接受时。并且还注册了一个周期性的（即基于时间的）事件处理函数，用于处理类似于cron的任务，如需要在常规客户端处理路径之外处理的密钥到期。一旦客户端连接了，就会在事件循环中注册一个函数，以便在客户端有数据需要读取（即对一个命令的查询）时得到通知。客户端的查询一经被解析，一个命令处理程序就会被调用，以执行该命令并将响应返回给客户端（向客户端写入数据也由`event-notification`循环处理）。客户端对象被重置，服务器准备处理更多的查询。

