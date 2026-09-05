# 交叉验证用的真实指令流：由 gcc 汇编、objdump 反汇编生成真值
.intel_syntax noprefix
.text
.global _start
_start:
    # 常见内核序言
    mov     qword ptr [rsp+8], rbx
    mov     qword ptr [rsp+0x10], rdi
    mov     qword ptr [rsp+0x18], rsi
    push    rbp
    mov     rbp, rsp
    sub     rsp, 0x20
    sub     rsp, 0x12345678
    push    rbx
    push    rdi
    push    rsi
    push    r14
    push    r15
    lea     rax, [rip + 0x1234]
    lea     rcx, [rsp + 0x30]
    lea     rdx, [rax + rbx*4]
    lea     r8, [r9 + r10*8 + 0x100]
    lea     r11, [rbx + r12*2 - 0x10]
    # 数据搬运
    mov     rax, rcx
    mov     rbx, rdx
    mov     r8, qword ptr [rax]
    mov     r9d, dword ptr [rax+4]
    mov     r10w, word ptr [rax+0x20]
    mov     r11b, byte ptr [rax+0x21]
    mov     qword ptr [rax], rbx
    mov     qword ptr [rax+0x8], rcx
    mov     dword ptr [rax+0x1000], 0x1234
    mov     byte ptr [rax], 0x7f
    mov     rax, 0x1122334455667788
    mov     eax, 0x12345678
    mov     r11, 0x12345678
    # 算术/逻辑
    add     rax, rbx
    add     eax, 0x12345678
    add     rax, 0x12345678
    add     ax, 0x1234
    add     al, 0x12
    sub     rax, rbx
    sub     eax, 0x10
    sub     rsp, 0x28
    and     eax, 0xff
    or      rax, 1
    xor     eax, eax
    xor     r8d, r8d
    not     rax
    neg     rbx
    inc     rax
    dec     rbx
    mul     rbx
    imul    rax, rbx
    imul    rax, rbx, 0x10
    imul    rax, rbx, 0x12345678
    # 比较/测试
    cmp     rax, rbx
    cmp     eax, 0x10
    test    rax, rax
    test    eax, eax
    test    al, 1
    test    eax, 0x12345678
    test    byte ptr [rax], 1
    test    dword ptr [rax], 0x1234
    # 位操作
    shl     rax, 1
    shl     rax, cl
    shr     rax, 5
    shl     rax, 5
    sar     rax, 1
    rol     eax, 1
    shld    rax, rbx, 3
    shrd    rax, rbx, 3
    bts     rax, rbx
    btr     dword ptr [rax], 3
    bt      qword ptr [rax], 3
    bsf     rax, rbx
    bsr     rax, rbx
    # 扩展
    movzx   eax, byte ptr [rcx]
    movzx   rax, word ptr [rcx+4]
    movsx   rax, dword ptr [rbx]
    movsxd  rax, r8d
    movsxd  rcx, dword ptr [rax]
    # 控制流（rel8 跳转使用局部近标签，避免超范围）
    call    _start
    jmp     _start
    je      1f
    jne     1f
    jz      1f
    jnz     1f
    js      1f
    jns     1f
    jle     1f
    jg      1f
    loop    1f
    jmp     short 1f
1:  nop
    # 条件置位/传送
    setz    al
    setnz   al
    setl    al
    setle   al
    cmovz   rax, rbx
    cmovnz  rax, rbx
    cmovg   rax, rbx
    # 原子
    lock add qword ptr [rax], rbx
    lock xadd qword ptr [rax], rbx
    lock cmpxchg qword ptr [rax], rbx
    xchg    rax, rbx
    # 函数结尾
    ret
    ret     0x10
    leave
    int3
    nop
    # SSE
    movaps  xmm0, xmmword ptr [rax]
    movaps  xmmword ptr [rax], xmm0
    movups  xmm1, xmmword ptr [rbx+0x10]
    movdqu  xmm2, xmmword ptr [rcx]
    movdqa  xmm0, xmm1
    pxor    xmm0, xmm0
    xorps   xmm0, xmm0
    pshufd  xmm0, xmm1, 0x1b
    shufps  xmm0, xmm1, 0x10
    cmpps   xmm0, xmm1, 0
    movd    eax, xmm0
    movd    xmm0, eax
    movq    xmm0, rax
    movq    rax, xmm0
    # 字符串
    movsb
    movsq
    stosb
    stosq
    lodsb
    scasq
    cmpsb
    # 特权/系统
    syscall
    cpuid
    rdtsc
    rdmsr
    wrmsr
    cli
    sti
    cld
    std
    hlt
    # 中断
    int3
    int     0x2e
    # 杂项
    pushfq
    popfq
    cdqe
    cqo
    push    0x1234
    push    0x12
    enter   0x100, 0
    # 多字节 NOP
    nop
    .byte 0x0f, 0x1f, 0x40, 0x00
    .byte 0x0f, 0x1f, 0x44, 0x00, 0x00
    .byte 0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00
    # x87
    fldz
    fld     qword ptr [rax]
    fld     qword ptr [rax+0x8]
    fstp    st(0)
    fstp    qword ptr [rax]
    fnstcw  word ptr [rsp-8]
    # 更多内存寻址
    mov     rax, qword ptr [rax + rcx*8 + 0x12345678]
    mov     rbx, qword ptr [rsp + r15*8]
    mov     rcx, qword ptr [r13 + r14*4 + 0x10]
    mov     rdx, qword ptr [rip + 0x12345678]
    mov     rax, qword ptr [r8 + 0x7fffffff]
    # 段前缀
    mov     rax, qword ptr fs:[0x30]
    mov     rax, qword ptr gs:[0x10]
    mov     rax, qword ptr fs:[0x188]
