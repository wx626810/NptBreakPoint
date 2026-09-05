;
; @file       x64.asm
;
; @brief      所有汇编代码：
;               - SvLaunchVm            : VM 循环（VMRUN / VMEXIT 分发）
;               - TrampolineTemplate    : 跳板模板（被拷贝到可执行池后修补）
;               - AsmVmmCallResetShadows: Guest 侧 vmmcall 封装（影子页复位）
;               - AsmGetGdtr / AsmGetIdtr: 读取 GDTR/IDTR
;
; @details    参考 SimpleSvm (tandasat) 的 x64.asm。
;
.const

KTRAP_FRAME_SIZE            equ     190h
MACHINE_FRAME_SIZE          equ     28h

;
; VMMCALL 功能码（与 NptHook.hpp 保持一致）
;
VMMCALL_RESET_SHADOWS       equ     00004e51h
VMMCALL_BP_CONTINUE         equ     00004e52h
VMMCALL_DRPROBE_SET         equ     00004e53h
VMMCALL_SYSCALL_DISPATCH    equ     00004e58h

.code

extern NptHandleVmExit : proc

;
;   @brief      把全部通用寄存器压栈。
;
;   @details    不修改标志寄存器。RSP 位置压入占位值。
;
PUSHAQ macro
        push    rax
        push    rcx
        push    rdx
        push    rbx
        push    -1      ; Dummy for rsp.
        push    rbp
        push    rsi
        push    rdi
        push    r8
        push    r9
        push    r10
        push    r11
        push    r12
        push    r13
        push    r14
        push    r15
        endm

;
;   @brief      把全部通用寄存器出栈。
;
;   @details    不修改标志寄存器。
;
POPAQ macro
        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     r11
        pop     r10
        pop     r9
        pop     r8
        pop     rdi
        pop     rsi
        pop     rbp
        pop     rbx    ; Dummy for rsp (this value is destroyed by the next pop).
        pop     rbx
        pop     rdx
        pop     rcx
        pop     rax
        endm

;
;   @brief      进入“执行 Guest / 处理 #VMEXIT”循环。
;
;   @details    切换到 Host 栈指针，反复运行 Guest 并处理 #VMEXIT，
;               直到 SvHandleVmExit 返回非零值（请求卸载 Hypervisor）。
;               卸载后返回到触发 #VMEXIT 的指令的下一条。
;
;   @param[in]  HostRsp - Hypervisor 栈指针（指向 HostStackLayout.GuestVmcbPa）。
;
SvLaunchVm proc frame
        ;
        ; 切换到 Host 栈。原来的 Guest 栈不再使用（防止被 Guest 覆盖）。
        ;
        mov     rsp, rcx    ; Rsp <= HostRsp

SvLV10: ;
        ; 当前栈布局（HostStackLayout）：
        ;   Rsp          => 0x...fd0 GuestVmcbPa
        ;                  0x...fd8 HostVmcbPa
        ;                  0x...fe0 Self
        ;                  0x...fe8 SharedVpData
        ;                  0x...ff0 Padding1
        ;                  0x...ff8 Reserved1
        ;
        mov     rax, [rsp]  ; RAX <= VpData->HostStackLayout.GuestVmcbPa
        vmload  rax         ; 加载 Guest 状态到处理器

        ;
        ; 进入 Guest 模式。VMRUN 在 #VMEXIT 时返回，且：
        ;   - 清除 GIF（中断被禁用）
        ;   - 保存 Guest 状态到 VMCB
        ;   - 加载 Host 状态
        ;
        vmrun   rax

        ;
        ; #VMEXIT：用 VMSAVE 保存未被硬件保存的 Guest 状态。
        ;
        vmsave  rax

        ;
        ; 构造 KTRAP_FRAME，便于 Windbg 在 SvHandleVmExit 执行期间
        ; 重建 Guest 调用栈。
        ;
        .pushframe
        sub     rsp, KTRAP_FRAME_SIZE
        .allocstack KTRAP_FRAME_SIZE - MACHINE_FRAME_SIZE + 100h

        ;
        ; 保存 Guest 通用寄存器（硬件不会自动保存）。
        ;
        PUSHAQ

        ;
        ; 设置 SvHandleVmExit 参数。当前栈布局：
        ;   Rsp                             => 0x...dc0 R15       ; GUEST_REGISTERS
        ;   Rsp + 8 * 16                    => 0x...e40 TrapFrame ; HostStackLayout
        ;   Rsp + 8 * 16 + KTRAP_FRAME_SIZE => 0x...fd0 GuestVmcbPa
        ;   Rsp + 8 * 18 + KTRAP_FRAME_SIZE => 0x...fe0 Self
        ;
        mov     rdx, rsp                                ; Rdx <= GuestRegisters
        mov     rcx, [rsp + 8 * 18 + KTRAP_FRAME_SIZE]  ; Rcx <= VpData

        ;
        ; 保存易失 XMM 寄存器（XMM0-5），分配 home space。
        ;
        sub     rsp, 80h
        movaps  xmmword ptr [rsp + 20h], xmm0
        movaps  xmmword ptr [rsp + 30h], xmm1
        movaps  xmmword ptr [rsp + 40h], xmm2
        movaps  xmmword ptr [rsp + 50h], xmm3
        movaps  xmmword ptr [rsp + 60h], xmm4
        movaps  xmmword ptr [rsp + 70h], xmm5
        .endprolog

        ;
        ; 处理 #VMEXIT。
        ;
        call    NptHandleVmExit

        ;
        ; 恢复 XMM 寄存器，回滚栈指针。
        ;
        movaps  xmm5, xmmword ptr [rsp + 70h]
        movaps  xmm4, xmmword ptr [rsp + 60h]
        movaps  xmm3, xmmword ptr [rsp + 50h]
        movaps  xmm2, xmmword ptr [rsp + 40h]
        movaps  xmm1, xmmword ptr [rsp + 30h]
        movaps  xmm0, xmmword ptr [rsp + 20h]
        add     rsp, 80h

        ;
        ; 测试 SvHandleVmExit 返回值（RAX），然后恢复 Guest 寄存器。
        ;
        test    al, al
        POPAQ

        ;
        ; 非零 = 请求卸载；否则继续循环。
        ;
        jnz     SvLV20                  ; if (ExitVm != 0) jmp SvLV20
        add     rsp, KTRAP_FRAME_SIZE   ; else 恢复 RSP 并
        jmp     SvLV10                  ;      继续运行 Guest

SvLV20: ;
        ; 虚拟化已终止。恢复原始（Guest）栈指针并返回。
        ; 此时寄存器内容：
        ;   RBX     = 返回地址（Guest NRip）
        ;   RCX     = 要恢复的原始栈指针
        ;   EDX:EAX = 本 CPU 的每处理器数据结构地址
        ;
        mov     rsp, rcx

        ;
        ; ECX 置为卸载魔法值 'NPTU'，供 C 侧校验。
        ;
        mov     ecx, 'NPTU'

        ;
        ; 返回 cpuid 触发指令的下一条。寄存器结果：
        ;   EBX     = 未定义
        ;   ECX     = 'NPTU'
        ;   EDX:EAX = 每处理器数据结构地址
        ;
        jmp     rbx
SvLaunchVm endp

;
; ============================================================================
;   跳板模板 (TrampolineTemplate)
; ============================================================================
;
;   Guest 在 #BP VMEXIT 中被重定向到跳板入口（= 跳板基址 + 模板偏移），
;   以“原函数入口的视角”执行：
;
;   1. 保存全部 GPR + XMM0-15 + 返回地址
;   2. 组装 HOOK_CALL_CONTEXT 并调用回调
;      BOOLEAN Callback(PHOOK_CALL_CONTEXT)
;      - 返回 TRUE  (拦截)：从 Context 恢复寄存器（回调可改返回值）,
;                          vmmcall 通知 Hypervisor, ret 返回调用者
;      - 返回 FALSE (放行)：恢复寄存器, 执行序言副本, 跳回原函数继续
;
;   模板被整体拷贝到可执行内存池后，需要修补以下数据：
;     [Trampoline+2h] HookFunction     - 回调函数地址
;     [Trampoline+0ah] OriginalRip      - 被 Hook 函数入口地址
;     [Trampoline+12h] AfterPrologRip   - 被 Hook 函数入口 + 序言长度
;     [Trampoline+1ah] PrologBytesRip   - 跳板缓冲区内序言副本的地址
;
;   跳板缓冲区布局：[模板][序言副本][跳回桩 mov rax,imm64; jmp rax]
;
;   帧布局（RSP 进入时 8 对齐；sub 228h 后 16 对齐）：
;     [rsp+0..1fh] 回调 home space（会被 callee 写入，勿存数据）
;     [rsp+20h..11fh] XMM0-15
;     [rsp+120h..197h] GPR（rax,rcx,rdx,rbx,rbp,rsi,rdi,r8..r15）
;     [rsp+198h..19fh] 返回地址
;     [rsp+1a0h..227h] HOOK_CALL_CONTEXT（88h 字节）
; ============================================================================
TrampolineTemplate proc
        ;
        ; 跳过数据区。
        ;
        jmp     TCode

HookFunction     dq      0       ; +2h  回调地址（安装时修补）
OriginalRip      dq      0       ; +0ah  被 Hook 函数入口（安装时修补）
AfterPrologRip   dq      0       ; +12h  入口+序言长度（安装时修补）
PrologBytesRip   dq      0       ; +1ah  序言副本地址（安装时修补）

TCode:
        sub     rsp, 228h

        ; ---- 保存 XMM0-15 ----
        movaps  xmmword ptr [rsp+20h], xmm0
        movaps  xmmword ptr [rsp+30h], xmm1
        movaps  xmmword ptr [rsp+40h], xmm2
        movaps  xmmword ptr [rsp+50h], xmm3
        movaps  xmmword ptr [rsp+60h], xmm4
        movaps  xmmword ptr [rsp+70h], xmm5
        movaps  xmmword ptr [rsp+80h], xmm6
        movaps  xmmword ptr [rsp+90h], xmm7
        movaps  xmmword ptr [rsp+0a0h], xmm8
        movaps  xmmword ptr [rsp+0b0h], xmm9
        movaps  xmmword ptr [rsp+0c0h], xmm10
        movaps  xmmword ptr [rsp+0d0h], xmm11
        movaps  xmmword ptr [rsp+0e0h], xmm12
        movaps  xmmword ptr [rsp+0f0h], xmm13
        movaps  xmmword ptr [rsp+100h], xmm14
        movaps  xmmword ptr [rsp+110h], xmm15

        ; ---- 保存 GPR ----
        mov     [rsp+120h], rax
        mov     [rsp+128h], rcx
        mov     [rsp+130h], rdx
        mov     [rsp+138h], rbx
        mov     [rsp+140h], rbp
        mov     [rsp+148h], rsi
        mov     [rsp+150h], rdi
        mov     [rsp+158h], r8
        mov     [rsp+160h], r9
        mov     [rsp+168h], r10
        mov     [rsp+170h], r11
        mov     [rsp+178h], r12
        mov     [rsp+180h], r13
        mov     [rsp+188h], r14
        mov     [rsp+190h], r15

        ; ---- 保存返回地址（入口时位于 [rsp+228h]）----
        mov     rax, [rsp+228h]
        mov     [rsp+198h], rax

        ; ---- 组装 HOOK_CALL_CONTEXT（[rsp+1a0h]）----
        lea     rcx, [rsp+1a0h]
        mov     rax, qword ptr [OriginalRip]
        mov     [rcx+0], rax                 ; OriginalFunction
        mov     rax, [rsp+198h]
        mov     [rcx+8h], rax                 ; ReturnAddress
        mov     rax, [rsp+120h]                ; Rax
        mov     [rcx+10h], rax
        mov     rax, [rsp+128h]                ; Rcx
        mov     [rcx+18h], rax
        mov     rax, [rsp+130h]                ; Rdx
        mov     [rcx+20h], rax
        mov     rax, [rsp+138h]                ; Rbx
        mov     [rcx+28h], rax
        mov     rax, [rsp+140h]                ; Rbp
        mov     [rcx+30h], rax
        mov     rax, [rsp+148h]                ; Rsi
        mov     [rcx+38h], rax
        mov     rax, [rsp+150h]                ; Rdi
        mov     [rcx+40h], rax
        mov     rax, [rsp+158h]                ; R8
        mov     [rcx+48h], rax
        mov     rax, [rsp+160h]                ; R9
        mov     [rcx+50h], rax
        mov     rax, [rsp+168h]                ; R10
        mov     [rcx+58h], rax
        mov     rax, [rsp+170h]                ; R11
        mov     [rcx+60h], rax
        mov     rax, [rsp+178h]                ; R12
        mov     [rcx+68h], rax
        mov     rax, [rsp+180h]                ; R13
        mov     [rcx+70h], rax
        mov     rax, [rsp+188h]                ; R14
        mov     [rcx+78h], rax
        mov     rax, [rsp+190h]                ; R15
        mov     [rcx+80h], rax

        ; ---- 调用回调：BOOLEAN HookFunction(PHOOK_CALL_CONTEXT) ----
        mov     rax, qword ptr [HookFunction]
        call    rax
        test    al, al
        jnz     TIntercepted

        ;
        ; ============ 放行路径 ============
        ; 恢复现场 → 执行序言副本 → 跳回原函数
        ;
        movaps  xmm0,  xmmword ptr [rsp+20h]
        movaps  xmm1,  xmmword ptr [rsp+30h]
        movaps  xmm2,  xmmword ptr [rsp+40h]
        movaps  xmm3,  xmmword ptr [rsp+50h]
        movaps  xmm4,  xmmword ptr [rsp+60h]
        movaps  xmm5,  xmmword ptr [rsp+70h]
        movaps  xmm6,  xmmword ptr [rsp+80h]
        movaps  xmm7,  xmmword ptr [rsp+90h]
        movaps  xmm8,  xmmword ptr [rsp+0a0h]
        movaps  xmm9,  xmmword ptr [rsp+0b0h]
        movaps  xmm10, xmmword ptr [rsp+0c0h]
        movaps  xmm11, xmmword ptr [rsp+0d0h]
        movaps  xmm12, xmmword ptr [rsp+0e0h]
        movaps  xmm13, xmmword ptr [rsp+0f0h]
        movaps  xmm14, xmmword ptr [rsp+100h]
        movaps  xmm15, xmmword ptr [rsp+110h]

        mov     rax, [rsp+120h]
        mov     rcx, [rsp+128h]
        mov     rdx, [rsp+130h]
        mov     rbx, [rsp+138h]
        mov     rbp, [rsp+140h]
        mov     rsi, [rsp+148h]
        mov     rdi, [rsp+150h]
        mov     r8,  [rsp+158h]
        mov     r9,  [rsp+160h]
        mov     r10, [rsp+168h]
        mov     r11, [rsp+170h]
        mov     r12, [rsp+178h]
        mov     r13, [rsp+180h]
        mov     r14, [rsp+188h]
        mov     r15, [rsp+190h]

        add     rsp, 228h

        ; 跳到序言副本（副本末尾附有“mov rax, imm64; jmp rax”跳回桩）
        mov     rax, qword ptr [PrologBytesRip]
        jmp     rax

TIntercepted:
        ;
        ; ============ 拦截路径 ============
        ; 从 Context 恢复寄存器（回调可修改以设置返回值）→ vmmcall → 返回调用者
        ;
        movaps  xmm0,  xmmword ptr [rsp+20h]
        movaps  xmm1,  xmmword ptr [rsp+30h]
        movaps  xmm2,  xmmword ptr [rsp+40h]
        movaps  xmm3,  xmmword ptr [rsp+50h]
        movaps  xmm4,  xmmword ptr [rsp+60h]
        movaps  xmm5,  xmmword ptr [rsp+70h]
        movaps  xmm6,  xmmword ptr [rsp+80h]
        movaps  xmm7,  xmmword ptr [rsp+90h]
        movaps  xmm8,  xmmword ptr [rsp+0a0h]
        movaps  xmm9,  xmmword ptr [rsp+0b0h]
        movaps  xmm10, xmmword ptr [rsp+0c0h]
        movaps  xmm11, xmmword ptr [rsp+0d0h]
        movaps  xmm12, xmmword ptr [rsp+0e0h]
        movaps  xmm13, xmmword ptr [rsp+0f0h]
        movaps  xmm14, xmmword ptr [rsp+100h]
        movaps  xmm15, xmmword ptr [rsp+110h]

        mov     rax, [rsp+1b0h]                ; Context.Rax (1a0h+10h)
        mov     rcx, [rsp+1b8h]                ; Context.Rcx
        mov     rdx, [rsp+1c0h]                ; Context.Rdx
        mov     rbx, [rsp+1c8h]                ; Context.Rbx
        mov     rbp, [rsp+1d0h]                ; Context.Rbp
        mov     rsi, [rsp+1d8h]                ; Context.Rsi
        mov     rdi, [rsp+1e0h]                ; Context.Rdi
        mov     r8,  [rsp+1e8h]                ; Context.R8
        mov     r9,  [rsp+1f0h]                ; Context.R9
        mov     r10, [rsp+1f8h]                ; Context.R10
        mov     r11, [rsp+200h]                ; Context.R11
        mov     r12, [rsp+208h]                ; Context.R12
        mov     r13, [rsp+210h]                ; Context.R13
        mov     r14, [rsp+218h]                ; Context.R14
        mov     r15, [rsp+220h]                ; Context.R15

        add     rsp, 228h

        ;
        ; 通知 Hypervisor 复位影子页（被 Hook 的都是内核函数，CPL==0）。
        ; 用原始字节形式编码 vmmcall（0F 01 D9），避免 ml64 兼容性问题。
        ;
        mov     eax, VMMCALL_RESET_SHADOWS
        db      0Fh, 01h, 0D9h          ; vmmcall
        ret
TrampolineTemplate endp

;
; 模板大小（整个模板含数据区与代码区）。安装时拷贝到可执行池后
; 在尾部追加序言副本与跳回桩。
;
public TrampolineTemplateSize
TrampolineTemplateSizeValue label byte
TrampolineTemplateSize dd (TrampolineTemplateSizeValue - TrampolineTemplate)

;
;   @brief      Guest 侧 vmmcall 封装：请求 Hypervisor 复位当前 CPU 的
;               所有影子页（回到“读/写视图、NX=1”状态）。
;
;   @details    由复位线程在目标 CPU 上执行（亲和性切换后调用）。
;
AsmVmmCallResetShadows proc
        mov     eax, VMMCALL_RESET_SHADOWS
        db      0Fh, 01h, 0D9h          ; vmmcall
        ret
AsmVmmCallResetShadows endp

;
;   @brief      Guest 侧 vmmcall 封装：请求 Hypervisor 继续被暂停的断点。
;
;   @details    参数：rcx = BpId（0 = 全部）。由 NpBreakPointContinue
;               在断点暂停所在 CPU 上调用（亲和性切换后）。
;
AsmVmmCallBpContinue proc
        mov     eax, VMMCALL_BP_CONTINUE
        db      0Fh, 01h, 0D9h          ; vmmcall
        ret
AsmVmmCallBpContinue endp

;
;   @brief      Guest 侧 vmmcall 封装：开启/关闭 DR 探测（DR 硬件断点虚拟化）。
;
;   @details    参数：rcx = 0（关闭）或 1（开启）。由 NpBreakPointSetDrProbe
;               在目标 CPU 上调用（亲和性切换后）。处理器在 VMEXIT 上下文
;               修改自己的 VMCB.InterceptDrRead/Write（下次 VMRUN 生效）。
;
AsmVmmCallDrProbe proc
        mov     eax, VMMCALL_DRPROBE_SET
        db      0Fh, 01h, 0D9h          ; vmmcall
        ret
AsmVmmCallDrProbe endp


;
;   @brief      读取 GDTR。
;
;   @param[in]  Descriptor - DESCRIPTOR_TABLE_REGISTER 输出缓冲区（10 字节）。
;
AsmGetGdtr proc
        sgdt    [rcx]
        ret
AsmGetGdtr endp

;
;   @brief      读取 IDTR。
;
;   @param[in]  Descriptor - DESCRIPTOR_TABLE_REGISTER 输出缓冲区（10 字节）。
;
AsmGetIdtr proc
        sidt    [rcx]
        ret
AsmGetIdtr endp

        end
