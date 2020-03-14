;++
;
; Copyright (c) Petr Benes. All rights reserved.
;
; Module:
;
;   vcpu.asm
;
; Abstract:
;
;   This module implements VM-Exit stub handler.
;
; Author:
;
;    Petr Benes (@PetrBenes) 26-Jul-2018 - Initial version
;
; Environment:
;
;    Kernel mode only.
;
;--

INCLUDE ksamd64.inc

    machine_frame_t struct
        $rip    dq ?
        $cs     dq ?
        $eflags dq ?
        $rsp    dq ?
        $ss     dq ?
    machine_frame_t ends

    context_t struct
        $rax    dq ?
        $rcx    dq ?
        $rdx    dq ?
        $rbx    dq ?
        $rsp    dq ?
        $rbp    dq ?
        $rsi    dq ?
        $rdi    dq ?
        $r8     dq ?
        $r9     dq ?
        $r10    dq ?
        $r11    dq ?
        $r12    dq ?
        $r13    dq ?
        $r14    dq ?
        $r15    dq ?
        $rip    dq ?
        $rflags dq ?
    context_t ends


.CODE

    VCPU_OFFSET                         = -8000h             ; -vcpu_stack_size
    VCPU_CONTEXT_OFFSET                 =  0                 ; ..
    VCPU_LAUNCH_CONTEXT_OFFSET          =  0                 ; ... connected by union {}
                                                             ;
    SHADOW_SPACE                        =  20h

;
; Externally used symbols.
;
    ; "private: void    __cdecl hvpp::vcpu_t::entry_host(void)"
    EXTERN ?entry_host@vcpu_t@Travel_vt@@AEAAXXZ           : PROC

    ; "private: void    __cdecl hvpp::vcpu_t::entry_guest(void)"
    EXTERN ?entry_guest@vcpu_t@Travel_vt@@AEAAXXZ          : PROC



;++
;
; public:
;   int __cdecl
;   ia32::context_t::capture(void)
;
; Routine description:
;
;   This method captures the context of the caller.
;
; Return Value:
;
;   0 if caller captured the context, RAX otherwise.
;
;--
    ?capture@context_t@ia32@@QEAAHXZ PROC
        pushfq
        mov     context_t.$rax[rcx], rax
        mov     context_t.$rcx[rcx], rcx
        mov     context_t.$rdx[rcx], rdx
        mov     context_t.$rbx[rcx], rbx
        mov     context_t.$rbp[rcx], rbp
        mov     context_t.$rsi[rcx], rsi
        mov     context_t.$rdi[rcx], rdi
        mov     context_t.$r8 [rcx], r8
        mov     context_t.$r9 [rcx], r9
        mov     context_t.$r10[rcx], r10
        mov     context_t.$r11[rcx], r11
        mov     context_t.$r12[rcx], r12
        mov     context_t.$r13[rcx], r13
        mov     context_t.$r14[rcx], r14
        mov     context_t.$r15[rcx], r15

;
; RSP, RIP and RFLAGS are captured here.
;
        lea     rax, qword ptr [rsp + 16]
        mov     context_t.$rsp[rcx], rax

        mov     rax, qword ptr [rsp +  8]
        mov     context_t.$rip[rcx], rax

        mov     rax, qword ptr [rsp +  0]
        mov     context_t.$rflags[rcx], rax

        xor     rax, rax
        add     rsp, 8
        ret
    ?capture@context_t@ia32@@QEAAHXZ ENDP
 

;++
;
; public:
;   void __cdecl
;   ia32::context_t::restore(void)
;
; Routine description:
;
;   This method restores the context of the caller to the specified
;   context.
;
; Return Value:
;
;   None - there is no return from this method.
;
;--
    ?restore@context_t@ia32@@QEAAXXZ PROC
        sub     rsp, 8
        mov     word ptr [rsp + 4 * 8], ss

        mov     rax, context_t.$rsp[rcx]
        mov     qword ptr [rsp + 3 * 8], rax

        mov     rax, context_t.$rflags[rcx]
        mov     qword ptr [rsp + 2 * 8], rax

        mov     word ptr [rsp + 1 * 8], cs

        mov     rax, context_t.$rip[rcx]
        mov     qword ptr [rsp + 0 * 8], rax

        mov     rax, context_t.$rax[rcx]
        mov     rdx, context_t.$rdx[rcx]
        mov     rbx, context_t.$rbx[rcx]
        mov     rbp, context_t.$rbp[rcx]
        mov     rsi, context_t.$rsi[rcx]
        mov     rdi, context_t.$rdi[rcx]
        mov     r8 , context_t.$r8 [rcx]
        mov     r9 , context_t.$r9 [rcx]
        mov     r10, context_t.$r10[rcx]
        mov     r11, context_t.$r11[rcx]
        mov     r12, context_t.$r12[rcx]
        mov     r13, context_t.$r13[rcx]
        mov     r14, context_t.$r14[rcx]
        mov     r15, context_t.$r15[rcx]
        mov     rcx, context_t.$rcx[rcx]
        iretq
    ?restore@context_t@ia32@@QEAAXXZ ENDP

;++
;
; private:
;   static void __cdecl
;   Travel_vt::vcpu_t::asm_entry_guest(void)
;
; Routine description:
;
;   Determines virtual cpu context from the stack pointer and calls
;   vcpu_t::asm_entry_guest() method.
;
;--

    ?asm_entry_guest@vcpu_t@Travel_vt@@CAXXZ PROC
;
; RCX = &vcpu
; RBX = &vcpu.launch_context_
;
        lea     rcx, qword ptr [rsp + VCPU_OFFSET]
        lea     rbx, qword ptr [rsp + VCPU_LAUNCH_CONTEXT_OFFSET]

;
; Create shadow space
;
        sub     rsp, SHADOW_SPACE
        call    ?entry_guest@vcpu_t@Travel_vt@@AEAAXXZ

;
; Restore CPU context
; Note that RBX is preserved, because it is non-volatile register
;
        mov     rcx, rbx
        jmp     ?restore@context_t@ia32@@QEAAXXZ
    ?asm_entry_guest@vcpu_t@Travel_vt@@CAXXZ ENDP

;++
;
; private:
;   static void __cdecl
;   Travel_vt::vcpu_t::asm_entry_host(void)
;
; Routine description:
;
;   This method captures current CPU context and calls vcpu_t::entry_host()
;   method.
;
;   Note that this procedure is declared with FRAME attribute.
;
;   This attribute causes MASM to generate a function table entry in
;   .pdata and unwind information in .xdata for a function's structured
;   exception handling unwind behavior.  If ehandler is present, this
;   proc is entered in the .xdata as the language specific handler.
;
;   When the FRAME attribute is used, it must be followed by an .ENDPROLOG
;   directive.
;   (ref: https://docs.microsoft.com/cs-cz/cpp/build/raw-pseudo-operations)
;
;   Among exception handling, which isn't very important for us, this
;   is especially useful for recreating callstack in WinDbg.
;
;--

    ?asm_entry_host@vcpu_t@Travel_vt@@CAXXZ PROC FRAME
        push    rcx

;
; RCX = &vcpu.context_
;
        lea     rcx, qword ptr [rsp + 8 + VCPU_CONTEXT_OFFSET]
        call    ?capture@context_t@ia32@@QEAAHXZ

;
; RBX = &vcpu.context_
; RCX = original value of RCX
; RSP = original value of RSP
;
        mov     rbx, rcx
        pop     rcx

        mov     context_t.$rcx[rbx], rcx
        mov     context_t.$rsp[rbx], rsp

;
; RCX = &vcpu
;
        lea     rcx, qword ptr [rsp + VCPU_OFFSET]

;
; Create dummy machine frame.
;
; This code is not critical for any hypervisor functionality, but
; it'll help WinDbg to "append" callstack of the application which
; initiated VM-exit to the callstack of the hypervisor.  In another
; words - the callstack of the application which initiated VM-exit
; will be shown "below" the vcpu_t::entry_host_() method.
;
; This is achieved by forcing WinDbg to think this is in fact
; interrupt handler.  When interrupt occurs in 64-bit mode, the
; CPU pushes [ SS, RSP, EFLAGS, CS, RIP ] on the stack before
; execution of the interrupt handler (we call it "machine frame").
; At the end of the interrupt handler, these values are restored
; using the IRETQ instruction.
; See Vol3A[6.14.2(64-Bit Mode Stack Frame)] for more details.
;
; We will manually emulate this behavior by pushing 5 values
; (representing the registers mentioned above) on the stack
; and then issuing directive .pushframe.  The .pushframe directive
; doesn't emit any assembly instruction - instead, an opcode
; UWOP_PUSH_MACHFRAME is emitted into the unwind information of
; the executable file.  WinDbg recognizes this opcode and will
; look at the RIP and RSP values of the machine frame to recreate
; callstack.  Other fields than RIP and RSP appear to be ignored
; by WinDbg (and we don't use them either).
;
; TL;DR:
;   WinDbg recreates callstacks of interrupt handlers by looking
;   at RIP and RSP fields of the machine frame.  Therefore, make
;   WinDbg think this function is an interrupt handler by pushing
;   fake machine frame + issuing .pushframe.
;
; Note1:
;   nt!KiSystemCall64(Shadow) work in similar way.
;
; Note2:
;   We set dummy values here.  Correct values of RIP and RSP fields
;   are set in the vcpu_t::entry_host() method (vcpu.cpp).
;
; See: https://docs.microsoft.com/en-us/cpp/build/struct-unwind-code
;

        sub     rsp, 8 + sizeof machine_frame_t
        mov     machine_frame_t.$ss[rsp],     KGDT64_R3_DATA or RPL_MASK
        mov     machine_frame_t.$rsp[rsp],    2
        mov     machine_frame_t.$eflags[rsp], 3
        mov     machine_frame_t.$cs[rsp],     KGDT64_R3_CODE or RPL_MASK
        mov     machine_frame_t.$rip[rsp],    5

        .pushframe

;
; Create shadow space.
;
; The .allocstack directive will tell the compiler to emit
; UWOP_ALLOC_SMALL opcode into the unwind information of the
; executable file.  This will help WinDbg to recognize that
; in this stack-space there are local variables (and reserved
; shadow space for callees, respectivelly) and that this space
; belongs to this function.
;
; This is also needed for the callstack reconstruction to work
; correctly - otherwise WinDbg might wrongly look in this space
; to look for return addresses or stack pointers (RIP/RSP).
;

        sub     rsp, SHADOW_SPACE
        .allocstack  SHADOW_SPACE

;
; Finally, issue the .endprolog directive.
;
; This will signal end of prologue declarations (such as allocation
; of the shadow space).
;
        .endprolog

        call    ?entry_host@vcpu_t@Travel_vt@@AEAAXXZ

;
; Restore CPU context
; Note that RBX is preserved, because it is non-volatile register
;
        mov     rcx, rbx
        jmp     ?restore@context_t@ia32@@QEAAXXZ
    ?asm_entry_host@vcpu_t@Travel_vt@@CAXXZ ENDP

END
