#pragma once
#include "vcpu.h"

namespace Travel_vt
{


	class vmexit_handler
	{
	public:
		vmexit_handler();
		~vmexit_handler();

		void * operator new(size_t size);

		status_code setup(vcpu_t* vp)									noexcept;

		status_code handle_interrupt(vcpu_t& vp)						noexcept;

		status_code handle_exception_or_nmi(vcpu_t& vp)					noexcept;
		status_code handle_external_interrupt(vcpu_t& vp)				noexcept;
		status_code handle_triple_fault(vcpu_t& vp)						noexcept;
		status_code handle_init_signal(vcpu_t& vp)						noexcept;
		status_code handle_startup_ipi(vcpu_t& vp)						noexcept;
		status_code handle_io_smi(vcpu_t& vp)							noexcept;
		status_code handle_smi(vcpu_t& vp)								noexcept;
		status_code handle_interrupt_window(vcpu_t& vp)					noexcept;
		status_code handle_nmi_window(vcpu_t& vp)						noexcept;
		status_code handle_task_switch(vcpu_t& vp)						noexcept;
		status_code handle_execute_cpuid(vcpu_t& vp)					noexcept;
		status_code handle_execute_getsec(vcpu_t& vp)					noexcept;
		status_code handle_execute_hlt(vcpu_t& vp)						noexcept;
		status_code handle_execute_invd(vcpu_t& vp)						noexcept;
		status_code handle_execute_invlpg(vcpu_t& vp)					noexcept;
		status_code handle_execute_rdpmc(vcpu_t& vp)					noexcept;
		status_code handle_execute_rdtsc(vcpu_t& vp)					noexcept;
		status_code handle_execute_rsm_in_smm(vcpu_t& vp)				noexcept;
		status_code handle_execute_vmcall(vcpu_t& vp)					noexcept;
		status_code handle_execute_vmclear(vcpu_t& vp)					noexcept;
		status_code handle_execute_vmlaunch(vcpu_t& vp)					noexcept;
		status_code handle_execute_vmptrld(vcpu_t& vp)					noexcept;
		status_code handle_execute_vmptrst(vcpu_t& vp)					noexcept;
		status_code handle_execute_vmread(vcpu_t& vp)					noexcept;
		status_code handle_execute_vmresume(vcpu_t& vp)					noexcept;
		status_code handle_execute_vmwrite(vcpu_t& vp)					noexcept;
		status_code handle_execute_vmxoff(vcpu_t& vp)					noexcept;
		status_code handle_execute_vmxon(vcpu_t& vp)					noexcept;
		status_code handle_mov_cr(vcpu_t& vp)							noexcept;
		status_code handle_mov_dr(vcpu_t& vp)							noexcept;
		status_code handle_execute_io_instruction(vcpu_t& vp)			noexcept;
		status_code handle_execute_rdmsr(vcpu_t& vp)					noexcept;
		status_code handle_execute_wrmsr(vcpu_t& vp)					noexcept;
		status_code handle_error_invalid_guest_state(vcpu_t& vp)		noexcept;
		status_code handle_error_msr_load(vcpu_t& vp)					noexcept;
		status_code handle_reserved_1(vcpu_t& vp)						noexcept;// reserved_1
		status_code handle_execute_mwait(vcpu_t& vp)					noexcept;
		status_code handle_monitor_trap_flag(vcpu_t& vp)				noexcept;
		status_code handle_reserved_2(vcpu_t& vp)						noexcept; // reserved_2
		status_code handle_execute_monitor(vcpu_t& vp)					noexcept;
		status_code handle_execute_pause(vcpu_t& vp)					noexcept;
		status_code handle_error_machine_check(vcpu_t& vp)				noexcept;
		status_code handle_reserved_3(vcpu_t& vp)						noexcept; // reserved_3
		status_code handle_tpr_below_threshold(vcpu_t& vp)				noexcept;
		status_code handle_apic_access(vcpu_t& vp)						noexcept;
		status_code handle_virtualized_eoi(vcpu_t& vp)					noexcept;
		status_code handle_gdtr_idtr_access(vcpu_t& vp)					noexcept;
		status_code handle_ldtr_tr_access(vcpu_t& vp)					noexcept;
		status_code handle_ept_violation(vcpu_t& vp)					noexcept;
		status_code handle_ept_misconfiguration(vcpu_t& vp)				noexcept;
		status_code handle_execute_invept(vcpu_t& vp)					noexcept;
		status_code handle_execute_rdtscp(vcpu_t& vp)					noexcept;
		status_code handle_vmx_preemption_timer_expired(vcpu_t& vp)		noexcept;
		status_code handle_execute_invvpid(vcpu_t& vp)					noexcept;
		status_code handle_execute_wbinvd(vcpu_t& vp)					noexcept;
		status_code handle_execute_xsetbv(vcpu_t& vp)					noexcept;
		status_code handle_apic_write(vcpu_t& vp)						noexcept;
		status_code handle_execute_rdrand(vcpu_t& vp)					noexcept;
		status_code handle_execute_invpcid(vcpu_t& vp)					noexcept;
		status_code handle_execute_vmfunc(vcpu_t& vp)					noexcept;
		status_code handle_execute_encls(vcpu_t& vp)					noexcept;
		status_code handle_execute_rdseed(vcpu_t& vp)					noexcept;
		status_code handle_page_modification_log_full(vcpu_t& vp)		noexcept;
		status_code handle_execute_xsaves(vcpu_t& vp)					noexcept;
		status_code handle_execute_xrstors(vcpu_t& vp)					noexcept;

		
		
	};

 

};