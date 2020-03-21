#include "vmexit.h"
#include "msr.h"

namespace Travel_vt
{
	vmexit_handler::vmexit_handler()
	{

	}
	vmexit_handler::~vmexit_handler()
	{

	}
	void* vmexit_handler::operator new(size_t size)
	{
		return ExAllocatePool(PagedPool, size);
	}

	status_code vmexit_handler::setup(vcpu_t * vp) noexcept
	{
	
		ia32::segment_t			 segment_cs		= { 0 };
		ia32::segment_t			 segment_ds		= { 0 };
		ia32::segment_t			 segment_es		= { 0 };
		ia32::segment_t			 segment_fs		= { 0 };
		ia32::segment_t			 segment_gs		= { 0 };
		ia32::segment_t			 segment_ss		= { 0 };
		ia32::segment_t			 segment_tr		= { 0 };
		ia32::segment_t			 segment_ldtr	= { 0 };

		ia32::segment_selector_t selector_cs	= { 0 };
		ia32::segment_selector_t selector_ds	= { 0 };
		ia32::segment_selector_t selector_es	= { 0 };
		ia32::segment_selector_t selector_fs	= { 0 };
		ia32::segment_selector_t selector_gs	= { 0 };
		ia32::segment_selector_t selector_ss	= { 0 };
		ia32::segment_selector_t selector_tr	= { 0 };
		ia32::segment_selector_t selector_ldtr  = { 0 };

		selector_cs.flags	= ia32_asm_read_cs();
		selector_ds.flags	= ia32_asm_read_ds();
		selector_es.flags	= ia32_asm_read_es();
		selector_fs.flags	= ia32_asm_read_fs();
		selector_gs.flags	= ia32_asm_read_gs();
		selector_ss.flags	= ia32_asm_read_ss();
		selector_tr.flags	= ia32_asm_read_tr();
		selector_ldtr.flags = ia32_asm_read_ldtr();


		ia32::read_segment_info(selector_cs,	&segment_cs);
		ia32::read_segment_info(selector_ds,	&segment_ds);
		ia32::read_segment_info(selector_es,	&segment_es);
		ia32::read_segment_info(selector_fs,	&segment_fs);
		ia32::read_segment_info(selector_gs,	&segment_gs);
		ia32::read_segment_info(selector_ss,	&segment_ss);
		ia32::read_segment_info(selector_tr,	&segment_tr);
		ia32::read_segment_info(selector_ldtr,	&segment_ldtr);

		segment_fs.base_address = (void*)ia32::asm_read_msr(ia32::msr::fs_base_t::msr_id);
		segment_gs.base_address = (void*)ia32::asm_read_msr(ia32::msr::gs_base_t::msr_id);

		vp->set_cr0_shadow(ia32::asm_read_cr0());
		vp->set_cr4_shadow(ia32::asm_read_cr4());

		vp->set_guest_cr0(ia32::asm_read_cr0());
		vp->set_guest_cr3(ia32::asm_read_cr3());
		vp->set_guest_cr4(ia32::asm_read_cr4());

		vp->set_guest_debugctl(ia32::asm_read_msr(ia32::msr::debugctl_t::msr_id));

		vp->set_guest_dr7(ia32::asm_read_dr7());

		vp->set_guest_rflags(ia32::asm_read_eflags());

		vp->set_guest_gdtr(ia32::asm_read_gdtr());
		vp->set_guest_idtr(ia32::asm_read_idtr());

		vp->set_guest_cs(segment_cs);
		vp->set_guest_ds(segment_ds);
		vp->set_guest_es(segment_es);
		vp->set_guest_fs(segment_fs);
		vp->set_guest_gs(segment_gs);
		vp->set_guest_ss(segment_ss);
		vp->set_guest_tr(segment_tr);
		vp->set_guest_ldtr(segment_ldtr);
		
		//EPT--------------------------------------


		//EPT--------------------------------------


		//io_bitmaps-------------------------------

		ia32::msr::vmx_procbased_ctls_t procbased_ctls;
		 
		procbased_ctls.flags = vp->get_processor_based_controls();

		procbased_ctls.use_io_bitmaps = true;

		vp->set_processor_based_controls(procbased_ctls.flags);

 
		vp->set_io_bitmap(0x60);//键盘
		vp->set_io_bitmap(0x64);//鼠标

	 

		//io_bitmaps-------------------------------


		return status_code::success;
	}


	status_code vmexit_handler::handle_interrupt(vcpu_t& vp) noexcept
	{


		return status_code::success;
	}

	status_code vmexit_handler::handle_exception_or_nmi(vcpu_t& vp) noexcept //待续
	{
		const auto interrupt = vp.get_interrupt_info();

		switch (interrupt.int_info.type)
		{
		case (uint32_t)ia32::vmx::interrupt_type::nmi:
		{
			switch (interrupt.int_info.vector)
			{
			case (uint32_t)ia32::exception_vector::nmi_interrupt:
			{
				break;
			}
			default:
				__debugbreak();
				break;
			}
			break;
		}
		default:
			break;
		}
		
		__debugbreak();

		return status_code::success;
	}


	status_code vmexit_handler::handle_external_interrupt(vcpu_t& vp) noexcept //待续
	{
		return status_code::success;
	}
	status_code vmexit_handler::handle_triple_fault(vcpu_t& vp) noexcept //ok
	{
		for (;;)
		{
			ia32_asm_pause();
			ia32_asm_halt();
		}
		return status_code::success;
	}

	status_code vmexit_handler::handle_init_signal(vcpu_t& vp) noexcept //?
	{
		return status_code::success;
	}
	status_code vmexit_handler::handle_startup_ipi(vcpu_t& vp) noexcept //?
	{
		return status_code::success;
	}
	status_code vmexit_handler::handle_io_smi(vcpu_t& vp) noexcept //?
	{
		return status_code::success;
	}
	status_code vmexit_handler::handle_smi(vcpu_t& vp) noexcept //?
	{
		return status_code::success;
	}
	status_code vmexit_handler::handle_interrupt_window(vcpu_t& vp) noexcept//待续
	{
		return status_code::success;
	}
	status_code vmexit_handler::handle_nmi_window(vcpu_t& vp) noexcept//待续
	{
		return status_code::success;
	}
	status_code vmexit_handler::handle_task_switch(vcpu_t& vp) noexcept //?
	{
		return status_code::success;
	}
	status_code vmexit_handler::handle_execute_cpuid(vcpu_t& vp) noexcept//ok
	{
		uint32_t cpu_info[4];

		ia32::asm_cpuid_ex(cpu_info, vp.m_context.eax, vp.m_context.ecx);

		vp.m_context.rax = cpu_info[0];
		vp.m_context.rbx = cpu_info[1];
		vp.m_context.rcx = cpu_info[2];
		vp.m_context.rdx = cpu_info[3];

		return status_code::success;
	}
	status_code vmexit_handler::handle_execute_getsec(vcpu_t& vp) noexcept//?
	{
		return status_code::success;
	}
	status_code vmexit_handler::handle_execute_hlt(vcpu_t& vp) noexcept//?
	{
		return status_code::success;
	}
	status_code vmexit_handler::handle_execute_invd(vcpu_t& vp) noexcept//ok
	{
		ia32::asm_wb_invd();

		return status_code::success;
	}
	status_code vmexit_handler::handle_execute_invlpg(vcpu_t& vp) noexcept//待续
	{
		
		return status_code::success;
	}
	status_code vmexit_handler::handle_execute_rdpmc(vcpu_t& vp) noexcept//?
	{

		return status_code::success;
	}
	status_code vmexit_handler::handle_execute_rdtsc(vcpu_t& vp) noexcept//ok
	{
		uint64_t tsc = ia32::asm_read_tsc();

		vp.m_context.rax = tsc & 0xffffffff;
		vp.m_context.rdx = tsc >> 32;
		return status_code::success;
	}
	status_code vmexit_handler::handle_execute_rsm_in_smm(vcpu_t& vp) noexcept//?
	{

		return status_code::success;
	}
	status_code vmexit_handler::handle_execute_vmcall(vcpu_t& vp) noexcept//待续
	{

		return status_code::success;
	}
	status_code vmexit_handler::handle_execute_vmclear(vcpu_t& vp) noexcept//待续
	{

		return status_code::success;
	}
	status_code vmexit_handler::handle_execute_vmlaunch(vcpu_t& vp) noexcept//待续
	{

		return status_code::success;
	}
	status_code vmexit_handler::handle_execute_vmptrld(vcpu_t& vp) noexcept//?
	{

		return status_code::success;
	}
	status_code vmexit_handler::handle_execute_vmptrst(vcpu_t& vp) noexcept//?
	{

		return status_code::success;
	}
	status_code vmexit_handler::handle_execute_vmread(vcpu_t& vp) noexcept//?
	{

		return status_code::success;
	}
	status_code vmexit_handler::handle_execute_vmresume(vcpu_t& vp) noexcept//?
	{

		return status_code::success;
	}
	status_code vmexit_handler::handle_execute_vmwrite(vcpu_t& vp) noexcept//?
	{

		return status_code::success;
	}
	status_code vmexit_handler::handle_execute_vmxoff(vcpu_t& vp) noexcept//?
	{

		return status_code::success;
	}
	status_code vmexit_handler::handle_execute_vmxon(vcpu_t& vp) noexcept//?
	{

		return status_code::success;
	}
	status_code vmexit_handler::handle_mov_cr(vcpu_t& vp) noexcept//?
	{

		return status_code::success;
	}
	status_code vmexit_handler::handle_mov_dr(vcpu_t& vp) noexcept//?
	{

		return status_code::success;
	}
	status_code vmexit_handler::handle_execute_io_instruction(vcpu_t& vp) noexcept//?
	{

		return status_code::success;
	}
	status_code vmexit_handler::handle_execute_rdmsr(vcpu_t& vp) noexcept//?
	{

		return status_code::success;
	}
	status_code vmexit_handler::handle_execute_wrmsr(vcpu_t& vp) noexcept//?
	{

		return status_code::success;
	}
	status_code vmexit_handler::handle_error_invalid_guest_state(vcpu_t& vp) noexcept//?
	{

		return status_code::success;
	}
	status_code vmexit_handler::handle_error_msr_load(vcpu_t& vp) noexcept//?
	{

		return status_code::success;
	}
	status_code vmexit_handler::handle_reserved_1(vcpu_t& vp) noexcept//?
	{

		return status_code::success;
	}
	status_code vmexit_handler::handle_execute_mwait(vcpu_t& vp) noexcept//?
	{

		return status_code::success;
	}
	status_code vmexit_handler::handle_monitor_trap_flag(vcpu_t& vp) noexcept//?
	{

		return status_code::success;
	}
	status_code vmexit_handler::handle_reserved_2(vcpu_t& vp) noexcept//?
	{

		return status_code::success;
	}
	status_code vmexit_handler::handle_execute_monitor(vcpu_t& vp) noexcept//?
	{

		return status_code::success;
	}
	status_code vmexit_handler::handle_execute_pause(vcpu_t& vp) noexcept//?
	{

		return status_code::success;
	}
	status_code vmexit_handler::handle_error_machine_check(vcpu_t& vp) noexcept//?
	{

		return status_code::success;
	}
	status_code vmexit_handler::handle_reserved_3(vcpu_t& vp) noexcept//?
	{

		return status_code::success;
	}
	status_code vmexit_handler::handle_tpr_below_threshold(vcpu_t& vp) noexcept//?
	{

		return status_code::success;
	}
	status_code vmexit_handler::handle_apic_access(vcpu_t& vp) noexcept//?
	{

		return status_code::success;
	}
	status_code vmexit_handler::handle_virtualized_eoi(vcpu_t& vp) noexcept//?
	{

		return status_code::success;
	}
	status_code vmexit_handler::handle_gdtr_idtr_access(vcpu_t& vp) noexcept//?
	{

		return status_code::success;
	}
	status_code vmexit_handler::handle_ldtr_tr_access(vcpu_t& vp) noexcept//?
	{

		return status_code::success;
	}
	status_code vmexit_handler::handle_ept_violation(vcpu_t& vp) noexcept//?
	{

		return status_code::success;
	}
	status_code vmexit_handler::handle_ept_misconfiguration(vcpu_t& vp) noexcept//?
	{

		return status_code::success;
	}
	status_code vmexit_handler::handle_execute_invept(vcpu_t& vp) noexcept//?
	{

		return status_code::success;
	}
	status_code vmexit_handler::handle_execute_rdtscp(vcpu_t& vp) noexcept//?
	{

		return status_code::success;
	}
	status_code vmexit_handler::handle_vmx_preemption_timer_expired(vcpu_t& vp) noexcept//?
	{

		return status_code::success;
	}
	status_code vmexit_handler::handle_execute_invvpid(vcpu_t& vp) noexcept//?
	{

		return status_code::success;
	}
	status_code vmexit_handler::handle_execute_wbinvd(vcpu_t& vp) noexcept//?
	{

		return status_code::success;
	}
	status_code vmexit_handler::handle_execute_xsetbv(vcpu_t& vp) noexcept//?
	{

		return status_code::success;
	}
	status_code vmexit_handler::handle_apic_write(vcpu_t& vp) noexcept//?
	{

		return status_code::success;
	}
	status_code vmexit_handler::handle_execute_rdrand(vcpu_t& vp) noexcept//?
	{

		return status_code::success;
	}
	status_code vmexit_handler::handle_execute_invpcid(vcpu_t& vp) noexcept//?
	{

		return status_code::success;
	}
	status_code vmexit_handler::handle_execute_vmfunc(vcpu_t& vp) noexcept//?
	{

		return status_code::success;
	}
	status_code vmexit_handler::handle_execute_encls(vcpu_t& vp) noexcept//?
	{

		return status_code::success;
	}
	status_code vmexit_handler::handle_execute_rdseed(vcpu_t& vp) noexcept//?
	{

		return status_code::success;
	}
	status_code vmexit_handler::handle_page_modification_log_full(vcpu_t& vp) noexcept//?
	{

		return status_code::success;
	}
	status_code vmexit_handler::handle_execute_xsaves(vcpu_t& vp) noexcept//?
	{

		return status_code::success;
	}
	status_code vmexit_handler::handle_execute_xrstors(vcpu_t& vp) noexcept//?
	{

		return status_code::success;
	}
};