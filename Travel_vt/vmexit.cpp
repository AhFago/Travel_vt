#include "vmexit.h"
#include "msr.h"
namespace Travel_vt
{

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
		
		return status_code::success;
	}










};