#include "vcpu.h"
#include "vmx.h"
#include "msr.h"


namespace Travel_vt
{
	uint16_t vcpu_t::set_vpid(uint16_t virtual_processor_identifier) noexcept
	{
		return (uint16_t)ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::ctrl_virtual_processor_identifier, virtual_processor_identifier);
	}

	uint16_t vcpu_t::get_vpid() noexcept
	{
		uint16_t result;

		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::ctrl_virtual_processor_identifier,(uint64_t *)&result);

		return result;
	
	}

	uint64_t vcpu_t::set_vmcs_link_pointer(uint64_t link_pointer) noexcept
	{
		return (uint64_t)ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::guest_vmcs_link_pointer, link_pointer);
	}

	uint64_t vcpu_t::get_vmcs_link_pointer() noexcept
	{
		uint64_t result;

		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::guest_vmcs_link_pointer,&result);

		return result;
	}

 	uint64_t vcpu_t::get_pin_based_controls() noexcept
	{
		uint64_t result;

		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::ctrl_pin_based_vm_execution_controls, &result);

		return result;
	}
 
	uint64_t vcpu_t::set_pin_based_controls(uint64_t controls) noexcept
	{
		ia32::msr::vmx_true_ctls_t true_ctls;

		true_ctls.flags = ia32::asm_read_msr(controls + 0x0C);

		controls |= true_ctls.allowed_0_settings;
		controls &= true_ctls.allowed_1_settings;

		return (uint64_t)ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::ctrl_pin_based_vm_execution_controls, controls);
	}

	uint64_t vcpu_t::get_processor_based_controls() noexcept
	{
		uint64_t result;

		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::ctrl_processor_based_vm_execution_controls, &result);

		return result;
	}

	uint64_t vcpu_t::set_processor_based_controls(uint64_t controls) noexcept
	{
		ia32::msr::vmx_true_ctls_t true_ctls;

		true_ctls.flags = ia32::asm_read_msr(controls + 0x0C);

		controls |= true_ctls.allowed_0_settings;
		controls &= true_ctls.allowed_1_settings;

		return (uint64_t)ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::ctrl_processor_based_vm_execution_controls, controls);
	}

	uint64_t vcpu_t::get_processor_based_controls2() noexcept
	{
		uint64_t result;

		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::ctrl_secondary_processor_based_vm_execution_controls, &result);

		return result;
	}

	uint64_t vcpu_t::set_processor_based_controls2(uint64_t controls) noexcept
	{
		ia32::msr::vmx_true_ctls_t true_ctls;

		true_ctls.flags = ia32::asm_read_msr(controls);

		controls |= true_ctls.allowed_0_settings;
		controls &= true_ctls.allowed_1_settings;

		return (uint64_t)ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::ctrl_secondary_processor_based_vm_execution_controls, controls);
	}

	uint64_t vcpu_t::get_vm_entry_controls() noexcept
	{
		uint64_t result;

		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::ctrl_vmentry_controls, &result);

		return result;
	}

	uint64_t vcpu_t::set_vm_entry_controls(uint64_t controls) noexcept
	{
		ia32::msr::vmx_true_ctls_t true_ctls;

		true_ctls.flags = ia32::asm_read_msr(controls + 0x0C);

		controls |= true_ctls.allowed_0_settings;
		controls &= true_ctls.allowed_1_settings;

		return (uint64_t)ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::ctrl_vmentry_controls, controls);
	}

	uint64_t vcpu_t::get_vm_exit_controls() noexcept
	{
		uint64_t result;

		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::ctrl_vmexit_controls, &result);

		return result;
	}

	uint64_t vcpu_t::set_vm_exit_controls(uint64_t controls) noexcept
	{
		ia32::msr::vmx_true_ctls_t true_ctls;

		true_ctls.flags = ia32::asm_read_msr(controls + 0x0C);

		controls |= true_ctls.allowed_0_settings;
		controls &= true_ctls.allowed_1_settings;

		return (uint64_t)ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::ctrl_vmexit_controls, controls);
	}

	uint64_t vcpu_t::get_msr_bitmap() noexcept
	{
		return (uint64_t)&m_msr_bitmap;
	}

	uint64_t vcpu_t::set_msr_bitmap(uint64_t msr_bitmap) noexcept
	{
		return (uint64_t)ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::ctrl_msr_bitmap_address, MmGetPhysicalAddress((PVOID)msr_bitmap).QuadPart);
	}



	uint64_t vcpu_t::get_system_cr3() noexcept
	{
		struct _kprocess_t
		{
			DISPATCHER_HEADER Header;
			LIST_ENTRY ProfileListHead;
			ULONG_PTR DirectoryTableBase;
			LIST_ENTRY ThreadListHead;
		};

		_kprocess_t* system_process = reinterpret_cast<_kprocess_t*>(PsInitialSystemProcess);

		return system_process->DirectoryTableBase;
	}

	status_code vcpu_t::load_vmxon() noexcept
	{

		ia32::msr::vmx_cr0_fixed0_t cr0_fixed0;
		ia32::msr::vmx_cr0_fixed1_t cr0_fixed1;

		ia32::msr::vmx_cr4_fixed0_t cr4_fixed0;
		ia32::msr::vmx_cr4_fixed1_t cr4_fixed1;

		ia32::msr::vmx_basic_t		vmx_basic;

		ia32::asm_write_cr0(ia32::asm_read_cr0() | ia32::asm_read_msr(cr0_fixed0.msr_id) & ia32::asm_read_msr(cr0_fixed1.msr_id));
		ia32::asm_write_cr4(ia32::asm_read_cr4() | ia32::asm_read_msr(cr4_fixed0.msr_id) & ia32::asm_read_msr(cr4_fixed1.msr_id));

		vmx_basic.flags = ia32::asm_read_msr(vmx_basic.msr_id);
		m_vmxon.revision_id = vmx_basic.vmcs_revision_id;

		uint64_t vmxon_pa = MmGetPhysicalAddress(&m_vmxon).QuadPart;

		if ((status_code)ia32::asm_vmx_on(&vmxon_pa) != status_code::success)
		{
			return status_code::permission_denied;
		}

		//  vmx::invvpid_all_contexts();
		//  vmx::invept_all_contexts();

		return status_code::success;
	}


	status_code vcpu_t::load_vmcs() noexcept
	{
		ia32::msr::vmx_basic_t		vmx_basic;

		vmx_basic.flags = ia32::asm_read_msr(vmx_basic.msr_id);

		m_vmcs.revision_id = vmx_basic.vmcs_revision_id;

		uint64_t vmcs_pa = MmGetPhysicalAddress(&m_vmcs).QuadPart;

		if ((status_code)ia32::asm_vmx_vmclear(&vmcs_pa) != status_code::success || (status_code)ia32::asm_vmx_vmptr_write(&vmcs_pa) != status_code::success)
		{
			return status_code::permission_denied;
		}


		return status_code::success;
	}

	status_code vcpu_t::setup_host() noexcept
	{


		ia32::segment_t			 segment_cs;
		ia32::segment_t			 segment_ds;
		ia32::segment_t			 segment_es;
		ia32::segment_t			 segment_fs;
		ia32::segment_t			 segment_gs;
		ia32::segment_t			 segment_ss;
		ia32::segment_t			 segment_tr;

		ia32::segment_selector_t selector_cs;
		ia32::segment_selector_t selector_ds;
		ia32::segment_selector_t selector_es;
		ia32::segment_selector_t selector_fs;
		ia32::segment_selector_t selector_gs;
		ia32::segment_selector_t selector_ss;
		ia32::segment_selector_t selector_tr;

		selector_cs.flags = ia32_asm_read_cs();
		selector_ds.flags = ia32_asm_read_ds();
		selector_es.flags = ia32_asm_read_es();
		selector_fs.flags = ia32_asm_read_fs();
		selector_gs.flags = ia32_asm_read_gs();
		selector_ss.flags = ia32_asm_read_ss();
		selector_tr.flags = ia32_asm_read_tr();

		const auto gdtr = ia32::asm_read_gdtr();
		const auto idtr = ia32::asm_read_idtr();

		ia32::read_segment_info(selector_cs, &segment_cs);
		ia32::read_segment_info(selector_ds, &segment_ds);
		ia32::read_segment_info(selector_es, &segment_es);
		ia32::read_segment_info(selector_fs, &segment_fs);
		ia32::read_segment_info(selector_gs, &segment_gs);
		ia32::read_segment_info(selector_ss, &segment_ss);
		ia32::read_segment_info(selector_tr, &segment_tr);

		segment_fs.base_address = (void*)ia32::asm_read_msr(ia32::msr::fs_base_t::msr_id);
		segment_gs.base_address = (void*)ia32::asm_read_msr(ia32::msr::gs_base_t::msr_id);

		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::host_gdtr_base, gdtr.base_address);
		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::host_idtr_base, idtr.base_address);

		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::host_cs_selector, (uint64_t)(segment_cs.selector.index * 8));
		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::host_ds_selector, (uint64_t)(segment_ds.selector.index * 8));
		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::host_es_selector, (uint64_t)(segment_es.selector.index * 8));
		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::host_fs_selector, (uint64_t)(segment_fs.selector.index * 8));
		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::host_gs_selector, (uint64_t)(segment_gs.selector.index * 8));
		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::host_ss_selector, (uint64_t)(segment_ss.selector.index * 8));
		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::host_tr_selector, (uint64_t)(segment_tr.selector.index * 8));


		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::host_cr0, ia32::asm_read_cr0());
		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::host_cr4, ia32::asm_read_cr4());

		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::host_cr3, get_system_cr3());// PsInitialSystemProcess.DirectoryTableBase


		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::host_rsp, (uint64_t)(m_stack.data + m_stack.size));
		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::host_rip, (uint64_t)(&vcpu_t::asm_entry_host));

		
		return status_code::success;
	}

	status_code vcpu_t::setup_guest() noexcept
	{

		set_vpid(1);
		set_vmcs_link_pointer(~0ull);
		set_pin_based_controls(0);


		ia32::msr::vmx_exit_ctls_t	exit_ctls				= { 0 };
		ia32::msr::vmx_entry_ctls_t entry_ctls				= { 0 };
		ia32::msr::vmx_procbased_ctls_t  procbased_ctls		= { 0 };
		ia32::msr::vmx_procbased_ctls2_t procbased_ctls2	= { 0 };


		procbased_ctls.activate_secondary_controls			= true;
		procbased_ctls.use_msr_bitmaps						= true;

		procbased_ctls2.enable_vpid							= true;
		procbased_ctls2.enable_rdtscp						= true;
		procbased_ctls2.enable_xsaves						= true;
		procbased_ctls2.enable_invpcid						= true;

		entry_ctls.ia32e_mode_guest							= true;

		exit_ctls.ia32e_mode_host							= true;
		
		set_vm_exit_controls(exit_ctls.flags);
		set_vm_entry_controls(entry_ctls.flags);

		set_processor_based_controls(procbased_ctls.flags);
		set_processor_based_controls2(procbased_ctls2.flags);

		set_msr_bitmap((uint64_t)&m_msr_bitmap);


		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::guest_rsp, (uint64_t)(m_stack.data + m_stack.size));
		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::guest_rip, (uint64_t)(&vcpu_t::asm_entry_guest));

		return status_code::success;
	}
	
	status_code vcpu_t::vmx_enter() noexcept
	{
		status_code error_code;

		error_code = load_vmxon();

		if (error_code != status_code::success)
		{
			return error_code;
		}

		error_code = load_vmcs();

		if (error_code != status_code::success)
		{
			return error_code;
		}

		error_code = setup_host();

		if (error_code != status_code::success)
		{
			return error_code;
		}

		error_code = setup_guest();

		if (error_code != status_code::success)
		{
			return error_code;
		}
	

		return status_code::success;
	}


	void vcpu_t::entry_host() noexcept
	{

	}

	void vcpu_t::entry_guest() noexcept
	{

	}

};
