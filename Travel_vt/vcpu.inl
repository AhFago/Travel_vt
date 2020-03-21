#include "vmx.h"
#include "msr.h"
#include "vmexit.h"

namespace Travel_vt 
{
	uint16_t vcpu_t::set_vpid(uint16_t virtual_processor_identifier) noexcept
	{
		return (uint16_t)ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::ctrl_virtual_processor_identifier, virtual_processor_identifier);
	}
	uint16_t vcpu_t::get_vpid() noexcept
	{
		uint16_t result;

		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::ctrl_virtual_processor_identifier, (uint64_t*)&result);

		return result;

	}

	uint64_t vcpu_t::set_vmcs_link_pointer(uint64_t link_pointer) noexcept
	{
		return (uint64_t)ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::guest_vmcs_link_pointer, link_pointer);
	}
	uint64_t vcpu_t::get_vmcs_link_pointer() noexcept
	{
		uint64_t result;

		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::guest_vmcs_link_pointer, &result);

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
		ia32::msr::vmx_true_ctls_t			  true_ctls;

		true_ctls.flags = ia32::asm_read_msr(ia32::msr::vmx_pinbased_ctls_t::msr_id + 0x0C);

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

		true_ctls.flags = ia32::asm_read_msr(ia32::msr::vmx_procbased_ctls_t::msr_id + 0x0C);

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

		true_ctls.flags = ia32::asm_read_msr(ia32::msr::vmx_procbased_ctls2_t::msr_id);

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

		true_ctls.flags = ia32::asm_read_msr(ia32::msr::vmx_entry_ctls_t::msr_id + 0x0C);

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
		ia32::msr::vmx_true_ctls_t  true_ctls;

		true_ctls.flags = ia32::asm_read_msr(ia32::msr::vmx_exit_ctls_t::msr_id + 0x0C);

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

	uint64_t vcpu_t::get_io_bitmap() noexcept
	{
		return (uint64_t)&m_io_bitmap;

	}
	uint64_t vcpu_t::set_io_bitmap(uint64_t io_bit) noexcept
	{
		m_io_bitmap.a[io_bit / sizeof(uint64_t)] |= 1 << (io_bit % (sizeof(uint64_t)));

		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::ctrl_io_bitmap_a_address, MmGetPhysicalAddress(&m_io_bitmap.a).QuadPart);
		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::ctrl_io_bitmap_b_address, MmGetPhysicalAddress(&m_io_bitmap.b).QuadPart);

		return 0;
	}

	uint64_t vcpu_t::get_cr0_shadow() noexcept
	{
		uint64_t result;

		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::ctrl_cr0_read_shadow, &result);

		return result;
	}
	uint64_t vcpu_t::set_cr0_shadow(uint64_t cr0) noexcept
	{
		return ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::ctrl_cr0_read_shadow, cr0);
	}

	uint64_t vcpu_t::get_cr4_shadow() noexcept
	{
		uint64_t result;

		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::ctrl_cr4_read_shadow, &result);

		return result;
	}
	uint64_t vcpu_t::set_cr4_shadow(uint64_t cr4) noexcept
	{
		return ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::ctrl_cr4_read_shadow, cr4);
	}

	uint64_t vcpu_t::get_guest_cr0() noexcept
	{
		uint64_t result;

		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::guest_cr0, &result);

		return result;
	}
	uint64_t vcpu_t::set_guest_cr0(uint64_t cr0) noexcept
	{
		return ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::guest_cr0, cr0);
	}

	uint64_t vcpu_t::get_guest_cr3() noexcept
	{
		uint64_t result;

		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::guest_cr3, &result);

		return result;
	}
	uint64_t vcpu_t::set_guest_cr3(uint64_t cr3) noexcept
	{
		return ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::guest_cr3, cr3);
	}

	uint64_t vcpu_t::get_guest_cr4() noexcept
	{
		uint64_t result;

		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::guest_cr4, &result);

		return result;
	}
	uint64_t vcpu_t::set_guest_cr4(uint64_t cr4) noexcept
	{
		return ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::guest_cr4, cr4);
	}

	uint64_t vcpu_t::get_guest_dr7() noexcept
	{
		uint64_t result;

		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::guest_dr7, &result);

		return result;
	}
	uint64_t vcpu_t::set_guest_dr7(uint64_t dr7) noexcept
	{
		return ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::guest_dr7, dr7);
	}

	uint64_t vcpu_t::get_guest_rflags() noexcept
	{
		uint64_t result;

		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::guest_rflags, &result);

		return result;
	}
	uint64_t vcpu_t::set_guest_rflags(uint64_t rflags) noexcept
	{
		return ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::guest_rflags, rflags);
	}

	uint64_t vcpu_t::get_guest_debugctl() noexcept
	{
		uint64_t result;

		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::guest_debugctl, &result);

		return result;
	}
	uint64_t vcpu_t::set_guest_debugctl(uint64_t debugctl) noexcept
	{
		return ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::guest_debugctl, debugctl);
	}

	ia32::gdtr_t vcpu_t::get_guest_gdtr() noexcept
	{
		ia32::gdtr_t gdtr;

		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::guest_gdtr_base, (uint64_t*)&gdtr.base_address);
		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::guest_gdtr_limit, (uint64_t*)&gdtr.limit);

		return gdtr;
	}
	ia32::gdtr_t vcpu_t::set_guest_gdtr(ia32::gdtr_t gdtr) noexcept
	{
		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::guest_gdtr_base, gdtr.base_address);
		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::guest_gdtr_limit, gdtr.limit);

		return gdtr;
	}

	ia32::idtr_t vcpu_t::get_guest_idtr() noexcept
	{
		ia32::idtr_t idtr;

		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::guest_idtr_base, (uint64_t*)&idtr.base_address);
		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::guest_idtr_limit, (uint64_t*)&idtr.limit);

		return idtr;
	}
	ia32::idtr_t vcpu_t::set_guest_idtr(ia32::idtr_t idtr) noexcept
	{
		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::guest_idtr_base, idtr.base_address);
		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::guest_idtr_limit, idtr.limit);

		return idtr;
	}

	ia32::segment_t vcpu_t::get_guest_cs() noexcept
	{
		ia32::segment_t segment_cs;

		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::guest_cs_base, (uint64_t*)&segment_cs.base_address);
		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::guest_cs_limit, (uint64_t*)&segment_cs.limit);
		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::guest_cs_selector, (uint64_t*)&segment_cs.selector);
		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::guest_cs_access_rights, (uint64_t*)&segment_cs.access);

		return segment_cs;
	}
	ia32::segment_t vcpu_t::set_guest_cs(ia32::segment_t segment_cs) noexcept
	{
		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::guest_cs_base, (uint64_t)segment_cs.base_address);
		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::guest_cs_limit, (uint64_t)segment_cs.limit);
		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::guest_cs_selector, (uint64_t)segment_cs.selector.flags);
		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::guest_cs_access_rights, (uint64_t)segment_cs.access.flags);

		return segment_cs;
	}

	ia32::segment_t vcpu_t::get_guest_ds() noexcept
	{
		ia32::segment_t segment_ds;

		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::guest_ds_base, (uint64_t*)&segment_ds.base_address);
		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::guest_ds_limit, (uint64_t*)&segment_ds.limit);
		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::guest_ds_selector, (uint64_t*)&segment_ds.selector);
		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::guest_ds_access_rights, (uint64_t*)&segment_ds.access);

		return segment_ds;
	}
	ia32::segment_t vcpu_t::set_guest_ds(ia32::segment_t segment_ds) noexcept
	{
		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::guest_ds_base, (uint64_t)segment_ds.base_address);
		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::guest_ds_limit, (uint64_t)segment_ds.limit);
		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::guest_ds_selector, (uint64_t)segment_ds.selector.flags);
		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::guest_ds_access_rights, (uint64_t)segment_ds.access.flags);

		return segment_ds;
	}

	ia32::segment_t vcpu_t::get_guest_es() noexcept
	{
		ia32::segment_t segment_es;

		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::guest_es_base, (uint64_t*)&segment_es.base_address);
		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::guest_es_limit, (uint64_t*)&segment_es.limit);
		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::guest_es_selector, (uint64_t*)&segment_es.selector);
		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::guest_es_access_rights, (uint64_t*)&segment_es.access);

		return segment_es;
	}
	ia32::segment_t vcpu_t::set_guest_es(ia32::segment_t segment_es) noexcept
	{
		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::guest_es_base, (uint64_t)segment_es.base_address);
		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::guest_es_limit, (uint64_t)segment_es.limit);
		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::guest_es_selector, (uint64_t)segment_es.selector.flags);
		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::guest_es_access_rights, (uint64_t)segment_es.access.flags);

		return segment_es;
	}

	ia32::segment_t vcpu_t::get_guest_fs() noexcept
	{
		ia32::segment_t segment_fs;

		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::guest_fs_base, (uint64_t*)&segment_fs.base_address);
		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::guest_fs_limit, (uint64_t*)&segment_fs.limit);
		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::guest_fs_selector, (uint64_t*)&segment_fs.selector);
		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::guest_fs_access_rights, (uint64_t*)&segment_fs.access);

		return segment_fs;
	}
	ia32::segment_t vcpu_t::set_guest_fs(ia32::segment_t segment_fs) noexcept
	{
		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::guest_fs_base, (uint64_t)segment_fs.base_address);
		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::guest_fs_limit, (uint64_t)segment_fs.limit);
		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::guest_fs_selector, (uint64_t)segment_fs.selector.flags);
		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::guest_fs_access_rights, (uint64_t)segment_fs.access.flags);

		return segment_fs;
	}

	ia32::segment_t vcpu_t::get_guest_gs() noexcept
	{
		ia32::segment_t segment_gs;

		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::guest_gs_base, (uint64_t*)&segment_gs.base_address);
		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::guest_gs_limit, (uint64_t*)&segment_gs.limit);
		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::guest_gs_selector, (uint64_t*)&segment_gs.selector);
		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::guest_gs_access_rights, (uint64_t*)&segment_gs.access);

		return segment_gs;
	}
	ia32::segment_t vcpu_t::set_guest_gs(ia32::segment_t segment_gs) noexcept
	{
		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::guest_gs_base, (uint64_t)segment_gs.base_address);
		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::guest_gs_limit, (uint64_t)segment_gs.limit);
		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::guest_gs_selector, (uint64_t)segment_gs.selector.flags);
		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::guest_gs_access_rights, (uint64_t)segment_gs.access.flags);

		return segment_gs;
	}

	ia32::segment_t vcpu_t::get_guest_ss() noexcept
	{
		ia32::segment_t segment_ss;

		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::guest_ss_base, (uint64_t*)&segment_ss.base_address);
		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::guest_ss_limit, (uint64_t*)&segment_ss.limit);
		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::guest_ss_selector, (uint64_t*)&segment_ss.selector);
		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::guest_ss_access_rights, (uint64_t*)&segment_ss.access);

		return segment_ss;
	}
	ia32::segment_t vcpu_t::set_guest_ss(ia32::segment_t segment_ss) noexcept
	{
		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::guest_ss_base, (uint64_t)segment_ss.base_address);
		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::guest_ss_limit, (uint64_t)segment_ss.limit);
		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::guest_ss_selector, (uint64_t)segment_ss.selector.flags);
		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::guest_ss_access_rights, (uint64_t)segment_ss.access.flags);

		return segment_ss;
	}

	ia32::segment_t vcpu_t::get_guest_tr() noexcept
	{
		ia32::segment_t segment_tr;

		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::guest_tr_base, (uint64_t*)&segment_tr.base_address);
		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::guest_tr_limit, (uint64_t*)&segment_tr.limit);
		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::guest_tr_selector, (uint64_t*)&segment_tr.selector);
		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::guest_tr_access_rights, (uint64_t*)&segment_tr.access);

		return segment_tr;
	}
	ia32::segment_t vcpu_t::set_guest_tr(ia32::segment_t segment_tr) noexcept
	{
		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::guest_tr_base, (uint64_t)segment_tr.base_address);
		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::guest_tr_limit, (uint64_t)segment_tr.limit);
		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::guest_tr_selector, (uint64_t)segment_tr.selector.flags);
		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::guest_tr_access_rights, (uint64_t)segment_tr.access.flags);

		return segment_tr;
	}

	ia32::segment_t vcpu_t::get_guest_ldtr() noexcept
	{
		ia32::segment_t segment_ldtr;

		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::guest_ldtr_base, (uint64_t*)&segment_ldtr.base_address);
		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::guest_ldtr_limit, (uint64_t*)&segment_ldtr.limit);
		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::guest_ldtr_selector, (uint64_t*)&segment_ldtr.selector);
		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::guest_ldtr_access_rights, (uint64_t*)&segment_ldtr.access);

		return segment_ldtr;
	}
	ia32::segment_t vcpu_t::set_guest_ldtr(ia32::segment_t segment_ldtr) noexcept
	{
		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::guest_ldtr_base, (uint64_t)segment_ldtr.base_address);
		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::guest_ldtr_limit, (uint64_t)segment_ldtr.limit);
		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::guest_ldtr_selector, (uint64_t)segment_ldtr.selector.flags);
		ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::guest_ldtr_access_rights, (uint64_t)segment_ldtr.access.flags);

		return segment_ldtr;
	}

	uint32_t vcpu_t::get_entry_instruction_length() noexcept
	{
		uint64_t result;
		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::ctrl_vmentry_instruction_length, &result);
		return result;
	}
	uint32_t vcpu_t::set_entry_instruction_length(uint32_t instruction_length) noexcept
	{
		return ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::ctrl_vmentry_instruction_length, instruction_length);;
	}

	uint32_t vcpu_t::get_entry_interruption_info() noexcept
	{
		uint64_t result;
		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::ctrl_vmentry_interruption_info, &result);
		return result;
	}
	uint32_t vcpu_t::set_entry_interruption_info(uint32_t  interrupt_info) noexcept
	{
		return ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::ctrl_vmentry_interruption_info, interrupt_info);;
	}

	uint32_t vcpu_t::get_entry_interruption_error_code() noexcept
	{
		uint64_t result;
		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::ctrl_vmentry_exception_error_code, &result);
		return result;
	}
	uint32_t vcpu_t::set_entry_interruption_error_code(uint32_t  error_code) noexcept
	{
		return ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::ctrl_vmentry_exception_error_code, error_code);;
	}

	//------------------------------------------------------------------------------------------------------------------------------------
	// exit state
	//------------------------------------------------------------------------------------------------------------------------------------
	uint32_t vcpu_t::exit_reason() noexcept
	{
		uint64_t result;
		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::vmexit_reason, &result);
		return result;
	}
	uint32_t vcpu_t::exit_instruction_error() noexcept
	{
		uint64_t result;
		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::vmexit_instruction_error, &result);
		return result;
	}
	uint32_t vcpu_t::exit_instruction_info() noexcept
	{
		uint64_t result;
		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::vmexit_instruction_info, &result);
		return result;
	}
	uint32_t vcpu_t::exit_instruction_length() noexcept
	{
		uint64_t result;
		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::vmexit_instruction_length, &result);
		return result;
	}
	uint32_t vcpu_t::exit_interruption_info() noexcept
	{
		uint64_t result;
		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::vmexit_interruption_info, &result);
		return result;
	}
	uint32_t vcpu_t::exit_interruption_error_code() noexcept
	{
		uint64_t result;
		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::vmexit_interruption_error_code, &result);
		return result;
	}
	uint32_t vcpu_t::exit_idt_vectoring_info() noexcept
	{
		uint64_t result;
		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::vmexit_idt_vectoring_info, &result);
		return result;
	}
	uint32_t vcpu_t::exit_idt_vectoring_error_code() noexcept
	{
		uint64_t result;
		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::vmexit_idt_vectoring_error_code, &result);
		return result;
	}
	uint32_t vcpu_t::exit_qualification() noexcept
	{
		uint64_t result;
		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::vmexit_qualification, &result);
		return result;
	}
	uint64_t vcpu_t::exit_guest_physical_address() noexcept
	{
		uint64_t result;
		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::vmexit_guest_physical_address, &result);
		return result;
	}
	uint64_t vcpu_t::exit_guest_linear_address() noexcept
	{
		uint64_t result;
		ia32::asm_vmx_vmread((uint64_t)ia32::vmx::vmcs_t::field::vmexit_guest_linear_address, &result);
		return result;
	}
	
	//------------------------------------------------------------------------------------------------------------------------------------
	// interrupts 
	//------------------------------------------------------------------------------------------------------------------------------------

	ia32::vmx::interrupt_t vcpu_t::get_interrupt_info() noexcept
	{
		ia32::vmx::interrupt_t result = { 0 };

		result.int_info.flags = exit_interruption_info();

		if (result.int_info.valid)
		{
			if (result.int_info.error_code_valid)
			{
				result.error_code.flags = exit_interruption_error_code();
			}

			result.rip_adjust = exit_instruction_length();
		}

		return result;
	}
	ia32::vmx::interrupt_t vcpu_t::get_idt_vectoring_info() noexcept
	{
		ia32::vmx::interrupt_t result = { 0 };

		result.int_info.flags = exit_idt_vectoring_info();

		if (result.int_info.valid)
		{
			if (result.int_info.error_code_valid)
			{
				result.error_code.flags = exit_idt_vectoring_error_code();
			}

			result.rip_adjust = exit_instruction_length();
		}

		return result;
	}
}