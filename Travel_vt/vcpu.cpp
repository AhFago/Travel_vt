#include "vcpu.h"
#include "vmx.h"
#include "msr.h"

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
	vmxon.revision_id = vmx_basic.vmcs_revision_id;

	uint64_t vmxon_pa = MmGetPhysicalAddress(&vmxon).QuadPart;

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

	vmcs.revision_id = vmx_basic.vmcs_revision_id;

	uint64_t vmcs_pa = MmGetPhysicalAddress(&vmcs).QuadPart;

	if ((status_code)ia32::asm_vmx_vmclear(&vmcs_pa) != status_code::success || (status_code)ia32::asm_vmx_vmptr_write(&vmcs_pa) != status_code::success)
	{
		return status_code::permission_denied;
	}
	

	return status_code::success;
}

status_code vcpu_t::setup_host() noexcept
{

	__debugbreak();

	const auto gdtr = ia32::asm_read_gdtr();
	const auto idtr = ia32::asm_read_idtr();

	ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::host_gdtr_base, gdtr.base_address);
	ia32::asm_vmx_vmwrite((uint64_t)ia32::vmx::vmcs_t::field::host_idtr_base, idtr.base_address);

// 	host_cs(segment_t{ gdtr, read<cs_t>() });
// 	host_ds(segment_t{ gdtr, read<ds_t>() });
// 	host_es(segment_t{ gdtr, read<es_t>() });
// 	host_fs(segment_t{ gdtr, read<fs_t>() });
// 	host_gs(segment_t{ gdtr, read<gs_t>() });
// 	host_ss(segment_t{ gdtr, read<ss_t>() });
// 	host_tr(segment_t{ gdtr, read<tr_t>() });



	
	ia32::segment_t segment;
	ia32::segment_selector_t selector;

	selector.flags = ia32_asm_read_cs();
	ia32::read_segment_info(selector, &segment);

	selector.flags = ia32_asm_read_ds();
	ia32::read_segment_info(selector, &segment);

	selector.flags = ia32_asm_read_es();
	ia32::read_segment_info(selector, &segment);

	selector.flags = ia32_asm_read_ss();
	ia32::read_segment_info(selector, &segment);

	selector.flags = ia32_asm_read_tr();
	ia32::read_segment_info(selector, &segment);


	selector.flags = ia32_asm_read_fs();//???
	ia32::read_segment_info(selector, &segment);

	selector.flags = ia32_asm_read_gs();
	ia32::read_segment_info(selector, &segment);

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
 
	return status_code::success;
}
