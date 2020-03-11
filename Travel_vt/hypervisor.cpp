#include "hypervisor.h"
#include "register_ia32.h"
#include "msr.h"

namespace hypervisor 
{

	static bool check_cpu_support() noexcept
	{
		ia32::cr4_t  cr4;
		ia32::cpuid_eax_01 cpuid_info;

		ia32::msr::vmx_basic_t vmx_basic;
		ia32::msr::vmx_ept_vpid_cap_t vmx_ept_vpid_cap;

		ia32::asm_cpuid(cpuid_info.cpu_info, 1);

		if (!cpuid_info.feature_information_ecx.virtual_machine_extensions)
		{
			return false;
		}
		
		cr4.flags =  ia32::asm_read_cr4();

		if (cr4.vmx_enable)
		{
			return false;
		}

		vmx_basic.flags = ia32::asm_read_msr(vmx_basic.msr_id);

		if (vmx_basic.vmcs_size_in_bytes > ia32::page_size || vmx_basic.memory_type != uint64_t(ia32::memory_type::write_back) || !vmx_basic.true_controls)
		{
			return false;
		}

		vmx_ept_vpid_cap.flags = ia32::asm_read_msr(vmx_ept_vpid_cap.msr_id);

		if (!vmx_ept_vpid_cap.page_walk_length_4  || !vmx_ept_vpid_cap.memory_type_write_back || !vmx_ept_vpid_cap.invept ||
			!vmx_ept_vpid_cap.invept_all_contexts || !vmx_ept_vpid_cap.execute_only_pages     || !vmx_ept_vpid_cap.pde_2mb_pages)
		{
			return false;
		}

		return true;
	}


	auto start() noexcept 
	{

		if (!check_cpu_support())
		{
			return status_code::not_supported;
		}

 
		return status_code::success;
	}

 



}