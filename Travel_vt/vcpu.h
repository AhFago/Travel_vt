#pragma once
#include "common.h"
#include "register_ia32.h"
#include "vmx.h"
#include "vmcs.h"
class vcpu_t 
{
public:
	uint64_t  vcpu_t::get_system_cr3() noexcept;

	status_code vcpu_t::load_vmxon() noexcept;

	status_code vcpu_t::load_vmcs() noexcept;
	
	status_code vcpu_t::setup_host() noexcept;

	status_code vcpu_t::vmx_enter() noexcept;

	

private:
	ia32::vmx::vmcs_t           vmxon;
	ia32::vmx::vmcs_t           vmcs;

};


 