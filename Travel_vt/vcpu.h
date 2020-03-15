#pragma once
#include "common.h"
#include "register_ia32.h"
#include "vmx.h"
#include "vmcs.h"



namespace   Travel_vt
{

	class vcpu_t 
	{
	public:

		
		uint16_t get_vpid()													noexcept;
		uint16_t set_vpid(uint16_t virtual_processor_identifier)			noexcept;

		uint64_t get_vmcs_link_pointer()									noexcept;
		uint64_t set_vmcs_link_pointer(uint64_t link_pointer)				noexcept;

		uint64_t get_pin_based_controls()									noexcept;
		uint64_t set_pin_based_controls(uint64_t controls)					noexcept;

		uint64_t get_processor_based_controls()								noexcept;
		uint64_t set_processor_based_controls(uint64_t controls)			noexcept;

		uint64_t get_processor_based_controls2()							noexcept;
		uint64_t set_processor_based_controls2(uint64_t controls)			noexcept;

		uint64_t get_vm_entry_controls()									noexcept;
		uint64_t set_vm_entry_controls(uint64_t controls)					noexcept;

		uint64_t get_vm_exit_controls()										noexcept;
		uint64_t set_vm_exit_controls(uint64_t controls)					noexcept;

		uint64_t get_msr_bitmap()											noexcept;
		uint64_t set_msr_bitmap(uint64_t msr_bitmap)						noexcept;

		uint64_t get_cr0_shadow()											noexcept;
		uint64_t set_cr0_shadow(uint64_t cr0)								noexcept;

		uint64_t get_cr4_shadow()											noexcept;
		uint64_t set_cr4_shadow(uint64_t cr0)								noexcept;

		uint64_t get_guest_cr0()											noexcept;
		uint64_t set_guest_cr0(uint64_t cr0)								noexcept;

		uint64_t get_guest_cr3()											noexcept;
		uint64_t set_guest_cr3(uint64_t cr0)								noexcept;

		uint64_t get_guest_cr4()											noexcept;
		uint64_t set_guest_cr4(uint64_t cr0)								noexcept;

		uint64_t get_guest_dr7()											noexcept;
		uint64_t set_guest_dr7(uint64_t dr7)								noexcept;

		uint64_t get_guest_rflags()											noexcept;
		uint64_t set_guest_rflags(uint64_t rflags)							noexcept;

		uint64_t get_guest_debugctl()										noexcept;
		uint64_t set_guest_debugctl(uint64_t debugctl)						noexcept;

		ia32::gdtr_t get_guest_gdtr()										noexcept;
		ia32::gdtr_t set_guest_gdtr(ia32::gdtr_t gdtr)						noexcept;
		
		ia32::idtr_t get_guest_idtr()										noexcept;
		ia32::idtr_t set_guest_idtr(ia32::idtr_t idtr)						noexcept;

		ia32::segment_t get_guest_cs()										noexcept;
		ia32::segment_t set_guest_cs(ia32::segment_t segment_cs)			noexcept;

		ia32::segment_t get_guest_ds()										noexcept;
		ia32::segment_t set_guest_ds(ia32::segment_t segment_ds)			noexcept;

		ia32::segment_t get_guest_es()										noexcept;
		ia32::segment_t set_guest_es(ia32::segment_t segment_es)			noexcept;

		ia32::segment_t get_guest_fs()										noexcept;
		ia32::segment_t set_guest_fs(ia32::segment_t segment_fs)			noexcept;

		ia32::segment_t get_guest_gs()										noexcept;
		ia32::segment_t set_guest_gs(ia32::segment_t segment_gs)			noexcept;

		ia32::segment_t get_guest_ss()										noexcept;
		ia32::segment_t set_guest_ss(ia32::segment_t segment_ss)			noexcept;

		ia32::segment_t get_guest_tr()										noexcept;
		ia32::segment_t set_guest_tr(ia32::segment_t segment_tr)			noexcept;

		ia32::segment_t get_guest_ldtr()									noexcept;
		ia32::segment_t set_guest_ldtr(ia32::segment_t segment_ldtr)		noexcept;


		uint64_t  vcpu_t::get_system_cr3() noexcept;

		status_code vcpu_t::load_vmxon() noexcept;

		status_code vcpu_t::load_vmcs() noexcept;
	
		status_code vcpu_t::setup_host()  noexcept;

		status_code vcpu_t::setup_guest() noexcept;
	


		status_code vcpu_t::vmx_enter() noexcept;



	private:

 		static void asm_entry_host()  noexcept;
 		static void asm_entry_guest() noexcept;

		void vcpu_t::entry_host()  noexcept;
		void vcpu_t::entry_guest() noexcept;

		struct stack_t
		{
			static constexpr auto size = 0x8000;

			struct machine_frame_t
			{
				uint64_t rip;
				uint64_t cs;
				uint64_t eflags;
				uint64_t rsp;
				uint64_t ss;
			};

			struct shadow_space_t
			{
				uint64_t dummy[4];
			};

			union
			{
				uint8_t data[size];

				struct
				{
					uint8_t         dummy[size
						- sizeof(shadow_space_t)
						- sizeof(machine_frame_t)
						- sizeof(uint64_t)];
					shadow_space_t  shadow_space;
					machine_frame_t machine_frame;
					uint64_t        unused;
				};
			};
		};


		ia32::vmx::vmcs_t           m_vmxon;
		ia32::vmx::vmcs_t           m_vmcs;
		ia32::vmx::msr_bitmap_t		m_msr_bitmap;

		stack_t m_stack;


	};

};


 