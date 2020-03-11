#pragma once
#include "common.h"
#include "intrin.h"
#include "asm.h"
namespace ia32 
{
	

	static constexpr auto page_shift = 12;
	static constexpr auto page_size = 4096;
	static constexpr auto page_mask = page_size - 1;

	enum class memory_type : uint8_t
	{
		uncacheable = 0,
		write_combining = 1,
		write_through = 4,
		write_protected = 5,
		write_back = 6,
		invalid = 0xff
	};

	#pragma pack(push, 1)

	struct cpuid_eax_01
	{
		union
		{
			struct
			{
				uint32_t cpu_info[4];
			};

			struct
			{
				uint32_t eax;
				uint32_t ebx;
				uint32_t ecx;
				uint32_t edx;
			};

			struct
			{
				union
				{
					uint32_t flags;

					struct
					{
						uint32_t stepping_id : 4;
						uint32_t model : 4;
						uint32_t family_id : 4;
						uint32_t processor_type : 2;
						uint32_t reserved1 : 2;
						uint32_t extended_model_id : 4;
						uint32_t extended_family_id : 8;
						uint32_t reserved2 : 4;
					};
				} version_information;

				union
				{
					uint32_t flags;

					struct
					{
						uint32_t brand_index : 8;
						uint32_t clflush_line_size : 8;
						uint32_t max_addressable_ids : 8;
						uint32_t initial_apic_id : 8;
					};
				} additional_information;

				union
				{
					uint32_t flags;

					struct
					{
						uint32_t streaming_simd_extensions_3 : 1;
						uint32_t pclmulqdq_instruction : 1;
						uint32_t ds_area_64bit_layout : 1;
						uint32_t monitor_mwait_instruction : 1;
						uint32_t cpl_qualified_debug_store : 1;
						uint32_t virtual_machine_extensions : 1;
						uint32_t safer_mode_extensions : 1;
						uint32_t enhanced_intel_speedstep_technology : 1;
						uint32_t thermal_monitor_2 : 1;
						uint32_t supplemental_streaming_simd_extensions_3 : 1;
						uint32_t l1_context_id : 1;
						uint32_t silicon_debug : 1;
						uint32_t fma_extensions : 1;
						uint32_t cmpxchg16b_instruction : 1;
						uint32_t xtpr_update_control : 1;
						uint32_t perfmon_and_debug_capability : 1;
						uint32_t reserved1 : 1;
						uint32_t process_context_identifiers : 1;
						uint32_t direct_cache_access : 1;
						uint32_t sse41_support : 1;
						uint32_t sse42_support : 1;
						uint32_t x2apic_support : 1;
						uint32_t movbe_instruction : 1;
						uint32_t popcnt_instruction : 1;
						uint32_t tsc_deadline : 1;
						uint32_t aesni_instruction_extensions : 1;
						uint32_t xsave_xrstor_instruction : 1;
						uint32_t osx_save : 1;
						uint32_t avx_support : 1;
						uint32_t half_precision_conversion_instructions : 1;
						uint32_t rdrand_instruction : 1;
						uint32_t hypervisor_present : 1;
					};
				} feature_information_ecx;

				union
				{
					uint32_t flags;

					struct
					{
						uint32_t floating_point_unit_on_chip : 1;
						uint32_t virtual_8086_mode_enhancements : 1;
						uint32_t debugging_extensions : 1;
						uint32_t page_size_extension : 1;
						uint32_t timestamp_counter : 1;
						uint32_t rdmsr_wrmsr_instructions : 1;
						uint32_t physical_address_extension : 1;
						uint32_t machine_check_exception : 1;
						uint32_t cmpxchg8b : 1;
						uint32_t apic_on_chip : 1;
						uint32_t reserved1 : 1;
						uint32_t sysenter_sysexit_instructions : 1;
						uint32_t memory_type_range_registers : 1;
						uint32_t page_global_bit : 1;
						uint32_t machine_check_architecture : 1;
						uint32_t conditional_move_instructions : 1;
						uint32_t page_attribute_table : 1;
						uint32_t page_size_extension_36bit : 1;
						uint32_t processor_serial_number : 1;
						uint32_t clflush : 1;
						uint32_t reserved2 : 1;
						uint32_t debug_store : 1;
						uint32_t thermal_control_msrs_for_acpi : 1;
						uint32_t mmx_support : 1;
						uint32_t fxsave_fxrstor_instructions : 1;
						uint32_t sse_support : 1;
						uint32_t sse2_support : 1;
						uint32_t self_snoop : 1;
						uint32_t hyper_threading_technology : 1;
						uint32_t thermal_monitor : 1;
						uint32_t reserved3 : 1;
						uint32_t pending_break_enable : 1;
					};
				} feature_information_edx;
			};
		};
	};


	struct idt_access_t
	{
		union
		{
			uint16_t flags;

			struct
			{
				uint16_t ist_index : 3;
				uint16_t reserved : 5;
				uint16_t type : 4;
				uint16_t descriptor_type : 1;
				uint16_t descriptor_privilege_level : 2;
				uint16_t present : 1;
			};
		};
	};
	struct segment_selector_t
	{
		enum
		{
			table_gdt = 0,
			table_ldt = 1,
		};
		union
		{
			uint16_t flags;

			struct
			{
				uint16_t request_privilege_level : 2;
				uint16_t table : 1;
				uint16_t index : 13;
			};
		};
	};

	struct segment_access_t
	{
		//
		// System-Segment and Gate-Descriptor Types
		// (when descriptor_type == 0 (* descriptor_type_system *))
		//

		enum
		{
			type_reserved_0 = 0b0000,
			type_16b_tss_available = 0b0001,
			type_ldt = 0b0010,
			type_16b_tss_busy = 0b0011,
			type_16b_call_gate = 0b0100,
			type_task_gate = 0b0101,
			type_16b_interrupt_gate = 0b0110,
			type_16b_trap_gate = 0b0111,
			type_reserved_8 = 0b1000,
			type_32b_tss_available = 0b1001,
			type_reserved_10 = 0b1010,
			type_32b_tss_busy = 0b1011,
			type_32b_call_gate = 0b1100,
			type_reserved_13 = 0b1101,
			type_32b_interrupt_gate = 0b1110,
			type_32b_trap_gate = 0b1111,

			//
			// Difference between:
			//   type_16b_tss_available / type_16b_tss_busy
			//   type_32b_tss_available / type_32b_tss_busy
			//

			type_tss_busy_flag = 0b0010,
		};

		//
		// Code- and Data-Segment Types
		// (when descriptor_type == 1 (* descriptor_type_code_or_data *))
		//

		enum
		{
			type_read_only = 0b0000,
			type_read_only_accessed = 0b0001,
			type_read_write = 0b0010,
			type_read_write_accessed = 0b0011,
			type_read_only_expand_down = 0b0100,
			type_read_only_expand_down_accessed = 0b0101,
			type_read_write_expand_down = 0b0110,
			type_read_write_expand_down_accessed = 0b0111,
			type_execute_only = 0b1000,
			type_execute_only_accessed = 0b1001,
			type_execute_read = 0b1010,
			type_execute_read_accessed = 0b1011,
			type_execute_only_conforming = 0b1100,
			type_execute_only_conforming_accessed = 0b1101,
			type_execute_read_conforming = 0b1110,
			type_execute_read_conforming_accessed = 0b1111,
		};

		enum
		{
			descriptor_type_system = 0,
			descriptor_type_code_or_data = 1,
		};

		enum
		{
			granularity_byte = 0,
			granularity_4kb = 1,
		};

		union
		{
			uint16_t flags;

			struct
			{
				uint16_t type : 4;
				uint16_t descriptor_type : 1;
				uint16_t descriptor_privilege_level : 2;
				uint16_t present : 1;
				uint16_t limit_high : 4; // or reserved
				uint16_t available_bit : 1;
				uint16_t long_mode : 1;
				uint16_t default_big : 1;
				uint16_t granularity : 1;
			};

			struct
			{
				uint16_t type_accessed : 1;
				uint16_t type_write_enable : 1;
				uint16_t type_expansion_direction : 1;
				uint16_t type_code_segment : 1;
			};
		};
	};

	struct gdtr_t
	{
		uint16_t limit;
		uint64_t base_address;
	};
	struct idtr_t
	{
		uint16_t limit;
		uint64_t base_address;
	};


	struct gdt_descriptor_t
	{
		uint16_t  limit_low;
		uint16_t  base_address_low;
		uint8_t   base_address_middle;
		segment_access_t access;
		uint8_t   base_address_high;
		uint32_t  base_address_upper;
		uint32_t  must_be_zero;

		uint64_t get_base_address() const noexcept
		{
			uint64_t result = ((uint64_t(base_address_low)) | (uint64_t(base_address_middle) << 16) | (uint64_t(base_address_high) << 24));

			if (!access.descriptor_type)
			{
				result |= uint64_t(base_address_upper) << 32;
			}

			return result;
		}

		uint32_t get_limit() const noexcept
		{
			return (uint32_t(limit_low)) | (uint32_t(access.limit_high) << 16);
		}

	};
	struct ldt_descriptor_t
	{
		uint16_t  limit_low;
		uint16_t  base_address_low;
		uint8_t   base_address_middle;
		segment_access_t access;
		uint8_t   base_address_high;
		uint32_t  base_address_upper;
		uint32_t  must_be_zero;

		uint64_t get_base_address() const noexcept
		{
			uint64_t result = ((uint64_t(base_address_low)) | (uint64_t(base_address_middle) << 16) | (uint64_t(base_address_high) << 24));

			if (!access.descriptor_type)
			{
				result |= uint64_t(base_address_upper) << 32;
			}

			return result;
		}

		uint32_t get_limit() const noexcept
		{
			return (uint32_t(limit_low)) | (uint32_t(access.limit_high) << 16);
		}

	};
	struct idt_descriptor_t
	{
		uint16_t  base_address_low;
		segment_selector_t selector;
		idt_access_t access;
		uint16_t  base_address_middle;
		uint32_t  base_address_high;
		uint32_t  reserved;

		uint64_t get_base_address() const noexcept
		{
			return  ((uint64_t(base_address_low)) | (uint64_t(base_address_middle) << 16) | (uint64_t(base_address_high) << 32));
		}

	};

	struct segment_t
	{
		segment_selector_t	selector;
		segment_access_t	access;
		void *				base_address;
		uint32_t			limit;

	};

	struct cr0_t
	{
		union
		{
			uint64_t flags;

			struct
			{
				uint64_t protection_enable : 1;
				uint64_t monitor_coprocessor : 1;
				uint64_t emulate_fpu : 1;
				uint64_t task_switched : 1;
				uint64_t extension_type : 1;
				uint64_t numeric_error : 1;
				uint64_t reserved_1 : 10;
				uint64_t write_protect : 1;
				uint64_t reserved_2 : 1;
				uint64_t alignment_mask : 1;
				uint64_t reserved_3 : 10;
				uint64_t not_write_through : 1;
				uint64_t cache_disable : 1;
				uint64_t paging_enable : 1;
			};
		};
	};

	struct cr2_t
	{
		union
		{
			uint64_t flags;
			uint64_t linear_address;
		};
	};

	struct cr3_t
	{
		union
		{
			uint64_t flags;

			struct
			{
				uint64_t pcid : 12;
				uint64_t page_frame_number : 36;
				uint64_t reserved_1 : 12;
				uint64_t reserved_2 : 3;
				uint64_t pcid_invalidate : 1;
			};
		};
	};

	struct cr4_t
	{
		union
		{
			uint64_t flags;

			struct
			{
				uint64_t virtual_mode_extensions : 1;
				uint64_t protected_mode_virtual_interrupts : 1;
				uint64_t timestamp_disable : 1;
				uint64_t debugging_extensions : 1;
				uint64_t page_size_extensions : 1;
				uint64_t physical_address_extension : 1;
				uint64_t machine_check_enable : 1;
				uint64_t page_global_enable : 1;
				uint64_t performance_monitoring_counter_enable : 1;
				uint64_t os_fxsave_fxrstor_support : 1;
				uint64_t os_xmm_exception_support : 1;
				uint64_t usermode_instruction_prevention : 1;
				uint64_t reserved_1 : 1;
				uint64_t vmx_enable : 1;
				uint64_t smx_enable : 1;
				uint64_t reserved_2 : 1;
				uint64_t fsgsbase_enable : 1;
				uint64_t pcid_enable : 1;
				uint64_t os_xsave : 1;
				uint64_t reserved_3 : 1;
				uint64_t smep_enable : 1;
				uint64_t smap_enable : 1;
				uint64_t protection_key_enable : 1;
			};
		};
	};

	#pragma pack(pop)

	inline void asm_cpuid(uint32_t result[4], uint32_t eax) noexcept
	{
		__cpuid((int*)result, (int)eax);
	}


	inline uint64_t asm_read_cr0() noexcept
	{
		return __readcr0();
	}
	inline uint64_t asm_read_cr2() noexcept
	{
		return __readcr2();
	}
	inline uint64_t asm_read_cr3() noexcept
	{
		return __readcr3();
	}
	inline uint64_t asm_read_cr4() noexcept
	{
		return __readcr4();
	}

	inline void asm_write_cr0(uint64_t value) noexcept
	{
		__writecr0(value);
	}
	inline void asm_write_cr2(uint64_t value) noexcept
	{
		//__writecr2(value);
	}
	inline void asm_write_cr3(uint64_t value) noexcept
	{
		__writecr3(value);
	}
	inline void asm_write_cr4(uint64_t value) noexcept
	{
		__writecr4(value);
	}

	inline uint64_t asm_read_dr0() noexcept
	{
		return __readdr(0);
	}
	inline uint64_t asm_read_dr1() noexcept
	{
		return __readdr(1);
	}
	inline uint64_t asm_read_dr2() noexcept
	{
		return __readdr(2);
	}
	inline uint64_t asm_read_dr3() noexcept
	{
		return __readdr(3);
	}
	inline uint64_t asm_read_dr4() noexcept
	{
		return __readdr(4);
	}
	inline uint64_t asm_read_dr5() noexcept
	{
		return __readdr(5);
	}
	inline uint64_t asm_read_dr6() noexcept
	{
		return __readdr(6);
	}
	inline uint64_t asm_read_dr7() noexcept
	{
		return __readdr(7);
	}

	inline void asm_write_dr0(uint64_t value) noexcept
	{
		return __writedr(0, value);
	}
	inline void asm_write_dr1(uint64_t value) noexcept
	{
		return __writedr(1, value);
	}
	inline void asm_write_dr2(uint64_t value) noexcept
	{
		return __writedr(2, value);
	}
	inline void asm_write_dr3(uint64_t value) noexcept
	{
		return __writedr(3, value);
	}
	inline void asm_write_dr4(uint64_t value) noexcept
	{
		return __writedr(4, value);
	}
	inline void asm_write_dr5(uint64_t value) noexcept
	{
		return __writedr(5, value);
	}
	inline void asm_write_dr6(uint64_t value) noexcept
	{
		return __writedr(6, value);
	}
	inline void asm_write_dr7(uint64_t value) noexcept
	{
		return __writedr(7, value);
	}

	inline uint64_t asm_read_msr(uint32_t msr) noexcept
	{
		return __readmsr(msr);
	}
	inline void asm_write_msr(uint32_t msr, uint64_t value) noexcept
	{
		__writemsr(msr, value);
	}


	inline uint8_t asm_vmx_on(uint64_t* vmxon_pa) noexcept
	{
		return __vmx_on(vmxon_pa);
	}
	inline void asm_vmx_off(void) noexcept
	{
		__vmx_off();
	}
	inline uint8_t asm_vmx_vmlaunch(void) noexcept
	{
		return __vmx_vmlaunch();
	}
	inline uint8_t asm_vmx_vmresume(void) noexcept
	{
		return __vmx_vmresume();
	}
	inline uint8_t asm_vmx_vmclear(uint64_t* vmcs_pa) noexcept
	{
		return __vmx_vmclear(vmcs_pa);
	}
	inline uint8_t asm_vmx_vmread(uint64_t vmcs_field, uint64_t* value) noexcept
	{
		return __vmx_vmread(vmcs_field, value);
	}


	#pragma intrinsic(__vmx_vmwrite)

	inline uint8_t asm_vmx_vmwrite(uint64_t vmcs_field, uint64_t value) noexcept
	{
		return __vmx_vmwrite(vmcs_field, value);
	}

	inline void asm_vmx_vmptr_read(uint64_t* vmcs_pa) noexcept
	{
		__vmx_vmptrst(vmcs_pa);
	}

	inline uint8_t asm_vmx_vmptr_write(uint64_t* vmcs_pa) noexcept
	{
		return __vmx_vmptrld(vmcs_pa);
	}

	inline gdtr_t asm_read_gdtr() noexcept
	{ 
		gdtr_t gdt;

		ia32_asm_read_gdtr((void *)&gdt);

		return gdt;
	}

	inline idtr_t asm_read_idtr() noexcept
	{
		idtr_t idtr;

		ia32_asm_read_idtr((void*)&idtr);

		return idtr;
	}




	inline bool read_segment_info(segment_selector_t selector,segment_t * segment) noexcept
	{
		//const auto gdtr = ia32::asm_read_gdtr();

	 
		segment->limit			= ia32_asm_read_sl(selector.flags);
		segment->access.flags	= (uint16_t)(ia32_asm_read_ar(selector.flags) >> 8);
		segment->selector.flags = selector.flags;


		if (selector.table == segment_selector_t::table_gdt)
		{
			gdt_descriptor_t   gdt_table;

			const auto gdtr = ia32::asm_read_gdtr();

			gdt_table = *(gdt_descriptor_t*)(gdtr.base_address + selector.index * 8);

			segment->base_address = (void *)gdt_table.get_base_address();

		}
		if (selector.table == segment_selector_t::table_ldt)
		{
			uint64_t			ldt_base;
			ldt_descriptor_t    ldt_table;
			segment_selector_t  ldtr_selector;
			
			const auto gdtr = ia32::asm_read_gdtr();

			ldtr_selector.flags = ia32_asm_read_ldtr();

			ldt_base = *(uint64_t*)(gdtr.base_address + ldtr_selector.index * 8);

			ldt_table = *(ldt_descriptor_t*)(ldt_base + selector.index * 8);

			segment->base_address = (void*)ldt_table.get_base_address();

		}


		return true;
	}

// 
// 	void ia32_asm_read_gdtr(void* gdt) noexcept;
// 	void ia32_asm_write_gdtr(const void* gdt) noexcept;

// 	inline uint8_t asm_read_gdtr(void* gdt) noexcept;
// 	{
// 		//return ia32_asm_read_gdtr(gdt);
// 	}
}

