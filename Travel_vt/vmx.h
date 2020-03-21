#pragma once
#include "common.h"
#include "register_ia32.h"


namespace ia32::vmx
{
	struct alignas(page_size) msr_bitmap_t
	{
		static constexpr uint32_t msr_id_low_min  = 0x00000000;
		static constexpr uint32_t msr_id_low_max  = 0x00001fff;
		static constexpr uint32_t msr_id_high_min = 0xc0000000;
		static constexpr uint32_t msr_id_high_max = 0xc0001fff;

		union
		{
			struct
			{
				uint8_t rdmsr_low[page_size / 4];
				uint8_t rdmsr_high[page_size / 4];
				uint8_t wrmsr_low[page_size / 4];
				uint8_t wrmsr_high[page_size / 4];
			};

			uint8_t data[page_size];
		};
	};

	struct alignas(page_size) io_bitmap_t
	{
		static constexpr uint32_t io_bitmap_a_min = 0x00000000;
		static constexpr uint32_t io_bitmap_a_max = 0x00007fff;
		static constexpr uint32_t io_bitmap_b_min = 0x00008000;
		static constexpr uint32_t io_bitmap_b_max = 0x0000ffff;

		union
		{
			struct
			{
				uint8_t a[page_size];
				uint8_t b[page_size];
			};

			uint8_t data[2 * page_size];
		};
	};



	enum class interrupt_type : uint32_t
	{
		external = 0,
		reserved = 1,
		nmi = 2,
		hardware_exception = 3,
		software = 4,
		privileged_exception = 5,
		software_exception = 6,
		other_event = 7,
	};

	struct interrupt_info_t
	{
		union
		{
			uint32_t flags;

			struct
			{
				uint32_t vector : 8;
				uint32_t type : 3;
				uint32_t error_code_valid : 1;
				uint32_t nmi_unblocking : 1; // Used only in VMEXIT interruption-information,
											 // otherwise reserved.
				uint32_t reserved : 18;
				uint32_t valid : 1;
			};
		};
	};

	struct interrupt_t
	{
		interrupt_info_t		int_info;
		exception_error_code_t	error_code;
		int						rip_adjust;
	};


	struct interruptibility_state_t
	{
		union
		{
			uint32_t flags;

			struct
			{
				uint32_t blocking_by_sti : 1;
				uint32_t blocking_by_mov_ss : 1;
				uint32_t blocking_by_smi : 1;
				uint32_t blocking_by_nmi : 1;
				uint32_t enclave_interruption : 1;
				uint32_t reserved : 27;
			};
		};
	};

	constexpr inline const char* to_string(interrupt_type value) noexcept
	{
		switch (value)
		{
		case interrupt_type::external: return "external";
		case interrupt_type::reserved: return "reserved";
		case interrupt_type::nmi: return "nmi";
		case interrupt_type::hardware_exception: return "hardware_exception";
		case interrupt_type::software: return "software";
		case interrupt_type::privileged_exception: return "privileged_exception";
		case interrupt_type::software_exception: return "software_exception";
		case interrupt_type::other_event: return "other_event";
		}

		return "";
	}


};