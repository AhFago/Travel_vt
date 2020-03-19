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


};