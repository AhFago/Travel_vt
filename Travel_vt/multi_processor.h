#pragma once
#include "common.h"
#include "intrin.h"

namespace multi_cpu
{

	inline uint32_t cpu_count() noexcept
	{
		 return KeQueryActiveProcessorCountEx(NULL);
	}

	inline uint32_t cpu_index() noexcept
	{
		return KeGetCurrentProcessorNumberEx(NULL);
	}
	void sleep(uint32_t milliseconds) noexcept
	{
		LARGE_INTEGER interval;
		interval.QuadPart = -(10000ll * milliseconds);

		KeDelayExecutionThread(KernelMode, FALSE, &interval);
	}

}



