#pragma once
#include "common.h"
#include "vcpu.h"

namespace Travel_vt
{

	class vmexit_handler
	{
	public:
		status_code setup(vcpu_t * vp) noexcept;

	};
};