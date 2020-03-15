#include "vmexit.h"

namespace Travel_vt
{

	status_code vmexit_handler::setup(vcpu_t * vp) noexcept
	{
	

		ia32::asm_read_cr0();



		return status_code::success;
	}










};