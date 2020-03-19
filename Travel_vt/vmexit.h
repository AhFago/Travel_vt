#pragma once
#include "vcpu.h"

namespace Travel_vt
{


	class vmexit_handler
	{
	public:
		vmexit_handler();
		~vmexit_handler();

		void * operator new(size_t size);
		status_code setup(vcpu_t* vp) noexcept;

	};

 

};