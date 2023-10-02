#pragma once

#include <Windows.h>

namespace hook_manager {
	void initialize();

	LONG handler(_EXCEPTION_POINTERS* info);

	void hook_function(uintptr_t hook_address, uintptr_t hooked_address);
}