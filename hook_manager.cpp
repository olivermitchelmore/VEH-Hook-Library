#include "hook_manager.hpp"

#include <vector>

struct hook_info_t {
	uintptr_t hook_address;
	uintptr_t hooked_address;
};

std::vector<hook_info_t> hook_info;

void hook_manager::initialize() {
	AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)handler);
}

void hook_manager::hook_function(uintptr_t hook_address, uintptr_t hooked_address) {
	hook_info.push_back(hook_info_t{ hook_address, hooked_address });

	DWORD old_protect;

	VirtualProtect((LPVOID)hook_address, 1, PAGE_EXECUTE_READWRITE, &old_protect);

	*(uint8_t*)hook_address = 0xCC;

	VirtualProtect((LPVOID)hook_address, 1, old_protect, &old_protect);
}

LONG hook_manager::handler(_EXCEPTION_POINTERS* exception_info) {
	for (hook_info_t& info : hook_info) {
		if (exception_info->ContextRecord->Eip == info.hook_address || 
			exception_info->ContextRecord->Eip - 1 == info.hook_address) {

			exception_info->ContextRecord->Eip = info.hooked_address;

			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}
	return EXCEPTION_CONTINUE_SEARCH;
}