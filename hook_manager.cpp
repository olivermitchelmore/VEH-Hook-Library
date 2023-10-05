#include "hook_manager.hpp"

#include <vector>

// a struct to store information of hooked functions
struct hook_info_t {
	uintptr_t hook_address;
	uintptr_t hooked_address;
};

std::vector<hook_info_t> hook_info;

// registers our exception handler to catch our patched interrupts
void hook_manager::initialize() {
	AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)handler);
}

// makes a function trigger an interrupt, "hooking" it
void hook_manager::hook_function(uintptr_t hook_address, uintptr_t hooked_address) {
	hook_info.push_back(hook_info_t{ hook_address, hooked_address });

	DWORD old_protect;

	VirtualProtect((LPVOID)hook_address, 1, PAGE_EXECUTE_READWRITE, &old_protect);

	*(uint8_t*)hook_address = 0xCC;

	VirtualProtect((LPVOID)hook_address, 1, old_protect, &old_protect);
}

// exception handler callback
LONG hook_manager::handler(_EXCEPTION_POINTERS* exception_info) {
	for (hook_info_t& info : hook_info) {
		// does the instruction pointer match this function
		if (exception_info->ContextRecord->Eip == info.hook_address || 
			exception_info->ContextRecord->Eip - 1 == info.hook_address) {

			// change the instruction pointer to the address of our function
			exception_info->ContextRecord->Eip = info.hooked_address;

			// resume execution at the new instruction pointer
			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}

	// this wasn't an exception caused by us
	// continue down the stack of exception handlers
	return EXCEPTION_CONTINUE_SEARCH;
}
