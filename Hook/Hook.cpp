#include"Hook.h"
// hook class
class FunctionHook {
private:
	void *Memory;
	DWORD MemorySize;
	ULONG_PTR HookAddress;
	bool bHooked;

	void operator=(const FunctionHook&) {};
	FunctionHook(const FunctionHook&) {}
public:
	FunctionHook(void *HookFunction, void *FunctionPointer, ULONG_PTR Address, DWORD OverWrite);
	~FunctionHook();
	bool Test();
};

FunctionHook::FunctionHook(void *HookFunction, void *FunctionPointer, ULONG_PTR Address, DWORD OverWrite) {
	bHooked = false;
	Memory = NULL;
	MemorySize = OverWrite;
	HookAddress = Address;

	if (MemorySize < 5) {
		return;
	}

	Memory = VirtualAlloc(NULL, MemorySize + 5, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (!Memory) {
		return;
	}

	DWORD old;
	if (!VirtualProtect((void *)HookAddress, MemorySize, PAGE_EXECUTE_READWRITE, &old)) {
		return;
	}

	*(ULONG_PTR *)FunctionPointer = (ULONG_PTR)Memory;
	memcpy_s(Memory, MemorySize, (void *)HookAddress, MemorySize);
	((BYTE *)(Memory))[MemorySize] = 0xE9;
	*(DWORD *)&((BYTE *)(Memory))[MemorySize + 1] = (HookAddress + MemorySize) - (ULONG_PTR)&((BYTE *)(Memory))[MemorySize] - 0x05;
	*(BYTE *)HookAddress = 0xE9;
	*(DWORD *)(HookAddress + 0x01) = (ULONG_PTR)HookFunction - HookAddress - 0x05;

	for (DWORD i = 5; i < MemorySize; i++) {
		*(BYTE *)(HookAddress + i) = 0x90;
	}

	if (VirtualProtect((void *)HookAddress, MemorySize, old, &old)) {
		bHooked = true;
	}
	return;
}

FunctionHook::~FunctionHook() {
	if (Memory) {
		DWORD old;
		if (VirtualProtect((void *)HookAddress, MemorySize, PAGE_EXECUTE_READWRITE, &old)) {
			memcpy_s((void *)HookAddress, MemorySize, (void *)Memory, MemorySize);
			VirtualFree(Memory, 0, MEM_RELEASE);
			Memory = NULL;
		}
	}
}

bool FunctionHook::Test() {
	return bHooked;
}

// hook class
// global
void Redirection(DWORD &dwEIP);

std::vector<FunctionHook*> HookList;
bool Hook(void *HookFunction, void *FunctionPointer, ULONG_PTR Address, DWORD OverWrite) {
	ULONG_PTR hookaddr = Address;
	Redirection(hookaddr);
	HookList.push_back(new FunctionHook(HookFunction, FunctionPointer, hookaddr, OverWrite));
	return HookList.back()->Test();
}

bool UnHook() {
	for (size_t i = 0; i < HookList.size(); i++) {
		delete HookList[i];
	}
	HookList.clear();
	return true;
}
// global
// decode
#define ZYCORE_STATIC_DEFINE
#define ZYDIS_STATIC_DEFINE
#include<inttypes.h>
#include<Zydis/Zydis.h>
#pragma comment(lib, "../Lib/Zydis.lib")
#pragma comment(lib, "../Lib/Zycore.lib")
ZydisDecoder zDecoder;
ZydisFormatter zFormatter;

bool DecodeInit() {
	ZydisDecoderInit(&zDecoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_ADDRESS_WIDTH_32);
	ZydisFormatterInit(&zFormatter, ZYDIS_FORMATTER_STYLE_INTEL);
	return true;
}

void Redirection(DWORD &dwEIP) {
	if (memcmp((void *)dwEIP, "\xFF\x25", 2) == 0) {
		dwEIP = *(DWORD *)(*(DWORD *)(dwEIP + 0x02));
		return Redirection(dwEIP);
	}
	if (memcmp((void *)dwEIP, "\x55\x8B\xEC\x5D\xFF\x25", 6) == 0) {
		dwEIP = *(DWORD *)(*(DWORD *)(dwEIP + 0x06));
		return Redirection(dwEIP);
	}
	if (memcmp((void *)dwEIP, "\x8B\xFF\x55\x8B\xEC\x5D\xFF\x25", 8) == 0) {
		dwEIP = *(DWORD *)(*(DWORD *)(dwEIP + 0x08));
		return Redirection(dwEIP);
	}
	if (memcmp((void *)dwEIP, "\x8B\xFF\x55\x8B\xEC\x5D\xE9", 7) == 0) {
		dwEIP = (dwEIP + 0x06) + *(signed long int *)(dwEIP + 0x07) + 0x05;
		return Redirection(dwEIP);
	}
	if (memcmp((void *)dwEIP, "\xEB", 1) == 0) {
		dwEIP += *(char *)(dwEIP + 0x01) + 0x02;
		return Redirection(dwEIP);
	}
	if (memcmp((void *)dwEIP, "\xE9", 1) == 0) {
		dwEIP += *(signed long int *)(dwEIP + 0x01) + 0x05;
		return Redirection(dwEIP);
	}
}

DWORD Decode(DWORD dwStartAddress) {
	static bool bDecode = false;

	if (!bDecode) {
		bDecode = DecodeInit();
	}

	ZydisDecodedInstruction zInst;
	DWORD dwEIP = dwStartAddress;

	Redirection(dwEIP);

	DWORD dwLength = 0;
	while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&zDecoder, (void *)dwEIP, 100, &zInst))) {
		if (ZYDIS_MNEMONIC_JB <= zInst.mnemonic && zInst.mnemonic <= ZYDIS_MNEMONIC_JZ) {
			return 0;
		}
		if (zInst.mnemonic == ZYDIS_MNEMONIC_CALL) {
			return 0;
		}
		dwEIP += zInst.length;
		dwLength += zInst.length;

		if (dwLength >= 5) {
			return dwLength;
		}
	}

	return 0;
}

// decode


CRITICAL_SECTION EnterHook::list_cs;

std::vector<DWORD> EnterHook::thread_id_list;
std::vector<int> EnterHook::hook_id_list;


bool EnterHook::Init() {
	memset(&list_cs, 0, sizeof(list_cs));
	InitializeCriticalSection(&list_cs);
	return true;
}

EnterHook::EnterHook(int Line) {
	thread_id = GetCurrentThreadId();
	hook_id = Line;
	is_entered = false;
}

EnterHook::~EnterHook() {
	if (is_entered) {
		Leave();
	}
}


bool EnterHook::Enter() {
	EnterCriticalSection(&list_cs);
	for (size_t i = 0; i < hook_id_list.size(); i++) {
		if (hook_id_list[i] == hook_id && thread_id_list[i] == thread_id) {
			LeaveCriticalSection(&list_cs);
			return false;
		}
	}
	hook_id_list.push_back(hook_id);
	thread_id_list.push_back(thread_id);
	is_entered = true;
	LeaveCriticalSection(&list_cs);
	return true;
}

bool EnterHook::Leave() {
	EnterCriticalSection(&list_cs);
	for (size_t i = 0; i < hook_id_list.size(); i++) {
		if (hook_id_list[i] == hook_id && thread_id_list[i] == thread_id) {
			hook_id_list.erase(hook_id_list.begin() + i);
			thread_id_list.erase(thread_id_list.begin() + i);
			LeaveCriticalSection(&list_cs);
			return true;
		}
	}
	LeaveCriticalSection(&list_cs);
	return false;
}