#ifndef __HOOK_H__
#define __HOOK_H__

#include<Windows.h>
#include<vector>

#define TestHookMacro(api) Hook(api##_Hook, &_##api, (DWORD)##api, Decode((DWORD)##api))
#define TestHook(api) if(!TestHookMacro(api)) MessageBoxW(NULL, L""#api, L"NG", MB_OK)
#define TestHookNT(dll, api) \
{\
	HMODULE hModule = GetModuleHandleW(L""#dll);\
	if (hModule) {\
		DWORD dwAddress = (DWORD)GetProcAddress(hModule, ""#api);\
		if (dwAddress) {\
			if(!Hook(api##_Hook, &_##api, dwAddress, Decode(dwAddress))) {\
				MessageBoxW(NULL, L""#api, L"NG", MB_OK);\
			}\
		}\
	}\
}
#define TestHookFunction(name, address) \
{\
	if(!Hook(name##_Hook, &_##name, address, Decode(address))) {\
		MessageBoxW(NULL, L""#name, L"NG", MB_OK);\
	}\
}


bool Hook(void *HookFunction, void *FunctionPointer, ULONG_PTR Address, DWORD OverWrite);
bool UnHook();

DWORD Decode(DWORD dwStartAddress);


class EnterHook {
private:
	static CRITICAL_SECTION list_cs;

	static std::vector<DWORD> thread_id_list;
	static std::vector<int> hook_id_list;
	DWORD thread_id;
	int hook_id;
	bool is_entered;
	bool Leave();
public:
	EnterHook(int Line);
	~EnterHook();
	bool Enter();
	static bool Init();
};

#endif