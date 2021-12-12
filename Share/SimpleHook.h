#ifndef __SIMPLEHOOK_H__
#define __SIMPLEHOOK_H__

#include<Windows.h>

#ifndef SIMPLEHOOK_EXPORT
#pragma comment(lib, "../Share/SimpleHook.lib")
#define SIMPLEHOOK_IMPORT __declspec(dllimport)
#else
#define SIMPLEHOOK_IMPORT
#endif

namespace SimpleHook {
	bool SIMPLEHOOK_IMPORT Hook(void *HookFunction, void *FunctionPointer, ULONG_PTR Address, DWORD OverWrite = 0);
	bool SIMPLEHOOK_IMPORT UnHook();
}

// APIフック
#define SHook(api) \
{\
	if(!SimpleHook::Hook(api##_Hook, &_##api, (DWORD)##api)) {\
		MessageBoxW(NULL, L""#api, L"NG", MB_OK);\
	}\
}

// DLLを指定するAPIフック
#define SHookNT(dll, api) \
{\
	HMODULE hModule = GetModuleHandleW(L""#dll);\
	if (hModule) {\
		DWORD dwAddress = (DWORD)GetProcAddress(hModule, ""#api);\
		if (dwAddress) {\
			if(!SimpleHook::Hook(api##_Hook, &_##api, dwAddress)) {\
				MessageBoxW(NULL, L""#api, L"NG", MB_OK);\
			}\
		}\
	}\
}

// アドレスを指定するフック
#define SHookFunction(name, address) \
{\
	if(!SimpleHook::Hook(name##_Hook, &_##name, address)) {\
		MessageBoxW(NULL, L""#name, L"NG", MB_OK);\
	}\
}

#endif