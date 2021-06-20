#include"../Lib/Hook.h"
#pragma comment(lib, "../Lib/Hook.lib")
#include"../Lib/Rosemary.h"
#pragma comment(lib, "../Lib/Rose.lib")
#include<iphlpapi.h>
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Netapi32.lib")
#pragma comment(lib, "ws2_32.lib")
#include<string>

// debug
std::wstring BYTEtoString(BYTE b) {
	std::wstring wb;
	WCHAR high = (b >> 4) & 0x0F;
	WCHAR low = b & 0x0F;

	high += (high <= 0x09) ? 0x30 : 0x37;
	low += (low <= 0x09) ? 0x30 : 0x37;

	wb.push_back(high);
	wb.push_back(low);

	return wb;
}

std::wstring WORDtoString(WORD w) {
	std::wstring ww;

	ww += BYTEtoString((w >> 8) & 0xFF);
	ww += BYTEtoString(w & 0xFF);

	return ww;
}

std::wstring DWORDtoString(DWORD dw) {
	std::wstring wdw;

	wdw += BYTEtoString((dw >> 24) & 0xFF);
	wdw += BYTEtoString((dw >> 16) & 0xFF);
	wdw += BYTEtoString((dw >> 8) & 0xFF);
	wdw += BYTEtoString(dw & 0xFF);

	return wdw;
}

#define DEBUG(msg) \
{\
std::wstring wmsg = L"[Maple]";\
wmsg += msg;\
OutputDebugStringW(wmsg.c_str());\
}
//


// CRCBypass
std::vector<MEMORY_BASIC_INFORMATION> vSection;
std::vector<void*> vBackup;
ULONG_PTR uMSCRC_Ret = 0;

DWORD __stdcall GetBackup(DWORD dwAddress) {
	for (size_t i = 0; i < vBackup.size(); i++) {
		if ((DWORD)vSection[i].BaseAddress <= dwAddress && dwAddress <= ((DWORD)vSection[i].BaseAddress + vSection[i].RegionSize)) {
			return (DWORD)&((BYTE *)vBackup[i])[dwAddress - (DWORD)vSection[i].BaseAddress];
		}
	}

	return dwAddress;
}

void __declspec(naked) CRCBypass() {
	__asm {
		mov ecx, [ecx]
		push eax

		push edx
		push ecx
		push ebx
		push esi
		push edi

		lea eax, [esi + edx * 0x4]
		push eax
		call GetBackup

		pop edi
		pop esi
		pop ebx
		pop ecx
		pop edx


		xor ecx, [eax]

		pop eax
		jmp uMSCRC_Ret
	}
}

bool MemoryPatch() {
	Rosemary r;
	r.Backup(vSection, vBackup);

	for (size_t i = 0; i < vSection.size(); i++) {
		DEBUG(L"vSection = " + DWORDtoString((ULONG_PTR)vSection[i].BaseAddress) + L" - " + DWORDtoString((ULONG_PTR)vSection[i].BaseAddress + vSection[i].RegionSize) + L", Backup = " + DWORDtoString((ULONG_PTR)vBackup[i]));
	}

	// 0x00B5D2B0 v186
	ULONG_PTR uMSCRC = r.Scan(L"8B 4D 18 8B 55 E0 8B 75 08 8B 09 33 0C 96 81 E1 FF 00 00 00 33 04 8D");
	if (uMSCRC) {
		uMSCRC += 0x09;
		uMSCRC_Ret = uMSCRC + 0x05;
		r.Hook(uMSCRC, CRCBypass);
	}
	DEBUG(L"uMSCRC = " + DWORDtoString(uMSCRC));


	// 0x00BC8D39 v186
	ULONG_PTR uHackShield_Init =  r.Scan(L"55 8B EC 81 EC ?? ?? ?? ?? 53 8B D9 8D 4B ?? 89 4D ?? E8 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0");
	if (uHackShield_Init) {
		r.Patch(uHackShield_Init, L"31 C0 C2 04 00");
	}

	// 0x00BCF256 v186
	ULONG_PTR uEHSvc_Loader_1 = r.Scan(L"55 8B EC 81 EC ?? ?? ?? ?? 57 C7 45 ?? 00 00 00 00 C6 85 ?? ?? ?? ?? 00 B9 ?? ?? ?? ?? 33 C0 8D BD ?? ?? ?? ?? F3 AB");
	if (uEHSvc_Loader_1) {
		r.Patch(uEHSvc_Loader_1, L"31 C0 C2 10 03");
	}

	// 0x00BCE382 v186
	ULONG_PTR uEHSvc_Loader_2 = r.Scan(L"55 8B EC 81 EC ?? ?? ?? ?? 57 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 C6 85 ?? ?? ?? ?? 00 B9 ?? ?? ?? ?? 33 C0 8D BD ?? ?? ?? ?? F3 AB");
	if (uEHSvc_Loader_2) {
		r.Patch(uEHSvc_Loader_2, L"31 C0 C2 18 00");
	}

	// 0x00BC91FC v186
	ULONG_PTR uHeartBeat = r.Scan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 81 EC ?? ?? ?? ?? 56 BE ?? ?? ?? ?? 56 8D 85 ?? ?? ?? ?? 6A 00 50 E8");
	if (uHeartBeat) {
		r.Patch(uHeartBeat, L"31 C0 C2 04 00");
	}

	// 0x00BC93BB v186
	ULONG_PTR uMKD25tray = r.Scan(L"55 8B EC 83 EC ?? 56 8B F1 57 8D 7E ?? 8B CF E8 ?? ?? ?? ?? 85 C0 0F 85");
	if (uMKD25tray) {
		r.Patch(uMKD25tray, L"31 C0 C3");
	}

	// 0x00BC938F v186
	ULONG_PTR uAutoup = r.Scan(L"56 8D 71 ?? 8B CE E8 ?? ?? ?? ?? 85 C0 74 ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15");
	if (uAutoup) {
		r.Patch(uAutoup, L"31 C0 C3");
	}

	// 0x00BC92F6 v186
	ULONG_PTR uASPLunchr = r.Scan(L"55 8B EC 83 EC ?? 56 8B F1 57 8D 7E ?? 8B CF E8 ?? ?? ?? ?? 85 C0 75 ?? 68 ?? ?? ?? ?? FF 15");
	if (uASPLunchr) {
		r.Patch(uASPLunchr, L"31 C0 C3");
	}

	// 0x00BC8A7A v186
	ULONG_PTR uHSUpdate = r.Scan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 81 EC ?? ?? ?? ?? 56 83 C1 ?? 57 89 4D ?? E8 ?? ?? ?? ?? 85 C0 0F 85");
	if (!uHSUpdate) {
		// 0x00C10331 v187
		uHSUpdate = r.Scan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 81 EC ?? ?? ?? ?? 53 56 83 C1 ?? 57 89 4D ?? E8 ?? ?? ?? ?? 85 C0 0F 85");
	}
	if (uHSUpdate) {
		r.Patch(uHSUpdate, L"31 C0 C3");
	}

	// 0x00B60EE5 v186
	ULONG_PTR uWindowMode = r.Scan(L"C7 45 ?? 10 00 00 00 6A 03 FF 75 ?? 8D 4D ?? E8");
	if (uWindowMode) {
		r.Patch(uWindowMode, L"C7 45 DC 00 00 00 00");
	}
	else {
		// 0x00BA70CF v187
		uWindowMode = r.Scan(L"8B 45 ?? 89 45 ?? 6A 03 FF 75");
		if (uWindowMode) {
			r.Patch(uWindowMode, L"31 C0 90");
		}
	}

	// 0x0084268E v186
	ULONG_PTR uLauncher = r.Scan(L"55 8B EC 83 EC ?? 53 56 57 33 DB 53 FF 15 ?? ?? ?? ?? 8B 7D ?? 89 3D ?? ?? ?? ?? 8B 87 ?? ?? ?? ?? 6A");
	if (uLauncher) {
		r.Patch(uLauncher, L"B8 01 00 00 00 C3");
	}

	DEBUG(L"uHackShield_Init = " + DWORDtoString(uHackShield_Init));
	DEBUG(L"uEHSvc_Loader_1  = " + DWORDtoString(uEHSvc_Loader_1));
	DEBUG(L"uEHSvc_Loader_2 = " + DWORDtoString(uEHSvc_Loader_2));
	DEBUG(L"uHeartBeat = " + DWORDtoString(uHeartBeat));
	DEBUG(L"uMKD25tray = " + DWORDtoString(uMKD25tray));
	DEBUG(L"uAutoup  = " + DWORDtoString(uAutoup));
	DEBUG(L"uASPLunchr = " + DWORDtoString(uASPLunchr));
	DEBUG(L"uHSUpdate = " + DWORDtoString(uHSUpdate));
	DEBUG(L"uWindowMode = " + DWORDtoString(uWindowMode));
	DEBUG(L"uLauncher = " + DWORDtoString(uLauncher));

	return true;
}


// API Hook
HANDLE(WINAPI *_CreateMutexExW)(LPSECURITY_ATTRIBUTES, LPCWSTR, DWORD, DWORD) = NULL;
HANDLE WINAPI CreateMutexExW_Hook(LPSECURITY_ATTRIBUTES lpMutexAttributes, LPCWSTR lpName, DWORD dwFlags, DWORD dwDesiredAccess) {
	EnterHook e(__LINE__);
	if (e.Enter()) {
		if (lpName) {
			if (wcscmp(lpName, L"WvsClientMtx") == 0) {
				HANDLE hRet = _CreateMutexExW(lpMutexAttributes, lpName, dwFlags, dwDesiredAccess);
				HANDLE hDuplicatedMutex = NULL;
				if (DuplicateHandle(GetCurrentProcess(), hRet, 0, &hDuplicatedMutex, 0, FALSE, DUPLICATE_CLOSE_SOURCE)) {
					CloseHandle(hDuplicatedMutex);
				}
				DEBUG(L"Mutex Blocked");
				if (vBackup.size() == 0) {
					MemoryPatch();
				}
				return hRet;
			}
		}
	}
	return _CreateMutexExW(lpMutexAttributes, lpName, dwFlags, dwDesiredAccess);
}

DWORD dwPServer = 0x0100007F; // 127.0.0.1
int (PASCAL *_connect)(SOCKET, sockaddr_in *, int) = NULL;
int PASCAL connect_Hook(SOCKET s, sockaddr_in *name, int namelen) {
	WORD wPort = ntohs(name->sin_port);
	std::wstring server = std::to_wstring(name->sin_addr.S_un.S_un_b.s_b1) + L"." + std::to_wstring(name->sin_addr.S_un.S_un_b.s_b2) + L"." + std::to_wstring(name->sin_addr.S_un.S_un_b.s_b3) + L"." + std::to_wstring(name->sin_addr.S_un.S_un_b.s_b4) + L":" + std::to_wstring(wPort);
	
	*(DWORD *)&name->sin_addr.S_un = dwPServer;

	std::wstring pserver = std::to_wstring(name->sin_addr.S_un.S_un_b.s_b1) + L"." + std::to_wstring(name->sin_addr.S_un.S_un_b.s_b2) + L"." + std::to_wstring(name->sin_addr.S_un.S_un_b.s_b3) + L"." + std::to_wstring(name->sin_addr.S_un.S_un_b.s_b4) + L":" + std::to_wstring(wPort);

	DEBUG(L"[connect][" + server + L" -> " + pserver + L"]");

	return _connect(s, name, namelen);
}

bool SetServerIP() {
	FILE *fp = NULL;
	if (fopen_s(&fp, "Emu.txt", "r")) {
		return false;
	}
	BYTE *ip_bytes = (BYTE *)&dwPServer;

	fscanf_s(fp, "%d.%d.%d.%d", &ip_bytes[0], &ip_bytes[1], &ip_bytes[2], &ip_bytes[3]);
	fclose(fp);

	return true;
}

void RireSaba() {
	EnterHook::Init();

	SetServerIP();

	// ip redirect
	TestHook(connect);
	// remove mutex and enable memory edit
	TestHook(CreateMutexExW);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
	if (fdwReason == DLL_PROCESS_ATTACH) {
		DisableThreadLibraryCalls(hinstDLL);
		RireSaba();
	}
	return TRUE;
}