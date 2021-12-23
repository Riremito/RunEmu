#include"../Lib/Hook.h"
#pragma comment(lib, "../Lib/Hook.lib")
#include"../Lib/Rosemary.h"
#pragma comment(lib, "../Lib/Rose.lib")
#include<iphlpapi.h>
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Netapi32.lib")
#pragma comment(lib, "ws2_32.lib")
#include<string>
#include<intrin.h>
#pragma intrinsic(_ReturnAddress)
#include"FixThemida.h"

FixThemida fixthemida;
bool ThemidaAccessViolationFix() {
	// themida用の回避コードを有効化
	fixthemida.Patch();
	return true;
}


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

// v186.1
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

// 00A2A60D - 0FB6 09  - movzx ecx, byte ptr[ecx]
// 00A2A610 - 8B 55 14 - mov edx, [ebp + 14]
void __declspec(naked) CRCBypass180() {
	__asm {
		push eax
		push edx
		push ecx
		push ebx
		push esi
		push edi
		push ecx // Address
		call GetBackup
		// eax = new address
		pop edi
		pop esi
		pop ebx
		pop ecx
		pop edx
		movzx ecx, byte ptr[eax] // crc bypass
		pop eax
		mov edx, [ebp + 0x14]
		jmp uMSCRC_Ret
	}
}

// 0098A486 - 0FB6 3C 1F - movzx edi, byte ptr[edi + ebx]
// 0098A48A - 8B DA - mov ebx, edx
void __declspec(naked) CRCBypass176() {
	__asm {
		push eax
		push edx
		push ecx
		push ebx
		push esi
		push edi
		add ebx,edi
		push ebx
		call GetBackup
		// eax = new address
		pop edi
		pop esi
		pop ebx
		pop ecx
		pop edx
		movzx edi, byte ptr[eax] // crc bypass
		pop eax
		mov ebx, edx
		jmp uMSCRC_Ret
	}
}

// 00BA2C8D - 33 04 8E - xor eax, [esi + ecx * 4]
// 00BA2C90 - 25 FF000000 - and eax, 000000FF
void __declspec(naked) CRCBypass187() {
	__asm {
		push eax
		push edx
		push ebx
		push esi
		push edi
		lea edi, [esi + ecx * 4]
		push edi
		call GetBackup
		mov ecx,eax // ecxに必要なアドレスを入れる
		pop edi
		pop esi
		pop ebx
		pop edx
		pop eax
		xor eax, [ecx] // ecx保存不要
		and eax, 0x000000FF
		jmp uMSCRC_Ret
	}
}


std::wstring DatatoString(BYTE *b, DWORD Length) {
	std::wstring wdata;

	for (DWORD i = 0; i < Length; i++) {
		if (i) {
			wdata.push_back(L' ');
		}
		wdata += BYTEtoString(b[i]);
	}

	return wdata;
}


bool bWindowMode = true;
bool MemoryPatch() {
	Rosemary r;
	r.Backup(vSection, vBackup);

	for (size_t i = 0; i < vSection.size(); i++) {
		DEBUG(L"vSection = " + DWORDtoString((ULONG_PTR)vSection[i].BaseAddress) + L" - " + DWORDtoString((ULONG_PTR)vSection[i].BaseAddress + vSection[i].RegionSize) + L", Backup = " + DWORDtoString((ULONG_PTR)vBackup[i]));
	}

	// 0x00BA2C8D v187.0
	ULONG_PTR uMSCRC = r.Scan(L"33 04 8E 25 FF 00 00 00 33 14 85");
	if (uMSCRC) {
		uMSCRC_Ret = uMSCRC + 8;
		r.Hook(uMSCRC, CRCBypass187, 3);

		ULONG_PTR uThemidaCRC = r.Scan(L"55 8B EC 83 EC 54 53 56 57 89 4D B4 8B 4D B4 E8");
		if (uThemidaCRC) {
			r.Patch(uThemidaCRC, L"31 C0 C3");
		}
		DEBUG(L"uThemidaCRC = " + DWORDtoString(uThemidaCRC));
		ULONG_PTR uLoginCRC = 0;
		do {
			uLoginCRC = r.Scan(L"55 8B EC 83 EC 14 53 56 57 83 4D FC FF C7 45 F8");
			if (uLoginCRC) {
				r.Patch(uLoginCRC, L"31 C0 C3");
			}
			DEBUG(L"uLoginCRC = " + DWORDtoString(uLoginCRC));
		} while (uLoginCRC);
	}
	else {
		// v187.0だと別のアドレスがヒットしてしまうのでv187.0を優先して処理する
		// 0x0098A486 v176.0
		uMSCRC = r.Scan(L"0F B6 3C 1F 8B DA 23 DE 33 FB 8B 3C BD");
		if (uMSCRC) {
			uMSCRC_Ret = uMSCRC + 0x06;
			r.Hook(uMSCRC, CRCBypass176, 1);
		}
		// 0x00A2A60D v180.1
		if (!uMSCRC) {
			uMSCRC = r.Scan(L"0F B6 09 8B 55 14 8B 12 33 D1 81 E2 FF 00 00 00 33 04 95");
			if (uMSCRC) {
				uMSCRC_Ret = uMSCRC + 0x06;
				r.Hook(uMSCRC, CRCBypass180, 1);
			}
		}
		if (!uMSCRC) {
			// 0x00B5D2B0 v186.1
			uMSCRC = r.Scan(L"8B 4D 18 8B 55 E0 8B 75 08 8B 09 33 0C 96 81 E1 FF 00 00 00 33 04 8D");
			if (uMSCRC) {
				uMSCRC += 0x09;
				uMSCRC_Ret = uMSCRC + 0x05;
				r.Hook(uMSCRC, CRCBypass);
			}
		}
	}
	DEBUG(L"uMSCRC = " + DWORDtoString(uMSCRC));


	// 0x0090CC4E v164.0
	ULONG_PTR uHackShield_Init = r.Scan(L"55 8B EC 81 EC ?? ?? ?? ?? 53 8B D9 83 7B 10 00 0F 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 74");
	if (!uHackShield_Init) {
		// 0x00BC8D39 v186.1
		uHackShield_Init = r.Scan(L"55 8B EC 81 EC ?? ?? ?? ?? 53 8B D9 8D 4B ?? 89 4D ?? E8 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0");
	}
	if (uHackShield_Init) {
		r.Patch(uHackShield_Init, L"31 C0 C2 04 00");
	}

	// 0x00BCF256 v186.1
	ULONG_PTR uEHSvc_Loader_1 = r.Scan(L"55 8B EC 81 EC ?? ?? ?? ?? 57 C7 45 ?? 00 00 00 00 C6 85 ?? ?? ?? ?? 00 B9 ?? ?? ?? ?? 33 C0 8D BD ?? ?? ?? ?? F3 AB");
	if (uEHSvc_Loader_1) {
		r.Patch(uEHSvc_Loader_1, L"31 C0 C2 10 03");
	}

	// 0x00910FF2 v164.0
	ULONG_PTR uEHSvc_Loader_2 = r.Scan(L"55 8B EC 81 EC ?? ?? ?? ?? 57 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 C6 85 ?? ?? ?? ?? 00 B9 82 00 00 00 33 C0 8D BD ?? ?? ?? ?? F3 AB C7 45 ?? 00 00 00 00 90 E8 ?? ?? ?? ?? 50 E8");
	if (!uEHSvc_Loader_2) {
		// v164.0 call nop
		uEHSvc_Loader_2 = r.Scan(L"55 8B EC 81 EC ?? ?? ?? ?? 57 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 C6 85 ?? ?? ?? ?? 00 B9 82 00 00 00 33 C0 8D BD ?? ?? ?? ?? F3 AB C7 45 ?? 00 00 00 00 E8 ?? ?? ?? ?? 90 50 E8");
	}
	if (!uEHSvc_Loader_2) {
		// 0x00BCE382 v186.1
		uEHSvc_Loader_2 = r.Scan(L"55 8B EC 81 EC ?? ?? ?? ?? 57 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 C6 85 ?? ?? ?? ?? 00 B9 ?? ?? ?? ?? 33 C0 8D BD ?? ?? ?? ?? F3 AB");
	}
	if (uEHSvc_Loader_2) {
		r.Patch(uEHSvc_Loader_2, L"31 C0 C2 18 00");
	}

	// 0x00BC91FC v186.1
	ULONG_PTR uHeartBeat = r.Scan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 81 EC ?? ?? ?? ?? 56 BE ?? ?? ?? ?? 56 8D 85 ?? ?? ?? ?? 6A 00 50 E8");
	if (uHeartBeat) {
		r.Patch(uHeartBeat, L"31 C0 C2 04 00");
	}

	// 0x0090D128 v164.0
	ULONG_PTR uMKD25tray = r.Scan(L"55 8B EC 83 EC 0C 56 8B F1 83 7E 18 00 0F 85 ?? ?? ?? ?? 83 65 FC 00 8D 45 FC 50 90 E8 ?? ?? ?? ?? 83 7D FC 00 59");
	if (!uMKD25tray) {
		// v164.0 call nop
		uMKD25tray = r.Scan(L"55 8B EC 83 EC 0C 56 8B F1 83 7E 18 00 0F 85 ?? ?? ?? ?? 83 65 FC 00 8D 45 FC 50 E8 ?? ?? ?? ?? 90 83 7D FC 00 59");
	}
	if (!uMKD25tray) {
		// 0x009DF88A v176.0
		uMKD25tray = r.Scan(L"55 8B EC 83 EC 0C 56 8B F1 83 7E 18 00 0F 85 ?? ?? ?? ?? 83 65 FC 00 8D 45 FC 50 FF 15");
	}
	if (!uMKD25tray) {
		// 0x00BC93BB v186.1
		uMKD25tray = r.Scan(L"55 8B EC 83 EC ?? 56 8B F1 57 8D 7E ?? 8B CF E8 ?? ?? ?? ?? 85 C0 0F 85");
	}
	if (uMKD25tray) {
		r.Patch(uMKD25tray, L"31 C0 C3");
	}

	// 0x0090D107 v164.0
	ULONG_PTR uAutoup = r.Scan(L"56 8B F1 83 7E 14 00 74 16 68 ?? ?? ?? ?? 68 80 00 00 00 90 E8 ?? ?? ?? ?? 83 66 14 00 59 59 5E C3");
	if (!uAutoup) {
		// v164.0 call nop
		uAutoup = r.Scan(L"56 8B F1 83 7E 14 00 74 16 68 ?? ?? ?? ?? 68 80 00 00 00 E8 ?? ?? ?? ?? 90 83 66 14 00 59 59 5E C3");
	}
	if (!uAutoup) {
		// 0x009DF869 v176.0
		uAutoup = r.Scan(L"56 8B F1 83 7E 14 00 74 ?? 68 ?? ?? ?? ?? 68 80 00 00 00 FF 15");
	}
	if (!uAutoup) {
		// 0x00BC938F v186.1
		uAutoup = r.Scan(L"56 8D 71 ?? 8B CE E8 ?? ?? ?? ?? 85 C0 74 ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15");
	}
	if (uAutoup) {
		r.Patch(uAutoup, L"31 C0 C3");
	}

	// 0x0090D07A v164.0
	ULONG_PTR uASPLunchr = r.Scan(L"55 8B EC 83 EC 0C 56 8B F1 83 7E 14 00 75 ?? 68 ?? ?? ?? ?? 90 E8");
	if (!uASPLunchr) {
		// v164.0 call nop
		uASPLunchr = r.Scan(L"55 8B EC 83 EC 0C 56 8B F1 83 7E 14 00 75 ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 90");
	}
	if (!uASPLunchr) {
		// 0x009DF7DC v176.0
		uASPLunchr = r.Scan(L"55 8B EC 83 EC 0C 56 8B F1 83 7E 14 00 75 ?? 68 ?? ?? ?? ?? FF 15");
	}
	if (!uASPLunchr) {
		// 0x00BC92F6 v186.1
		uASPLunchr = r.Scan(L"55 8B EC 83 EC ?? 56 8B F1 57 8D 7E ?? 8B CF E8 ?? ?? ?? ?? 85 C0 75 ?? 68 ?? ?? ?? ?? FF 15");
	}
	if (uASPLunchr) {
		r.Patch(uASPLunchr, L"31 C0 C3");
	}

	// 0x0090CA45 v164.0
	ULONG_PTR uHSUpdate = r.Scan(L"55 8B EC 81 EC ?? ?? ?? ?? 53 8B D9 83 7B 0C 00 56 57 0F 85 ?? ?? ?? ?? 8A 15");
	if (!uHSUpdate) {
		// 0x00A87C23 v180.1
		uHSUpdate = r.Scan(L"55 8B EC 81 EC ?? ?? ?? ?? 53 56 8D 59 ?? 57 8B CB E8 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 8A 15");
		if (!uHSUpdate) {
			// 0x00BC8A7A v186.1
			uHSUpdate = r.Scan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 81 EC ?? ?? ?? ?? 56 83 C1 ?? 57 89 4D ?? E8 ?? ?? ?? ?? 85 C0 0F 85");
			if (!uHSUpdate) {
				// 0x00C10331 v187
				uHSUpdate = r.Scan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 81 EC ?? ?? ?? ?? 53 56 83 C1 ?? 57 89 4D ?? E8 ?? ?? ?? ?? 85 C0 0F 85");
			}
		}
	}
	if (uHSUpdate) {
		r.Patch(uHSUpdate, L"31 C0 C3");
	}

	ULONG_PTR uWindowMode = 0;
	if (bWindowMode) {
		// 0x00B60EE5 v164.0
		uWindowMode = r.Scan(L"C7 45 E4 10 00 00 00 E8 ?? ?? ?? ?? 8D 45");
		if (!uWindowMode) {
			// 0x00B60EE5 v186.1
			uWindowMode = r.Scan(L"C7 45 DC 10 00 00 00 6A 03 FF 75 ?? 8D 4D ?? E8");
		}
		if (uWindowMode) {
			r.Patch(uWindowMode + 0x03, L"00 00 00 00");
		}
		else {
			// 0x00BA70CF v187
			uWindowMode = r.Scan(L"8B 45 ?? 89 45 ?? 6A 03 FF 75");
			if (uWindowMode) {
				r.Patch(uWindowMode, L"31 C0 90");
			}
		}
	}

	// 0x0084268E v186.1
	ULONG_PTR uLauncher = r.Scan(L"55 8B EC 83 EC ?? 53 56 57 33 DB 53 FF 15 ?? ?? ?? ?? 8B 7D ?? 89 3D ?? ?? ?? ?? 8B 87");
	if (uLauncher) {
		r.Patch(uLauncher, L"B8 01 00 00 00 C3");
	}

	// 0x00425A17 v186.1
	ULONG_PTR uAd = r.Scan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC ?? 53 56 57 33 DB 53 FF 15");
	if (uAd) {
		r.Patch(uAd, L"B8 01 00 00 00 C3");
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
	DEBUG(L"uAd = " + DWORDtoString(uAd));

	/*
	// v186.1
	{
		// アイテムドロップ不可マップ制限解除
		r.Patch(0x00B75373, L"EB");
		// ポイントアイテムドロップ制限解除
		r.Patch(0x00531626, L"90 90 90 90 90 90");
		r.Patch(0x00531638, L"90 90 90 90 90 90");
	}
	*/

	//SetDllDirectoryW(L"C:\\Users\\elfenlied\\Desktop\\Elfenlied\\Software\\Cheat Engine 7.3");
	//LoadLibraryW(L"Packet.dll");

	return true;
}


// API Hook
HANDLE(WINAPI *_CreateMutexExW)(LPSECURITY_ATTRIBUTES, LPCWSTR, DWORD, DWORD) = NULL;
HANDLE WINAPI CreateMutexExW_Hook(LPSECURITY_ATTRIBUTES lpMutexAttributes, LPCWSTR lpName, DWORD dwFlags, DWORD dwDesiredAccess) {
	EnterHook e(__LINE__);
	if (e.Enter()) {
		if (lpName) {
			if (wcscmp(lpName, L"WvsClientMtx") == 0) {
				// themida用の回避コードを無効にする
				fixthemida.Restore();
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

HHOOK (WINAPI *_SetWindowsHookExA)(int, HOOKPROC, HINSTANCE, DWORD) = NULL;
HHOOK WINAPI SetWindowsHookExA_Hook(int idHook, HOOKPROC lpfn, HINSTANCE hmod, DWORD dwThreadId) {
	return 0;
}

HHOOK(WINAPI *_SetWindowsHookExW)(int, HOOKPROC, HINSTANCE, DWORD) = NULL;
HHOOK WINAPI SetWindowsHookExW_Hook(int idHook, HOOKPROC lpfn, HINSTANCE hmod, DWORD dwThreadId) {
	return 0;
}

DWORD dwPServer = 0x0100007F; // 127.0.0.1
int (PASCAL *_connect)(SOCKET, sockaddr_in *, int) = NULL;
int PASCAL connect_Hook(SOCKET s, sockaddr_in *name, int namelen) {
	WORD wPort = ntohs(name->sin_port);

	std::wstring server = std::to_wstring(name->sin_addr.S_un.S_un_b.s_b1) + L"." + std::to_wstring(name->sin_addr.S_un.S_un_b.s_b2) + L"." + std::to_wstring(name->sin_addr.S_un.S_un_b.s_b3) + L"." + std::to_wstring(name->sin_addr.S_un.S_un_b.s_b4) + L":" + std::to_wstring(wPort);
	
	*(DWORD *)&name->sin_addr.S_un = dwPServer;

	std::wstring pserver = std::to_wstring(name->sin_addr.S_un.S_un_b.s_b1) + L"." + std::to_wstring(name->sin_addr.S_un.S_un_b.s_b2) + L"." + std::to_wstring(name->sin_addr.S_un.S_un_b.s_b3) + L"." + std::to_wstring(name->sin_addr.S_un.S_un_b.s_b4) + L":" + std::to_wstring(wPort);

	DEBUG(L"[connect][" + server + L" -> " + pserver + L"]");

	name->sin_port = htons(wPort);

	return _connect(s, name, namelen);
}

// 接続先のサーバーのIPを変更したい場合の設定
bool SetServerIP() {
	FILE *fp = NULL;
	if (fopen_s(&fp, "SetServer.txt", "r")) {
		return false;
	}
	DWORD dwIP[4] = { 0 };

	fscanf_s(fp, "%d.%d.%d.%d", &dwIP[0], &dwIP[1], &dwIP[2], &dwIP[3]);
	fclose(fp);

	BYTE *ip_bytes = (BYTE *)&dwPServer;
	for (int i = 0; i < 4; i++) {
		ip_bytes[i] = (BYTE)dwIP[i];
	}

	return true;
}

// ウィンドウモード無効にしたい場合の設定
bool SetWindowMode() {
	FILE *fp = NULL;
	if (fopen_s(&fp, "SetWindow.txt", "r")) {
		return false;
	}

	DWORD dwRead = 1;
	fscanf_s(fp, "%d", &dwRead);

	fclose(fp);

	if (!dwRead) {
		bWindowMode = false;
	}

	return true;
}

void RireSaba() {
	EnterHook::Init();
	ThemidaAccessViolationFix();
	SetWindowMode();
	SetServerIP();

	// ip redirect
	TestHook(connect);
	// remove mutex and enable memory edit
	TestHook(CreateMutexExW);
	// test
	TestHook(SetWindowsHookExA);
	TestHook(SetWindowsHookExW);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
	if (fdwReason == DLL_PROCESS_ATTACH) {
		DisableThreadLibraryCalls(hinstDLL);
		RireSaba();
	}
	return TRUE;
}