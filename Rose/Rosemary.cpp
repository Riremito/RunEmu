#include"Rosemary.h"
#include"AobScan.h"
#include"Code.h"

Rosemary::Rosemary() {
	init = GetSections(L"test", true);
}

Rosemary::Rosemary(std::wstring wModuleName) {
	init = GetSections(wModuleName);
}

Rosemary::~Rosemary() {

}

bool Rosemary::GetSections(std::wstring wModuleName , bool bExe) {
	DWORD pid = GetCurrentProcessId();

	if (!pid) {
		return false;
	}

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);

	if (hSnapshot == INVALID_HANDLE_VALUE) {
		return false;
	}

	MODULEENTRY32W me;
	memset(&me, 0, sizeof(me));
	me.dwSize = sizeof(me);
	if (!Module32FirstW(hSnapshot, &me)) {
		return false;
	}

	std::vector<MODULEENTRY32W> module_list;
	do {
		module_list.push_back(me);
	} while (Module32NextW(hSnapshot, &me));

	CloseHandle(hSnapshot);

	for (size_t i = 0; i < module_list.size(); i++) {
		if (bExe || _wcsicmp(module_list[i].szModule, wModuleName.c_str()) == 0) {
			MEMORY_BASIC_INFORMATION mbi;
			memset(&mbi, 0, sizeof(mbi));

			ULONG_PTR section_base = (ULONG_PTR)module_list[i].modBaseAddr;
			while (section_base < ((ULONG_PTR)module_list[i].modBaseAddr + module_list[i].modBaseSize) && (VirtualQuery((void *)section_base, &mbi, sizeof(mbi)) == sizeof(mbi))) {
				if (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
					section_list.push_back(mbi);
				}
				section_base += mbi.RegionSize;
			}

			if (!section_list.size()) {
				return false;
			}

			return true;
		}
	}

	return false;
}

ULONG_PTR Rosemary::Scan(std::wstring wAob) {
	if (!init) {
		return 0;
	}

	AobScan a(wAob);

	for (size_t i = 0; i < section_list.size(); i++) {
		for (ULONG_PTR uAddress = (ULONG_PTR)section_list[i].BaseAddress; uAddress < ((ULONG_PTR)section_list[i].BaseAddress + section_list[i].RegionSize); uAddress++) {
			if (a.Compare(uAddress)) {
				return uAddress;
			}
		}
	}

	return 0;
}

bool Rosemary::Patch(std::wstring wAob, std::wstring wCode) {
	ULONG_PTR uAddress = Scan(wAob);

	if (!uAddress) {
		return false;
	}

	Code c(wCode);
	return c.Write(uAddress);
}

bool Rosemary::Patch(ULONG_PTR uAddress, std::wstring wCode) {
	if (!uAddress) {
		return false;
	}

	Code c(wCode);
	return c.Write(uAddress);
}

bool Rosemary::Backup(std::vector<MEMORY_BASIC_INFORMATION> &vSection, std::vector<void*> &vBackup) {
	vSection.clear();
	vBackup.clear();

	if (!init) {
		return false;
	}

	for (size_t i = 0; i < section_list.size(); i++) {
		void *memory = VirtualAlloc(NULL, section_list[i].RegionSize, MEM_COMMIT, PAGE_READWRITE);
		if (!memory) {
			vBackup.clear();
			return false;
		}
		for (size_t j = 0; j < section_list[i].RegionSize; j++) {
			((BYTE *)memory)[j] = *(BYTE *)((ULONG_PTR)section_list[i].BaseAddress + j);
		}
		vBackup.push_back(memory);
	}

	vSection = section_list;
	return true;
}

bool Rosemary::Hook(ULONG_PTR uAddress, void *HookFunction, ULONG_PTR uNop) {
	DWORD old = 0;
	if (!VirtualProtect((void *)uAddress, 5 + uNop, PAGE_EXECUTE_READWRITE, &old)) {
		return false;
	}

	*(BYTE *)uAddress = 0xE9;
	*(DWORD *)(uAddress + 0x01) = (ULONG_PTR)HookFunction - uAddress - 0x05;

	for (size_t i = 0; i < uNop; i++) {
		((BYTE *)uAddress)[5 + i] = 0x90;
	}

	VirtualProtect((void *)uAddress, 5 + uNop, old, &old);
	return true;
}