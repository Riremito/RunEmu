#include"Injector.h"

Injector::Injector(std::wstring wTargetPath, std::wstring wDllPath) {
	target_path = wTargetPath;
	dll_path = wDllPath;
	process_handle = NULL;
	main_thread_handle = NULL;
	is_successed = false;
};

Injector::~Injector() {
	if (main_thread_handle) {
		if (is_successed) {
			ResumeThread(main_thread_handle);
		}
		CloseHandle(main_thread_handle);
	}
	if (process_handle) {
		if (!is_successed) {
			TerminateProcess(process_handle, 0xDEAD);
		}
		CloseHandle(process_handle);
	}
}

bool Injector::Run() {
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));
	si.cb = sizeof(si);

	if (!CreateProcessW(target_path.c_str(), 0, 0, 0, FALSE, CREATE_SUSPENDED, 0, 0, &si, &pi)) {
		return false;
	}

	process_handle = pi.hProcess;
	main_thread_handle = pi.hThread;

	// Process
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);
	if (!hProcess) {
		return false;
	}

	CloseHandle(process_handle);
	process_handle = hProcess;

	// Thread
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, pi.dwThreadId);
	if (!hThread) {
		return false;
	}

	CloseHandle(main_thread_handle);
	main_thread_handle = hThread;

	// EIP
	CONTEXT ct;
	memset(&ct, 0, sizeof(ct));
	ct.ContextFlags = CONTEXT_ALL;
	if (!GetThreadContext(main_thread_handle, &ct)) {
		return false;
	}

	void *vPath = VirtualAllocEx(process_handle, NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
	if (!vPath) {
		return false;
	}

	SIZE_T bw;
	if (!WriteProcessMemory(process_handle, vPath, dll_path.c_str(), (wcslen(dll_path.c_str()) + 1) * sizeof(wchar_t), &bw)) {
		return false;
	}

	void *vCode = VirtualAllocEx(process_handle, NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!vCode) {
		return false;
	}

	BYTE bLoader[] = { 0x50, 0x53, 0x68, 0xAB, 0xAB, 0xAB, 0xAB, 0xE8, 0x35, 0x02, 0x7C, 0x20, 0x5B, 0x58, 0xE9, 0x2E, 0x02, 0x7C, 0x20 };
	*(DWORD *)&bLoader[0x02 + 0x01] = (DWORD)vPath;
	*(DWORD *)&bLoader[0x07 + 0x01] = (DWORD)LoadLibraryW - ((DWORD)vCode + 0x07) - 0x05;
	*(DWORD *)&bLoader[0x0E + 0x01] = (DWORD)ct.Eip - ((DWORD)vCode + 0x0E) - 0x05;
	if (!WriteProcessMemory(process_handle, vCode, bLoader, sizeof(bLoader), &bw)) {
		return false;
	}

	CONTEXT ctInject = ct;
	ctInject.Eip = (DWORD)vCode;
	if (!SetThreadContext(main_thread_handle, &ctInject)) {
		return false;
	}

	is_successed = true;
	return true;
}