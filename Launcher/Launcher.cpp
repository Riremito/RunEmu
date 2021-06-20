#include"Injector.h"

bool Launcher() {
	WCHAR wcDir[MAX_PATH] = { 0 };

	if (!GetModuleFileNameW(GetModuleHandleW(NULL), wcDir, _countof(wcDir))) {
		return false;
	}

	std::wstring dir = wcDir;
	size_t pos = dir.rfind(L"\\");

	if (pos == std::wstring::npos) {
		return false;
	}

	dir = dir.substr(0, pos + 1);

	Injector injector(dir + L"MapleStory.exe", dir + L"Emu.dll");
	return injector.Run();
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
	if (!Launcher()) {
		MessageBoxW(NULL, L"Error", L"Launcher", MB_OK);
		return 1;
	}
	return 0;
}