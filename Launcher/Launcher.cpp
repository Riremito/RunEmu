#include"Injector.h"

bool GetClientFileName(std::wstring &wFileName) {
	FILE *fp = NULL;

	wFileName = L"MapleStory.exe";
	if (fopen_s(&fp, "RunEmu.txt", "r")) {
		return false;
	}
	wchar_t buffer[MAX_PATH] = { 0 };
	fwscanf_s(fp, L"%s", buffer);
	fclose(fp);

	if (wcslen(buffer)) {
		wFileName = buffer;
		return true;
	}
	return false;
}

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

	std::wstring wFileName;
	GetClientFileName(wFileName);

	Injector injector(dir + wFileName, dir + L"Emu.dll");
	return injector.Run();
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
	if (!Launcher()) {
		MessageBoxW(NULL, L"Error", L"Launcher", MB_OK);
		return 1;
	}
	return 0;
}