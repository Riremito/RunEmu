#ifndef __ROSEMARY_H__
#define __ROSEMARY_H__

#include<Windows.h>
#include<tlhelp32.h>
#include<string>
#include<vector>

class Rosemary {
private:
	bool init;
	std::vector<MEMORY_BASIC_INFORMATION> section_list;
	bool GetSections(std::wstring wModuleName, bool bExe = false);

public:
	Rosemary();
	Rosemary(std::wstring wModuleName);
	~Rosemary();
	ULONG_PTR Scan(std::wstring wAob);
	bool Patch(std::wstring wAob, std::wstring wCode);
	bool Patch(ULONG_PTR uAddress, std::wstring wCode);
	bool Backup(std::vector<MEMORY_BASIC_INFORMATION> &vSection, std::vector<void*> &vBackup);
	bool Hook(ULONG_PTR uAddress, void *HookFunction, ULONG_PTR uNop = 0);
};

#endif