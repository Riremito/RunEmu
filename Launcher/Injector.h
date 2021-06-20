#ifndef __INJECTOR_H__
#define __INJECTOR_H__

#include<Windows.h>
#include<string>

class Injector {
private:
	std::wstring target_path;
	std::wstring dll_path;
	HANDLE process_handle;
	HANDLE main_thread_handle;
	bool is_successed;

public:
	Injector(std::wstring wTargetPath, std::wstring wDllPath);
	~Injector();
	bool Run();
};

#endif