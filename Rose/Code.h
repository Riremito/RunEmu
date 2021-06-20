#ifndef __CODE_H__
#define __CODE_H__

#include<Windows.h>
#include<string>
#include<vector>

class Code {
private:
	bool init;
	std::vector<unsigned char> code;

	bool CreateCode(std::wstring wCode);

public:
	Code(std::wstring wCode);
	bool Write(ULONG_PTR uAddress);
};

#endif