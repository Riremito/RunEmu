#ifndef __AOBSCAN_H__
#define __AOBSCAN_H__

#include<string>
#include<vector>

class AobScan {
private:
	bool init;
	std::vector<unsigned char> array_of_bytes;
	std::vector<unsigned char> mask;

	bool CreateAob(std::wstring wAob);

public:
	AobScan(std::wstring wAob);
	bool Compare(unsigned long int uAddress);
};

#endif