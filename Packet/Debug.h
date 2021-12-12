#ifndef __DEBUG__H__
#define __DEBUG__H__

#include<Windows.h>
#include<string>

#define DEBUG(msg) \
{\
std::wstring wmsg = L"[Maple] ";\
wmsg += msg;\
OutputDebugStringW(wmsg.c_str());\
}

std::wstring BYTEtoString(BYTE b);
std::wstring WORDtoString(WORD w);
std::wstring DWORDtoString(DWORD dw);
std::wstring DatatoString(BYTE *b, DWORD Length, bool space = false);


#endif