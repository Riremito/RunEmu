#include"MaplePacket.h"
#include"../Share/SimpleHook.h"
#include"../Lib/Rosemary.h"
#pragma comment(lib, "../Lib/Rose.lib")
#include"MaplePacket.h"
#include"Debug.h"
#include<vector>
#include<intrin.h>
#pragma intrinsic(_ReturnAddress)
#include"../Lib/Pipe.h"
#pragma comment(lib, "../Lib/Pipe.lib")
#include"../PacketEditor/PacketEditor.h"

PipeClient *pc = NULL;

bool StartPipeClient() {
	pc = new PipeClient(L"PacketEditor");
	return pc->Run();
}

bool RestartPipeClient() {
	if (pc) {
		delete pc;
	}
	return StartPipeClient();
}

// ShiftJIS to UTF16
bool ShiftJIStoUTF8(std::string sjis, std::wstring &utf16) {
	// UTF16へ変換する際の必要なバイト数を取得
	int len = MultiByteToWideChar(CP_ACP, 0, sjis.c_str(), -1, 0, 0);
	if (!len) {
		return false;
	}

	// UTF16へ変換
	std::vector<BYTE> b((len + 1) * sizeof(WORD));
	if (!MultiByteToWideChar(CP_ACP, 0, sjis.c_str(), -1, (WCHAR *)&b[0], len)) {
		return false;
	}

	utf16 = std::wstring((WCHAR *)&b[0]);
	return true;
}

// バイト配列からShiftJIS文字列を取得
bool BYTEtoShiftJIS(BYTE *text, int len, std::string &sjis) {
	std::vector<BYTE> b(len + 1);
	for (size_t i = 0; i < len; i++) {
		b[i] = text[i];
	}
	sjis = std::string((char *)&b[0]);
	return true;
}

void (__thiscall *_SendPacket)(void *ecx, OutPacket *p);
void (__thiscall *_COutPacket)(OutPacket *p, WORD w);
void (__thiscall *_Encode1)(OutPacket *p, BYTE b);
void (__thiscall *_Encode2)(OutPacket *p, WORD w);
void (__thiscall *_Encode4)(OutPacket *p, DWORD dw);
void (__thiscall *_EncodeStr)(OutPacket *p, char *s);
void (__thiscall *_EncodeBuffer)(OutPacket *p, BYTE *b, DWORD len);

void (__thiscall *_ProcessPacket)(void *ecx, InPacket *p);
BYTE (__thiscall *_Decode1)(InPacket *p);
WORD (__thiscall *_Decode2)(InPacket *p);
DWORD (__thiscall *_Decode4)(InPacket *p);
char** (__thiscall *_DecodeStr)(InPacket *p, char **s);
void (__thiscall *_DecodeBuffer)(InPacket *p, BYTE *b, DWORD len);

DWORD packet_id_out = 0;
DWORD packet_id_in = 0;

typedef struct {
	DWORD id; // パケット識別子
	DWORD addr; // リターンアドレス
	MessageHeader fmt; // フォーマットの種類
	DWORD pos; // 場所
	DWORD len; // データの長さ (DecodeBuffer以外不要)

} PacketExtraInformation;


void AddExtra(PacketExtraInformation &pxi) {
	union {
		PacketEditorMessage *pem;
		BYTE *b;
	};

	pem = new PacketEditorMessage;

	if (!pem) {
		return;
	}

	pem->header = pxi.fmt;
	pem->id = pxi.id;
	pem->addr = pxi.addr;
	pem->Extra.pos = pxi.pos;
	pem->Extra.size = pxi.len;

	if (!pc->Send(b, sizeof(PacketEditorMessage))) {
		RestartPipeClient();
	}

	delete pem;
}

void AddSendPacket(OutPacket *p, DWORD addr) {
	union {
		PacketEditorMessage *pem;
		BYTE *b;
	};

	b = new BYTE[sizeof(PacketEditorMessage) + p->encoded];

	if (!b) {
		return;
	}

	pem->header = SENDPACKET;
	pem->id = packet_id_out;
	pem->addr = addr;
	pem->Binary.length = p->encoded;
	memcpy_s(pem->Binary.packet, p->encoded, p->packet, p->encoded);

	if (!pc->Send(b, sizeof(PacketEditorMessage) + p->encoded)) {
		RestartPipeClient();
	}

	delete[] b;
}

void AddRecvPacket(InPacket *p, DWORD addr) {
	union {
		PacketEditorMessage *pem;
		BYTE *b;
	};

	b = new BYTE[sizeof(PacketEditorMessage) + p->length2];

	if (!b) {
		return;
	}

	pem->header = RECVPACKET;
	pem->id = packet_id_in;
	pem->addr = addr;
	pem->Binary.length = p->length2;
	memcpy_s(pem->Binary.packet, p->length2, &p->packet[4], p->length2);

	if (!pc->Send(b, sizeof(PacketEditorMessage) + p->length2)) {
		RestartPipeClient();
	}

	delete[] b;
}


// 先にフォーマット情報は送信される
void __fastcall SendPacket_Hook(void *ecx, void *edx, OutPacket *p) {
	AddSendPacket(p, (DWORD)_ReturnAddress());
	// OK
	return _SendPacket(ecx, p);
}

void __fastcall  COutPacket_Hook(OutPacket *p, void *edx, WORD w) {
	packet_id_out++;
	PacketExtraInformation pxi = { packet_id_out, (DWORD)_ReturnAddress(), ENCODEHEADER, 0, sizeof(WORD) };
	AddExtra(pxi);
	return _COutPacket(p, w);
}

void __fastcall Encode1_Hook(OutPacket *p, void *edx, BYTE b) {
	if (p->encoded) {
		PacketExtraInformation pxi = { packet_id_out, (DWORD)_ReturnAddress(), ENCODE1, p->encoded, sizeof(BYTE) };
		AddExtra(pxi);
	}
	return _Encode1(p, b);
}
void __fastcall Encode2_Hook(OutPacket *p, void *edx, WORD w) {
	if (p->encoded) {
		PacketExtraInformation pxi = { packet_id_out, (DWORD)_ReturnAddress(), ENCODE2, p->encoded, sizeof(WORD) };
		AddExtra(pxi);
	}
	return _Encode2(p, w);

}
void __fastcall Encode4_Hook(OutPacket *p, void *edx, DWORD dw) {
	PacketExtraInformation pxi = { packet_id_out, (DWORD)_ReturnAddress(), ENCODE4, p->encoded, sizeof(DWORD) };
	AddExtra(pxi);
	return _Encode4(p, dw);
}
void __fastcall EncodeStr_Hook(OutPacket *p, void *edx, char *s) {
	PacketExtraInformation pxi = { packet_id_out, (DWORD)_ReturnAddress(), ENCODESTR, p->encoded, sizeof(WORD) + strlen(s) };
	AddExtra(pxi);
	return _EncodeStr(p, s);
}
void __fastcall EncodeBuffer_Hook(OutPacket *p, void *edx, BYTE *b, DWORD len) {
	PacketExtraInformation pxi = { packet_id_out, (DWORD)_ReturnAddress(), ENCODEBUFFER, p->encoded, sizeof(WORD) + len };
	AddExtra(pxi);
	return _EncodeBuffer(p, b, len);
}

// 後からフォーマット情報は送信される
void __fastcall ProcessPacket_Hook(void *ecx, void *edx, InPacket *p) {
	if (p->unk2 == 0x02) {
		packet_id_in++;
		AddRecvPacket(p, (DWORD)_ReturnAddress());
		_ProcessPacket(ecx, p);
		PacketExtraInformation pxi = { packet_id_in, (DWORD)0, DECODEEND, 0, 0 };
		AddExtra(pxi);
	}
	else {
		_ProcessPacket(ecx, p);
	}
}

BYTE __fastcall Decode1_Hook(InPacket *p, void *edx) {
	if (p->unk2 == 0x02) {
		PacketExtraInformation pxi = { packet_id_in, (DWORD)_ReturnAddress(), DECODE1, p->decoded - 4, sizeof(BYTE) };
		AddExtra(pxi);
	}
	return _Decode1(p);
}

WORD __fastcall Decode2_Hook(InPacket *p, void *edx) {
	if (p->unk2 == 0x02) {
		if (p->decoded == 4) {
			PacketExtraInformation pxi = { packet_id_in, (DWORD)_ReturnAddress(), DECODEHEADER, p->decoded - 4, sizeof(WORD) };
			AddExtra(pxi);
		}
		else {
			PacketExtraInformation pxi = { packet_id_in, (DWORD)_ReturnAddress(), DECODE2, p->decoded - 4, sizeof(WORD) };
			AddExtra(pxi);
		}
	}
	return _Decode2(p);
}

DWORD __fastcall Decode4_Hook(InPacket *p, void *edx) {
	if (p->unk2 == 0x02) {
		PacketExtraInformation pxi = { packet_id_in, (DWORD)_ReturnAddress(), DECODE4, p->decoded - 4, sizeof(DWORD) };
		AddExtra(pxi);
	}
	return _Decode4(p);
}

char** __fastcall DecodeStr_Hook(InPacket *p, void *edx, char **s) {
	if (p->unk2 == 0x02) {
		PacketExtraInformation pxi = { packet_id_in, (DWORD)_ReturnAddress(), DECODESTR, p->decoded - 4, sizeof(WORD) + *(WORD *)&p->packet[p->decoded] };
		AddExtra(pxi);
	}
	return _DecodeStr(p, s);
}

void __fastcall DecodeBuffer_Hook(InPacket *p, void *edx, BYTE *b, DWORD len) {
	if (p->unk2 == 0x02) {
		PacketExtraInformation pxi = { packet_id_in, (DWORD)_ReturnAddress(), DECODEBUFFER, p->decoded - 4, len };
		AddExtra(pxi);
	}
	return _DecodeBuffer(p, b, len);
}


bool PacketHook() {
	Rosemary r;

	// v164.0 to v186.1
	ULONG_PTR uSendPacket = r.Scan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC 10 53 56 8B F1 8D 9E 80 00 00 00 57 8B CB 89 5D F0 E8 ?? ?? ?? ?? 8B 46 0C 33 FF 3B C7");
	DEBUG(L"uSendPacket = " + DWORDtoString(uSendPacket));
	ULONG_PTR uProcessPacket = r.Scan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 51 A1 ?? ?? ?? ?? 56 57 8B F9 8D 4D EC 89 45 F0 E8 ?? ?? ?? ?? 8B 75 08 83 65 FC 00 8B CE E8 ?? ?? ?? ?? 0F B7");
	DEBUG(L"uProcessPacket = " + DWORDtoString(uProcessPacket));

	if (uSendPacket) {
		SHookFunction(SendPacket, uSendPacket);
		ULONG_PTR uCOutPacket = r.Scan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 51 56 8B F1 83 66 04 00 8D 45 F3 50 8D 4E 04 68 00 01 00 00 89 75 EC E8 ?? ?? ?? ?? FF 75 08 83 65 FC 00 8B CE E8");
		DEBUG(L"uCOutPacket = " + DWORDtoString(uCOutPacket));
		if (uCOutPacket) {
			SHookFunction(COutPacket, uCOutPacket);
			ULONG_PTR uEncode1 = r.Scan(L"56 8B F1 6A 01 E8 ?? ?? ?? ?? 8B 4E 08 8B 46 04 8A 54 24 08 88 14 08 FF 46 08 5E C2 04 00");
			if (uEncode1) {
				SHookFunction(Encode1, uEncode1);
			}

			ULONG_PTR uEncode2 = r.Scan(L"56 8B F1 6A 02 E8 ?? ?? ?? ?? 8B 4E 08 8B 46 04 66 8B 54 24 08 66 89 14 08 83 46 08 02 5E C2 04 00");
			if (uEncode2) {
				SHookFunction(Encode2, uEncode2);
			}

			ULONG_PTR uEncode4 = r.Scan(L"56 8B F1 6A 04 E8 ?? ?? ?? ?? 8B 4E 08 8B 46 04 8B 54 24 08 89 14 08 83 46 08 04 5E C2 04 00");
			if (uEncode4) {
				SHookFunction(Encode4, uEncode4);
			}

			ULONG_PTR uEncodeStr = r.Scan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 56 8B F1 8B 45 08 83 65 FC 00 85 C0 74 05 8B 40 FC EB 02 33 C0 83 C0 02 50 8B CE E8");
			if (uEncodeStr) {
				SHookFunction(EncodeStr, uEncodeStr);
			}

			ULONG_PTR uEncodeBuffer = r.Scan(L"56 57 8B 7C 24 10 8B F1 57 E8 ?? ?? ?? ?? 8B 46 04 03 46 08 57 FF 74 24 10 50 E8 ?? ?? ?? ?? 01 7E 08 83 C4 0C 5F 5E C2 08 00");
			if (uEncodeBuffer) {
				SHookFunction(EncodeBuffer, uEncodeBuffer);
			}

			DEBUG(L"uEncode1 = " + DWORDtoString(uEncode1));
			DEBUG(L"uEncode2 = " + DWORDtoString(uEncode2));
			DEBUG(L"uEncode4 = " + DWORDtoString(uEncode4));
			DEBUG(L"uEncodeStr = " + DWORDtoString(uEncodeStr));
			DEBUG(L"uEncodeBuffer = " + DWORDtoString(uEncodeBuffer));
		}
	}

	if (uProcessPacket) {
		SHookFunction(ProcessPacket, uProcessPacket);
		ULONG_PTR uDecode1 = r.Scan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC 14 0F B7 51 0C 8B 41 08 83 65 FC 00 53 56 8B 71 14 2B D6 57 03 C6 83 FA 01");
		if (uDecode1) {
			SHookFunction(Decode1, uDecode1);
		}

		ULONG_PTR uDecode2 = r.Scan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC 14 0F B7 51 0C 8B 41 08 83 65 FC 00 53 56 8B 71 14 2B D6 57 03 C6 83 FA 02");
		if (uDecode2) {
			SHookFunction(Decode2, uDecode2);
		}

		ULONG_PTR uDecode4 = r.Scan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC 14 0F B7 51 0C 8B 41 08 83 65 FC 00 53 56 8B 71 14 2B D6 57 03 C6 83 FA 04");
		if (uDecode4) {
			SHookFunction(Decode4, uDecode4);
		}

		ULONG_PTR uDecodeStr = r.Scan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC 18 53 56 57 89 65 F0 6A 01 33 FF 8B F1 5B");
		if (uDecodeStr) {
			SHookFunction(DecodeStr, uDecodeStr);
		}

		ULONG_PTR uDecodeBuffer = r.Scan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC 14 83 65 FC 00 53 56 8B F1 0F B7 46 0C");
		if (uDecodeBuffer) {
			SHookFunction(DecodeBuffer, uDecodeBuffer);
		}

		DEBUG(L"uDecode1 = " + DWORDtoString(uDecode1));
		DEBUG(L"uDecode2 = " + DWORDtoString(uDecode2));
		DEBUG(L"uDecode4 = " + DWORDtoString(uDecode4));
		DEBUG(L"uDecodeStr = " + DWORDtoString(uDecodeStr));
		DEBUG(L"uDecodeBuffer = " + DWORDtoString(uDecodeBuffer));
	}


	StartPipeClient();
	return true;
}
