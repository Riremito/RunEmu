#include"../Lib/Alice.h"
#pragma comment(lib, "../Lib/Alice.lib")
#include"../Lib/Pipe.h"
#pragma comment(lib, "../Lib/Pipe.lib")
#include"Debug.h"
#include"PacketEditor.h"

// Pipe from Client
bool Communicate(PipeServerThread& psh);

bool RunPipeServer() {
	PipeServer ps(L"PacketEditor");
	ps.SetCommunicate(Communicate);
	return ps.Run();
}

bool Server(Alice &a) {
	HANDLE hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)RunPipeServer, NULL, NULL, NULL);
	if (!hThread) {
		return false;
	}
	CloseHandle(hThread);
	return true;
}

// gui
Alice *ga = NULL;

enum SubControl {
	LISTVIEW_LOGGER,
	EDIT_EXTRA,
	CHECK_LOG,
	BUTTON_CLEAR,
	BUTTON_EXPORT
};


typedef struct {
	DWORD addr;
	MessageHeader type;
	DWORD pos;
	DWORD size;
} PacketFormat;

typedef struct {
	DWORD addr;
	DWORD id;
	MessageHeader type;
	std::vector<BYTE> packet;
	std::vector<PacketFormat> format;
	int status;
	DWORD used;
	BOOL lock;
} PacketData;

std::vector<PacketData> packet_data_out;
std::vector<PacketData> packet_data_in;


std::wstring GetExtraInfo(PacketData &pd);

// UTF16 to SJIS
bool ShiftJIStoUTF8(std::wstring utf16, std::string &sjis) {
	// UTF16へ変換する際の必要なバイト数を取得
	int len = WideCharToMultiByte(CP_ACP, 0, utf16.c_str(), -1, 0, 0, 0, 0);
	if (!len) {
		return false;
	}

	std::vector<BYTE> b(len + 1);

	if (!WideCharToMultiByte(CP_ACP, 0, utf16.c_str(), -1, (char *)&b[0], len, 0, 0)) {
		return false;
	}

	sjis = std::string((char *)&b[0]);
	return true;
}

bool ExportPacket() {
	SYSTEMTIME st = { 0 };
	GetLocalTime(&st);

	std::wstring wDir = L"plog";
	WCHAR date[256] = { 0 };
	swprintf_s(date, L"%04d%02d%02d_%02d%02d%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
	std::wstring wOutFile = wDir + L"/";
	wOutFile += date;
	wOutFile += L"_export_out.txt";
	std::wstring wInFile = wDir + L"/";
	wInFile += date;
	wInFile += L"_export_in.txt";
	std::string newline = "===================\r\n";

	CreateDirectoryW(wDir.c_str(), NULL);

	/*
	HANDLE hFile = CreateFileW(wOutFile.c_str(), GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD wb = 0;

	if (hFile != INVALID_HANDLE_VALUE) {
		for (size_t i = 0; i < packet_data_out.size(); i++) {
			DEBUG(L"EX...");
			std::wstring wText = GetExtraInfo(packet_data_out[i]);
			DEBUG(L"wru...");
			WriteFile(hFile, newline.c_str(), newline.length(), &wb, NULL);
			std::string text;
			DEBUG(L"testing...");
			if (!ShiftJIStoUTF8(wText, text)) {
				text = "ERROR";
			}
			DEBUG(L"OK");
			if (text.length()) {
				WriteFile(hFile, text.c_str(), text.length(), &wb, NULL);
			}
		}
		CloseHandle(hFile);
	}
	*/

	FILE *fp = NULL;
	_wfopen_s(&fp, wOutFile.c_str(), L"wb");

	if (fp) {
		for (size_t i = 0; i < packet_data_out.size(); i++) {
			std::wstring wText = GetExtraInfo(packet_data_out[i]);
			fwrite(newline.c_str(), 1, newline.length(), fp);
			std::string text;
			if (!ShiftJIStoUTF8(wText, text)) {
				text = "ERROR";
			}
			if (text.length()) {
				fwrite(text.c_str(), 1, text.length(), fp);
			}
		}
		fclose(fp);
	}

	fp = NULL;
	_wfopen_s(&fp, wInFile.c_str(), L"wb");
	if (fp) {
		for (size_t i = 0; i < packet_data_in.size(); i++) {
			std::wstring wText = GetExtraInfo(packet_data_in[i]);
			fwrite(newline.c_str(), 1, newline.length(), fp);
			std::string text;
			if (!ShiftJIStoUTF8(wText, text)) {
				text = "ERROR";
			}
			fwrite(text.c_str(), 1, text.length(), fp);
		}
		fclose(fp);
	}

	return true;
}

// ログインパケットのパスワードを消す
bool RemovePassword(PacketData &pd) {
	if (pd.packet.size() < 2) {
		return false;
	}

	if (*(WORD *)&pd.packet[0] != 0x0001) {
		return false;
	}

	for (size_t i = 0; i < pd.format.size(); i++) {
		if (pd.format[i].type == ENCODESTR) {
			for (size_t j = 0; j < *(WORD *)&pd.packet[pd.format[i].pos]; j++) {
				*(BYTE *)&pd.packet[pd.format[i].pos + 2 + j] = '*';
			}
		}
	}

	return true;
}


bool AddFormat(PacketData &pd, PacketEditorMessage &pem) {
	// パケットロック済み
	if (pd.lock) {
		return false;
	}
	// パケットを登録
	if (pem.header == SENDPACKET || pem.header == RECVPACKET) {
		pd.packet.resize(pem.Binary.length);
		memcpy_s(&pd.packet[0], pem.Binary.length, pem.Binary.packet, pem.Binary.length);
		pd.addr = pem.addr;

		// Sendの場合は先に全てEncodeされ後からパケットのサイズが判明する
		if (pd.packet.size() && pd.packet.size() == pd.used) {
			// 全てのデータが利用された
			if (pd.status == 0) {
				pd.status = 1;
			}
		}

		// パケットロック
		if (pem.header == SENDPACKET) {
			pd.lock = TRUE;

			// 末尾に謎データがある場合
			if (pd.used < pd.packet.size()) {
				PacketFormat unk;
				unk.type = WHEREFROM;
				unk.pos = pd.used;
				unk.size = pd.packet.size() - pd.used;
				unk.addr = 0;
				pd.format.push_back(unk);
				pd.status = -1;
			}
			else {
				pd.status = 1;
			}

			// ログインパケットのパスワードを消す
			RemovePassword(pd);
		}
		return true;
	}

	// パケットロック
	if (pem.header == DECODEEND) {
		pd.lock = TRUE;
		if (pd.used < pd.packet.size()) {
			PacketFormat unk;
			unk.type = NOTUSED;
			unk.pos = pd.used;
			unk.size = pd.packet.size() - pd.used;
			unk.addr = 0;
			pd.format.push_back(unk);
			pd.status = -1;
		}
		return true;
	}

	// 正常にdecode or encode出来ていない場合は穴埋めする
	if (pd.used < pem.Extra.pos) {
		PacketFormat unk;
		unk.type = UNKNOWNDATA;
		unk.pos = pd.used;
		unk.size = pem.Extra.pos - pd.used;
		unk.addr = 0;
		pd.format.push_back(unk);
		pd.status = -1;
		pd.used += unk.size;
		return false;
	}

	// フォーマットを登録
	PacketFormat pf;
	pf.type = pem.header;
	pf.pos = pem.Extra.pos;
	pf.size = pem.Extra.size;
	pf.addr = pem.addr;
	pd.format.push_back(pf);
	
	// 状態を変更
	pd.used += pf.size;
	// Recvの場合は先にパケットのサイズが分かっている
	if (pd.packet.size() && pd.packet.size() == pd.used) {
		// 全てのデータが利用された
		if (pd.status == 0) {
			pd.status = 1;
		}
	}
	return true;
}

bool AddRecvPacket(PacketEditorMessage &pem) {
	for (size_t i = 0; i < packet_data_in.size(); i++) {
		if (packet_data_in[i].id == pem.id) {
			AddFormat(packet_data_in[i], pem);
			return false;
		}
	}

	PacketData pd;
	pd.id = pem.id;
	pd.type = RECVPACKET;
	pd.status = 0;
	pd.used = 0;
	pd.lock = FALSE;
	AddFormat(pd, pem);
	packet_data_in.push_back(pd);
	return true;
}

bool AddSendPacket(PacketEditorMessage &pem) {
	for (size_t i = 0; i < packet_data_out.size(); i++) {
		if (packet_data_out[i].id == pem.id) {
			AddFormat(packet_data_out[i], pem);
			return false;
		}
	}

	PacketData pd;
	pd.id = pem.id;
	pd.type = SENDPACKET;
	pd.status = 0;
	pd.used = 0;
	pd.lock = FALSE;
	AddFormat(pd, pem);
	packet_data_out.push_back(pd);
	return true;
}

// クライアントからのパケットの処理
bool Communicate(PipeServerThread& psh) {
	Alice &a = *ga;
	a.SetText(EDIT_EXTRA, L"Connected");

	std::vector<BYTE> data;
	while (psh.Recv(data)) {
		PacketEditorMessage &pem = (PacketEditorMessage&)data[0];

		if (!a.CheckBoxStatus(CHECK_LOG)) {
			continue;
		}

		if (pem.header == SENDPACKET) {
			a.ListView_AddItem(LISTVIEW_LOGGER, 0, L"Send");
			a.ListView_AddItem(LISTVIEW_LOGGER, 1, std::to_wstring(pem.id));
			a.ListView_AddItem(LISTVIEW_LOGGER, 2, std::to_wstring(pem.Binary.length));
			std::wstring wpacket = DatatoString(pem.Binary.packet, (pem.Binary.length > 1024) ? 1024 : pem.Binary.length, true);
			a.ListView_AddItem(LISTVIEW_LOGGER, 3, wpacket);

			AddSendPacket(pem);
			continue;
		}
		if (pem.header == RECVPACKET) {
			a.ListView_AddItem(LISTVIEW_LOGGER, 0, L"Recv");
			a.ListView_AddItem(LISTVIEW_LOGGER, 1, std::to_wstring(pem.id));
			a.ListView_AddItem(LISTVIEW_LOGGER, 2, std::to_wstring(pem.Binary.length));
			std::wstring wpacket = DatatoString(pem.Binary.packet, (pem.Binary.length > 1024) ? 1024 : pem.Binary.length, true);
			a.ListView_AddItem(LISTVIEW_LOGGER, 3, wpacket);

			// Recv追加
			AddRecvPacket(pem);
			continue;
		}

		if (ENCODEHEADER <= pem.header && pem.header <= ENCODEBUFFER) {
			AddSendPacket(pem);
			continue;
		}

		if (DECODEHEADER <= pem.header && pem.header <= DECODEBUFFER) {
			AddRecvPacket(pem);
			continue;
		}

		if (pem.header == DECODEEND) {
			AddRecvPacket(pem);
			continue;
		}
	}

	a.SetText(EDIT_EXTRA, L"Disconnected");
	return true;
}

bool OnCreate(Alice &a) {
	a.ListView(LISTVIEW_LOGGER, 3, 3, 794, 294);
	a.ListView_AddHeader(LISTVIEW_LOGGER, L"Type", 40);
	a.ListView_AddHeader(LISTVIEW_LOGGER, L"ID", 40);
	a.ListView_AddHeader(LISTVIEW_LOGGER, L"Length", 50);
	a.ListView_AddHeader(LISTVIEW_LOGGER, L"Packet", 650);
	a.TextArea(EDIT_EXTRA, 3, 300 + 30, 794, 294 - 30);
	a.ReadOnly(EDIT_EXTRA);
	a.CheckBox(CHECK_LOG, L"Logging", 700, 310, BST_CHECKED);
	a.Button(BUTTON_CLEAR, L"Clear", 600, 310);
	a.Button(BUTTON_EXPORT, L"Export", 500, 310);

	Server(a);
	return true;
}

// 色々な処理
bool OnCommand(Alice &a, int nIDDlgItem) {
	if (nIDDlgItem == BUTTON_CLEAR) {
		a.ListView_Clear(LISTVIEW_LOGGER);
		packet_data_out.clear();
		packet_data_in.clear();
		return true;
	}

	if (nIDDlgItem == BUTTON_EXPORT) {
		ExportPacket();
		a.SetText(EDIT_EXTRA, L"Exported!");
		return true;
	}
	return true;
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

std::wstring GetFormat(PacketData &pd, PacketFormat &fmt) {
	std::wstring wText;

	wText = DWORDtoString(fmt.addr) + (((int)fmt.pos >= 0) ? L" +" : L" ") + std::to_wstring((int)fmt.pos) + L" ";

	switch (fmt.type) {
	case ENCODEHEADER:
	{
		wText += L"Header\r\n\t";
		wText += WORDtoString(*(WORD *)&pd.packet[fmt.pos]);
		break;
	}
	case ENCODE1:
	{
		wText += L"BYTE\r\n\t";
		wText += BYTEtoString(*(BYTE *)&pd.packet[fmt.pos]);
		break;
	}
	case ENCODE2:
	{
		wText += L"WORD\r\n\t";
		wText += WORDtoString(*(WORD *)&pd.packet[fmt.pos]);
		break;
	}
	case ENCODE4:
	{
		wText += L"DWORD\r\n\t";
		wText += DWORDtoString(*(DWORD *)&pd.packet[fmt.pos]);
		break;
	}
	case ENCODESTR:
	{
		wText += L"Str(" + std::to_wstring(fmt.size - sizeof(WORD)) + L")\r\n\t";
		std::string sjis;
		std::wstring utf16;
		if (BYTEtoShiftJIS((BYTE *)&pd.packet[fmt.pos + sizeof(WORD)], *(WORD *)&pd.packet[fmt.pos], sjis) && ShiftJIStoUTF8(sjis, utf16)) {
			wText += L"\"" + utf16 + L"\"";
		}
		else {
			wText += L"ERROR!";
		}
		break;
	}
	case ENCODEBUFFER:
	{
		wText += L"Buffer(" + std::to_wstring(fmt.size - sizeof(WORD)) + L")\r\n\t";
		wText += L"\'" + DatatoString(&pd.packet[fmt.pos + sizeof(WORD)], fmt.size) + L"\'";
		break;
	}
	case DECODEHEADER:
	{
		wText += L"Header\r\n\t";
		wText += WORDtoString(*(WORD *)&pd.packet[fmt.pos]);
		break;
	}
	case DECODE1:
	{
		wText += L"BYTE\r\n\t";
		wText += BYTEtoString(*(BYTE *)&pd.packet[fmt.pos]);
		break;
	}
	case DECODE2:
	{
		wText += L"WORD\r\n\t";
		wText += WORDtoString(*(WORD *)&pd.packet[fmt.pos]);
		break;
	}
	case DECODE4:
	{
		wText += L"DWORD\r\n\t";
		wText += DWORDtoString(*(DWORD *)&pd.packet[fmt.pos]);
		break;
	}
	case DECODESTR:
	{
		wText += L"Str(" + std::to_wstring(fmt.size - sizeof(WORD)) + L")\r\n\t";
		std::string sjis;
		std::wstring utf16;
		if (BYTEtoShiftJIS((BYTE *)&pd.packet[fmt.pos + sizeof(WORD)], *(WORD *)&pd.packet[fmt.pos], sjis) && ShiftJIStoUTF8(sjis, utf16)) {
			wText += L"\"" + utf16 + L"\"";
		}
		else {
			wText += L"ERROR!";
		}
		break;
	}
	case DECODEBUFFER:
	{
		wText += L"Buffer(" + std::to_wstring(fmt.size) + L")\r\n\t";
		wText += L"\'" + DatatoString(&pd.packet[fmt.pos], fmt.size) + L"\'";
		break;
	}
	// エラー処理
	case NOTUSED: {
		wText += L"NotUsed(" + std::to_wstring(fmt.size) + L")\r\n\t";
		wText += DatatoString(&pd.packet[fmt.pos], fmt.size, true);
		break;
	}
	case UNKNOWNDATA: {
		wText += L"UnknownFormat(" + std::to_wstring(fmt.size) + L")\r\n\t";
		wText += DatatoString(&pd.packet[fmt.pos], fmt.size, true);
		break;
	}
	case WHEREFROM: {
		wText += L"NotEncoded(" + std::to_wstring(fmt.size) + L")\r\n\t";
		wText += DatatoString(&pd.packet[fmt.pos], fmt.size, true);
		break;
	}
	}

	return wText;
}

std::wstring GetExtraInfo(PacketData &pd) {
	std::wstring wText;

	// パケットの状態
	wText += L"[Packet Status]\r\n";
	//wText += L"\tLock = " + std::to_wstring(pd.lock) + L"\r\n";
	wText += L"\tStatus = ";
	if (pd.status == 1) {
		wText += L"OK";
	}
	if (pd.status == 0) {
		wText += L"Wait";
	}
	if (pd.status == -1) {
		wText += L"NG";
	}
	wText += L"\r\n\r\n";

	if (pd.type == SENDPACKET) {
		wText += L"[SendPacket]\r\n";
	}
	else {
		wText += L"[RecvPacket]\r\n";
	}

	wText += L"ret = " + DWORDtoString(pd.addr) + L"\r\n";
	wText += L"length = " + std::to_wstring((int)pd.packet.size()) + L"\r\n";
	if (pd.packet.size()) {
		wText += DatatoString(&pd.packet[0], pd.packet.size(), true) + L"\r\n";
	}
	else {
		wText += L"ERROR";
	}
	wText += L"\r\n";

	wText += L"[Format]\r\n";
	if (pd.packet.size() >= 2) {
		for (size_t i = 0; i < pd.format.size(); i++) {
			wText += GetFormat(pd, pd.format[i]) + L"\r\n";
		}
	}
	else {
		wText += L"ERROR\r\n";
	}

	return wText;
}

// ListView上で選択したパケットを入力欄にコピー
bool OnNotify(Alice &a, int nIDDlgItem) {
	if (nIDDlgItem == LISTVIEW_LOGGER) {
		std::wstring text_type;
		std::wstring text_id;
		bool check = true;

		check &= a.ListView_Copy(LISTVIEW_LOGGER, 0, text_type, false);
		check &= a.ListView_Copy(LISTVIEW_LOGGER, 1, text_id, true);

		if (!check) {
			return false;
		}

		DWORD id = _wtoi(text_id.c_str());

		if (text_type.compare(L"Send") == 0) {
			for (size_t i = 0; i < packet_data_out.size(); i++) {
				if (packet_data_out[i].id == id) {
					a.SetText(EDIT_EXTRA, GetExtraInfo(packet_data_out[i]));
					return true;
				}
			}
			return true;
		}
		if (text_type.compare(L"Recv") == 0) {
			for (size_t i = 0; i < packet_data_in.size(); i++) {
				if (packet_data_in[i].id == id) {
					a.SetText(EDIT_EXTRA, GetExtraInfo(packet_data_in[i]));
					return true;
				}
			}
			return true;
		}

		return false;
	}
	return true;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
	Alice a(L"PacketEditorClass", L"PacketEditor", 800, 600, hInstance);
	a.SetOnCreate(OnCreate);
	a.SetOnCommand(OnCommand);
	a.SetOnNotify(OnNotify);
	a.Run();
	ga = &a;
	a.Wait();
	return 0;
}