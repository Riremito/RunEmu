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
	BUTTON_CLEAR
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


bool AddFormat(PacketData &pd, PacketEditorMessage &pem) {
	// �p�P�b�g���b�N�ς�
	if (pd.lock) {
		return false;
	}
	// �p�P�b�g��o�^
	if (pem.header == SENDPACKET || pem.header == RECVPACKET) {
		pd.packet.resize(pem.Binary.length);
		memcpy_s(&pd.packet[0], pem.Binary.length, pem.Binary.packet, pem.Binary.length);
		pd.addr = pem.addr;

		// Send�̏ꍇ�͐�ɑS��Encode����ォ��p�P�b�g�̃T�C�Y����������
		if (pd.packet.size() && pd.packet.size() == pd.used) {
			// �S�Ẵf�[�^�����p���ꂽ
			if (pd.status == 0) {
				pd.status = 1;
			}
		}

		// �p�P�b�g���b�N
		if (pem.header == SENDPACKET) {
			pd.lock = TRUE;

			// �����ɓ�f�[�^������ꍇ
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
		}
		return true;
	}

	// �p�P�b�g���b�N
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

	// �����decode or encode�o���Ă��Ȃ��ꍇ�͌����߂���
	if (pd.used < pem.Extra.pos) {
		PacketFormat unk;
		unk.type = UNKNOWNDATA;
		unk.pos = pd.used;
		unk.size = pem.Extra.pos - pd.used;
		unk.addr = 0;
		pd.format.push_back(unk);
		pd.status = -1;
	}

	// �t�H�[�}�b�g��o�^
	PacketFormat pf;
	pf.type = pem.header;
	pf.pos = pem.Extra.pos;
	pf.size = pem.Extra.size;
	pf.addr = pem.addr;
	pd.format.push_back(pf);
	
	// ��Ԃ�ύX
	pd.used += pf.size;
	// Recv�̏ꍇ�͐�Ƀp�P�b�g�̃T�C�Y���������Ă���
	if (pd.packet.size() && pd.packet.size() == pd.used) {
		// �S�Ẵf�[�^�����p���ꂽ
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

// �N���C�A���g����̃p�P�b�g�̏���
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

			// Recv�ǉ�
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

	Server(a);
	return true;
}

// �F�X�ȏ���
bool OnCommand(Alice &a, int nIDDlgItem) {
	if (nIDDlgItem == BUTTON_CLEAR) {
		a.ListView_Clear(LISTVIEW_LOGGER);
		packet_data_out.clear();
		packet_data_in.clear();
	}
	return true;
}


// ShiftJIS to UTF16
bool ShiftJIStoUTF8(std::string sjis, std::wstring &utf16) {
	// UTF16�֕ϊ�����ۂ̕K�v�ȃo�C�g�����擾
	int len = MultiByteToWideChar(CP_ACP, 0, sjis.c_str(), -1, 0, 0);
	if (!len) {
		return false;
	}

	// UTF16�֕ϊ�
	std::vector<BYTE> b((len + 1) * sizeof(WORD));
	if (!MultiByteToWideChar(CP_ACP, 0, sjis.c_str(), -1, (WCHAR *)&b[0], len)) {
		return false;
	}

	utf16 = std::wstring((WCHAR *)&b[0]);
	return true;
}

// �o�C�g�z�񂩂�ShiftJIS��������擾
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
	// �G���[����
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

	// �p�P�b�g�̏��
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
	wText += DatatoString(&pd.packet[0], pd.packet.size(), true) + L"\r\n";
	wText += L"\r\n";

	wText += L"[Format]\r\n";
	for (size_t i = 0; i < pd.format.size(); i++) {
		wText += GetFormat(pd, pd.format[i]) + L"\r\n";
	}

	return wText;
}

// ListView��őI�������p�P�b�g����͗��ɃR�s�[
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