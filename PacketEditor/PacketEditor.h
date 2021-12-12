#ifndef __PACKETEDITOR_H__
#define __PACKETEDITOR_H__

#include<Windows.h>

#pragma pack(push, 1)
enum MessageHeader {
	SENDPACKET, // stop encoding
	RECVPACKET, // start decoding
	ENCODEHEADER, // start encoding
	ENCODE1,
	ENCODE2,
	ENCODE4,
	ENCODESTR,
	ENCODEBUFFER,
	DECODEHEADER,
	DECODE1,
	DECODE2,
	DECODE4,
	DECODESTR,
	DECODEBUFFER,
	DECODEEND,
	UNKNOWNDATA, // not decoded by function
	NOTUSED, // recv not used
	WHEREFROM // not encoded by function
};
typedef struct {
	MessageHeader header;
	DWORD id;
	DWORD addr;
	union {
		// SEND or RECV
		struct {
			DWORD length; // �p�P�b�g�̃T�C�Y
			BYTE packet[1]; // �p�P�b�g
		} Binary;
		// Encode or Decode
		struct {
			DWORD pos; // Encode or Decode���ꂽ�ʒu
			DWORD size; // �T�C�Y
		} Extra;
		// Encode or Decode �����ʒm
		DWORD status; // ���
	};
} PacketEditorMessage;
#pragma pack(pop)

#endif