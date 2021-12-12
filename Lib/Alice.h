#ifndef __ALICE_H__
#define __ALICE_H__

#include<Windows.h>
#include<commctrl.h>
#pragma comment(lib,"comctl32.lib")
#include<string>
#include<vector>


class Alice {
	// global
public:
	enum CallbackType {
		CT_UNDEFINED,
		CT_CALL,
		CT_MANUAL,
		CT_INTERRUPTION
	};

	static bool Wait();

private:
	static std::vector<HWND> window_list;
	static std::vector<Alice*> list;

	static bool DetectInvalidWindow();

	// main
private:
	HWND main_hwnd;
	std::wstring main_class_name;
	std::wstring main_window_name;
	int main_width;
	int main_height;
	HINSTANCE main_instance;

	static LRESULT CALLBACK AliceProc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
	static bool Resize(HWND hWnd, int cx, int cy);
	bool Register();
	bool UnRegister();

public:
	Alice(std::wstring wClassName, std::wstring wWindowName, int nWidth, int nHeight, HINSTANCE hInstance);
	~Alice();
	bool Run();

	// External
private:
	bool (*on_create)(Alice&);
	bool (*on_command)(Alice&, int);
	bool (*on_notify)(Alice&, int);
	bool OnCreate(Alice &a);
	bool OnCommand(Alice &a, int nIDDlgItem);
	bool OnNotify(Alice &a, int nIDDlgItem);

	decltype(DefWindowProcW) *manual_callback;
	CallbackType callback_type;

public:
	bool SetOnCreate(bool(*function)(Alice&));
	bool SetOnCommand(bool(*function)(Alice&, int));
	bool SetOnNotify(bool(*function)(Alice&, int));
	bool SetCallback(decltype(DefWindowProcW) *function, CallbackType ct);
	CallbackType GetCallbackType();
	LRESULT CALLBACK Callback(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);

	// Control
private:
	std::vector<int> control_id_list;
	std::vector<HWND> control_hwnd_list;

	bool SetFont(int nIDDlgItem);
	int AutoWidth(std::wstring wText);
public:
	// create
	bool StaticText(int nIDDlgItem, std::wstring wText, int X, int Y);
	bool Button(int nIDDlgItem, std::wstring wText, int X, int Y, int nWidth = 0);
	bool CheckBox(int nIDDlgItem, std::wstring wText, int X, int Y, UINT uCheck = BST_UNCHECKED);
	bool EditBox(int nIDDlgItem, int X, int Y, std::wstring wText = L"", int nWidth = 0);
	bool TextArea(int nIDDlgItem, int X, int Y, int nWidth, int nHeight);
	bool ListView(int nIDDlgItem, int X, int Y, int nWidth, int nHeight);
	bool ComboBox(int nIDDlgItem, int X, int Y, int nWidth);
	// do
	bool ReadOnly(int nIDDlgItem, WPARAM wParam = true);
	bool SetText(int nIDDlgItem, std::wstring wText);
	bool AddText(int nIDDlgItem, std::wstring wText);
	std::wstring GetText(int nIDDlgItem);
	UINT CheckBoxStatus(int nIDDlgItem);

	// ListView
private:
	std::vector<int> listview_id_list;
	std::vector<int> listview_previous_selected;

	int ListView_HeaderCount(int nIDDlgItem);
	bool ListView_AutoScroll(int nIDDlgItem);
	bool ListView_GetPreviousSelected(int nIDDlgItem, int &Selected);
	bool ListView_SetPreviousSelected(int nIDDlgItem, int Selected);
public:
	bool ListView_AddHeader(int nIDDlgItem, std::wstring wHeader, int Width);
	bool ListView_AddItem(int nIDDlgItem, int index, std::wstring wText);
	bool ListView_Clear(int nIDDlgItem);
	bool ListView_Copy(int nIDDlgItem, int index, std::wstring &wText, bool block = false, size_t size = 256);
};

#endif