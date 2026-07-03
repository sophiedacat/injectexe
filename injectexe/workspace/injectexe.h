#pragma once
#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <fstream>
#include <vector>
// made by ellii <3

class c_inject {
	struct manual_map_data {
		LPVOID  image_base;
		PIMAGE_NT_HEADERS nt_headers;
		HMODULE(WINAPI* fn_load_library_a)(LPCSTR);
		FARPROC(WINAPI* fn_get_proc_address)(HMODULE, LPCSTR);
		BOOL(WINAPI* fn_dll_main)(HMODULE, DWORD, LPVOID);
	};
	// our shellcode
	static void __stdcall shell_loader(manual_map_data* data);

	// this is required to get the size of our shellcode <3
	static void shell_loader_end();

public:
	DWORD pid;
	bool attatch(const char* name);

	bool manual_map();
};
