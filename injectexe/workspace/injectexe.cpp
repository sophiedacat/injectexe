
#include "injectexe.h"

bool c_inject::attatch(const char* name) {
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap == INVALID_HANDLE_VALUE) return 0;

	PROCESSENTRY32 pe{ sizeof(pe) };


	if (Process32First(snap, &pe)) {
		do {
		
			if (_stricmp(pe.szExeFile, name) == 0) {
				this->pid = pe.th32ProcessID;
				break;
			}
		} while (Process32Next(snap, &pe));
	}

	CloseHandle(snap);
	return this->pid != 0;
}

void __stdcall c_inject::shell_loader(manual_map_data* data) {
	if (!data) return;

	BYTE* base = (BYTE*)data->image_base;
	PIMAGE_NT_HEADERS nt = data->nt_headers;

	BYTE* preferred = (BYTE*)nt->OptionalHeader.ImageBase;
	ptrdiff_t delta = base - preferred;

	if (delta && nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
		auto* reloc = (PIMAGE_BASE_RELOCATION)(base +
			nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

		while (reloc->VirtualAddress) {
			DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			WORD* entries = (WORD*)(reloc + 1);

			for (DWORD i = 0; i < count; i++) {
				if ((entries[i] >> 12) == IMAGE_REL_BASED_DIR64)
					*(uintptr_t*)(base + reloc->VirtualAddress + (entries[i] & 0xFFF)) += delta;
			}

			reloc = (PIMAGE_BASE_RELOCATION)((BYTE*)reloc + reloc->SizeOfBlock);
		}
	}

	if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		auto* import_desc = (PIMAGE_IMPORT_DESCRIPTOR)(base +
			nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		while (import_desc->Name) {
			HMODULE h_mod = data->fn_load_library_a((char*)(base + import_desc->Name));

			auto* orig_thunk = (PIMAGE_THUNK_DATA)(base + import_desc->OriginalFirstThunk);
			auto* thunk = (PIMAGE_THUNK_DATA)(base + import_desc->FirstThunk);

			while (thunk->u1.AddressOfData) {
				if (IMAGE_SNAP_BY_ORDINAL(orig_thunk->u1.Ordinal)) {
					thunk->u1.Function = (uintptr_t)data->fn_get_proc_address(
						h_mod, (LPCSTR)IMAGE_ORDINAL(orig_thunk->u1.Ordinal));
				}
				else {
					auto* ibn = (PIMAGE_IMPORT_BY_NAME)(base + orig_thunk->u1.AddressOfData);
					thunk->u1.Function = (uintptr_t)data->fn_get_proc_address(h_mod, ibn->Name);
				}
				orig_thunk++;
				thunk++;
			}

			import_desc++;
		}
	}

	if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
		auto* tls = (PIMAGE_TLS_DIRECTORY)(base +
			nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);

		auto** callbacks = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;
		while (callbacks && *callbacks) {
			(*callbacks)((LPVOID)base, DLL_PROCESS_ATTACH, nullptr);
			callbacks++;
		}
	}

	if (data->fn_dll_main)
		data->fn_dll_main((HMODULE)base, DLL_PROCESS_ATTACH, nullptr);
}

void c_inject::shell_loader_end() {}


bool c_inject::manual_map() {

	std::ifstream file("example.exe", std::ios::binary | std::ios::ate);
	if (!file.is_open()) return false;

	size_t file_size = (size_t)file.tellg();
	file.seekg(0);
	std::vector<BYTE> raw(file_size);
	file.read((char*)raw.data(), file_size);
	file.close();

	auto* dos = (PIMAGE_DOS_HEADER)raw.data();
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

	auto* nt = (PIMAGE_NT_HEADERS)(raw.data() + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

	HANDLE h_proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!h_proc) return false;
	LPVOID remote_image = VirtualAllocEx(h_proc, nullptr,
		nt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!remote_image) {
		CloseHandle(h_proc);
		return false;
	}

	WriteProcessMemory(h_proc, remote_image, raw.data(), nt->OptionalHeader.SizeOfHeaders, nullptr);

	auto* section = IMAGE_FIRST_SECTION(nt);
	for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, section++) {
		if (!section->SizeOfRawData) continue;
		WriteProcessMemory(h_proc,
			(BYTE*)remote_image + section->VirtualAddress,
			raw.data() + section->PointerToRawData,
			section->SizeOfRawData, nullptr);
	}

	HMODULE local_base = LoadLibraryA("example.exe"); 
	FARPROC local_entry = GetProcAddress(local_base, "injectexe_entry"); // can also be set to main to inject the entrypoint of any valid c++ app
	if (!local_entry) {
		VirtualFreeEx(h_proc, remote_image, 0, MEM_RELEASE);
		CloseHandle(h_proc);
		return false;
	}

	uintptr_t entry_offset = (uintptr_t)local_entry - (uintptr_t)local_base;

	BOOL(WINAPI * remote_entry)(HMODULE, DWORD, LPVOID) =
		(BOOL(WINAPI*)(HMODULE, DWORD, LPVOID))((uintptr_t)remote_image + entry_offset);


	manual_map_data map_data{};
	map_data.image_base = remote_image;
	map_data.nt_headers = (PIMAGE_NT_HEADERS)((BYTE*)remote_image + dos->e_lfanew);
	map_data.fn_load_library_a = LoadLibraryA;
	map_data.fn_get_proc_address = GetProcAddress;
	map_data.fn_dll_main = remote_entry;

	LPVOID remote_data = VirtualAllocEx(h_proc, nullptr, sizeof(manual_map_data),
		MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!remote_data) {
		VirtualFreeEx(h_proc, remote_image, 0, MEM_RELEASE);
		CloseHandle(h_proc);
		return false;
	}

	WriteProcessMemory(h_proc, remote_data, &map_data, sizeof(manual_map_data), nullptr);

	SIZE_T loader_size = (uintptr_t)shell_loader_end - (uintptr_t)shell_loader;
	LPVOID remote_loader = VirtualAllocEx(h_proc, nullptr, loader_size,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!remote_loader) {
		VirtualFreeEx(h_proc, remote_data, 0, MEM_RELEASE);
		VirtualFreeEx(h_proc, remote_image, 0, MEM_RELEASE);
		CloseHandle(h_proc);
		return false;
	}

	WriteProcessMemory(h_proc, remote_loader, (LPVOID)shell_loader, loader_size, nullptr);

	HANDLE h_thread = CreateRemoteThread(h_proc, nullptr, 0,
		(LPTHREAD_START_ROUTINE)remote_loader, remote_data, 0, nullptr);

	if (!h_thread) {
		VirtualFreeEx(h_proc, remote_loader, 0, MEM_RELEASE);
		VirtualFreeEx(h_proc, remote_data, 0, MEM_RELEASE);
		VirtualFreeEx(h_proc, remote_image, 0, MEM_RELEASE);
		CloseHandle(h_proc);
		return false;
	}

	WaitForSingleObject(h_thread, 5000);
	CloseHandle(h_thread);

	VirtualFreeEx(h_proc, remote_loader, 0, MEM_RELEASE);
	VirtualFreeEx(h_proc, remote_data, 0, MEM_RELEASE);
	CloseHandle(h_proc);
	return true;
}