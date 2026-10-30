#include "injectexe.h"

namespace {

inline void close_if(HANDLE h) {
    if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h);
}

inline void free_remote(HANDLE proc, LPVOID p) {
    if (proc && p) VirtualFreeEx(proc, p, 0, MEM_RELEASE);
}
bool read_file(const char* path, std::vector<BYTE>& out) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f.is_open()) return false;
    std::streamoff sz = f.tellg();
    if (sz <= 0) return false;
    f.seekg(0);
    out.resize(static_cast<size_t>(sz));
    f.read(reinterpret_cast<char*>(out.data()), sz);
    return f.good();
}

bool validate_image(const std::vector<BYTE>& raw, PIMAGE_DOS_HEADER& dos, PIMAGE_NT_HEADERS& nt) {
	// sanity checks (im missing these irl)
    if (raw.size() < sizeof(IMAGE_DOS_HEADER)) return false;
    dos = reinterpret_cast<PIMAGE_DOS_HEADER>(const_cast<BYTE*>(raw.data()));
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    if (dos->e_lfanew < 0) return false;
    if (static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS) > raw.size()) return false;
    nt = reinterpret_cast<PIMAGE_NT_HEADERS>(const_cast<BYTE*>(raw.data()) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) return false;
    if (nt->OptionalHeader.SizeOfImage == 0) return false;
    return true;
}
bool resolve_entry_offset(const char* module_path, const char* entry_name, uintptr_t& out_offset) {
    HMODULE local = LoadLibraryA(module_path);
    if (!local) return false;
    FARPROC entry = GetProcAddress(local, entry_name);
    if (!entry) { FreeLibrary(local); return false; }
    out_offset = reinterpret_cast<uintptr_t>(entry) - reinterpret_cast<uintptr_t>(local);
    FreeLibrary(local);
    return true;
}

} // namespace


bool c_inject::attach(const char* name) {
    if (!name) return false;
    pid = 0;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32 pe{ sizeof(pe) };
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }

    CloseHandle(snap);
    return pid != 0;
}


void __stdcall c_inject::shell_loader(manual_map_data* data) {
    if (!data) return;
    if (!data->image_base || !data->nt_headers) return;

    BYTE* base = static_cast<BYTE*>(data->image_base);
    PIMAGE_NT_HEADERS nt = data->nt_headers;

    BYTE* preferred = reinterpret_cast<BYTE*>(nt->OptionalHeader.ImageBase);
    ptrdiff_t delta = base - preferred;

    if (delta && nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        auto* reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(base +
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

        while (reloc->VirtualAddress && reloc->SizeOfBlock) {
            DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* entries = reinterpret_cast<WORD*>(reloc + 1);

            for (DWORD i = 0; i < count; ++i) {
                const WORD type = entries[i] >> 12;
                const WORD off  = entries[i] & 0xFFF;
                if (type == IMAGE_REL_BASED_DIR64)
                    *reinterpret_cast<uintptr_t*>(base + reloc->VirtualAddress + off) += delta;
                else if (type == IMAGE_REL_BASED_HIGHLOW)
                    *reinterpret_cast<uint32_t*>(base + reloc->VirtualAddress + off) +=
                        static_cast<uint32_t>(delta);
            }

            reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
                reinterpret_cast<BYTE*>(reloc) + reloc->SizeOfBlock);
        }
    }

    if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        auto* import_desc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(base +
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        while (import_desc->Name) {
            HMODULE h_mod = data->fn_load_library_a( 
                reinterpret_cast<char*>(base + import_desc->Name));

            auto* orig_thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(
                base + import_desc->OriginalFirstThunk);
            auto* thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(
                base + import_desc->FirstThunk);

            while (thunk->u1.AddressOfData) {
                if (IMAGE_SNAP_BY_ORDINAL(orig_thunk->u1.Ordinal)) {
                    thunk->u1.Function = reinterpret_cast<uintptr_t>(data->fn_get_proc_address(
                        h_mod, reinterpret_cast<LPCSTR>(IMAGE_ORDINAL(orig_thunk->u1.Ordinal))));
                } else {
                    auto* ibn = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
                        base + orig_thunk->u1.AddressOfData);
                    thunk->u1.Function = reinterpret_cast<uintptr_t>(
                        data->fn_get_proc_address(h_mod, ibn->Name));
                }
                ++orig_thunk;
                ++thunk;
            }

            ++import_desc;
        }
    }

    if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
        auto* tls = reinterpret_cast<PIMAGE_TLS_DIRECTORY>(base +
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);

        auto** callbacks = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tls->AddressOfCallBacks);
        while (callbacks && *callbacks) {
            (*callbacks)(reinterpret_cast<LPVOID>(base), DLL_PROCESS_ATTACH, nullptr);
            ++callbacks;
        }
    }

    if (data->fn_dll_main)
        data->fn_dll_main(reinterpret_cast<HMODULE>(base), DLL_PROCESS_ATTACH, nullptr);
}

void c_inject::shell_loader_end() {} // we use this to mark the end of the shellcode function (theres probably better ways to do this but atm i dont gaf)


bool c_inject::manual_map(const char* target_exe, const char* entry_export) {
    if (!pid) return false;
    if (!target_exe) target_exe = "example.exe";
    if (!entry_export) entry_export = "injectexe_entry";

    std::vector<BYTE> raw;
    if (!read_file(target_exe, raw)) return false;

    PIMAGE_DOS_HEADER dos = nullptr;
    PIMAGE_NT_HEADERS nt   = nullptr;
    if (!validate_image(raw, dos, nt)) return false;

    uintptr_t entry_offset = 0;
    if (!resolve_entry_offset(target_exe, entry_export, entry_offset)) return false;

    HANDLE h_proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!h_proc) return false;

    LPVOID remote_image = VirtualAllocEx(h_proc, nullptr,
        nt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote_image) { close_if(h_proc); return false; }
	
	if (!WriteProcessMemory(h_proc, remote_image, raw.data(), nt->OptionalHeader.SizeOfHeaders, nullptr)) 
		return false;

    auto* section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
        if (!section->SizeOfRawData) continue;
        if (section->PointerToRawData + section->SizeOfRawData > raw.size()) return false;
        if (!WriteProcessMemory(proc,
                static_cast<BYTE*>(remote_image) + section->VirtualAddress,
                raw.data() + section->PointerToRawData,
                section->SizeOfRawData, nullptr)) return false;
    }
  

    auto* remote_entry = reinterpret_cast<BOOL(WINAPI*)(HMODULE, DWORD, LPVOID)>(
        reinterpret_cast<uintptr_t>(remote_image) + entry_offset);

    manual_map_data map_data{};
    map_data.image_base         = remote_image;
    map_data.nt_headers         = reinterpret_cast<PIMAGE_NT_HEADERS>(
        static_cast<BYTE*>(remote_image) + dos->e_lfanew);
    map_data.fn_load_library_a  = LoadLibraryA;
    map_data.fn_get_proc_address = GetProcAddress;
    map_data.fn_dll_main        = remote_entry;

    LPVOID remote_data = VirtualAllocEx(h_proc, nullptr, sizeof(manual_map_data),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_data) {
        free_remote(h_proc, remote_image);
        close_if(h_proc);
        return false;
    }

    if (!WriteProcessMemory(h_proc, remote_data, &map_data, sizeof(manual_map_data), nullptr)) {
        free_remote(h_proc, remote_data);
        free_remote(h_proc, remote_image);
        close_if(h_proc);
        return false;
    }

    const SIZE_T loader_size = reinterpret_cast<uintptr_t>(&c_inject::shell_loader_end) -
                               reinterpret_cast<uintptr_t>(&c_inject::shell_loader);
    if (loader_size == 0) {
        free_remote(h_proc, remote_data);
        free_remote(h_proc, remote_image);
        close_if(h_proc);
        return false;
    }

    LPVOID remote_loader = VirtualAllocEx(h_proc, nullptr, loader_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote_loader) {
        free_remote(h_proc, remote_data);
        free_remote(h_proc, remote_image);
        close_if(h_proc);
        return false;
    }

    if (!WriteProcessMemory(h_proc, remote_loader,
            reinterpret_cast<LPVOID>(&c_inject::shell_loader), loader_size, nullptr)) {
        free_remote(h_proc, remote_loader);
        free_remote(h_proc, remote_data);
        free_remote(h_proc, remote_image);
        close_if(h_proc);
        return false;
    }

    HANDLE h_thread = CreateRemoteThread(h_proc, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(remote_loader), remote_data, 0, nullptr);
    if (!h_thread) {
        free_remote(h_proc, remote_loader);
        free_remote(h_proc, remote_data);
        free_remote(h_proc, remote_image);
        close_if(h_proc);
        return false;
    }

    WaitForSingleObject(h_thread, 5000);
    close_if(h_thread);

    free_remote(h_proc, remote_loader);
    free_remote(h_proc, remote_data);
    close_if(h_proc);
    return true;
}
