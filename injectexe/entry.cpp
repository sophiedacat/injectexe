#include "workspace/injectexe.h"

// poc of "injecting an exe"
// how it works
// its a normal manual mapper but instead of mapping an entire file we map 2 things
// 1. the function that we want to inject from another exe
// 2. the shellcode loader to call said function

// how would you get this to work for any process:
// change the shellcode loader to call a function with 0 args (you can ignore the ret value)
// set the function resolver to resolve "main" instead of "injectexe_entry"
// move the code you want to run in the injected process inside of main instead of the entry
// viola :)

c_inject* inj = new c_inject();

int main() {
	SetConsoleTitleA("injectexe | discord: .h6rny.");

	HWND console_window = GetConsoleWindow();
	SetLayeredWindowAttributes(console_window, 0, 235, LWA_ALPHA);

	SetWindowLongA(console_window, GWL_STYLE,
		GetWindowLongA(console_window, GWL_STYLE) & ~WS_MAXIMIZEBOX & ~WS_SIZEBOX & ~WS_MINIMIZEBOX & ~WS_EX_RIGHTSCROLLBAR);


	const char* target_process = "notepad.exe";

	if (!inj->attatch(target_process)) {
		__fastfail(67);
	}

	if (!inj->manual_map()) {
		printf("getlasterror %i\n", GetLastError());
	}

	std::cin.get();

	return 0;
}