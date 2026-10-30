#include <Windows.h>
#include <thread>

extern "C" __declspec(dllexport) BOOL WINAPI injectexe_entry(HMODULE h_module, DWORD ul_reason_for_call, LPVOID lp_reserved) {
	if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
		DisableThreadLibraryCalls(h_module);
		const char* sponsor_msg =
		    "Today's video is sponsored by Raid Shadow Legends, one of the biggest mobile role-playing games of 2019 and it's totally free!\n"
		    "Currently almost 10 million users have joined Raid over the last six months, and it's one of the most impressive games in its class with detailed models, environments and smooth 60 frames per second animations!\n"
		    "All the champions in the game can be customized with unique gear that changes your strategic buffs and abilities!\n"
		    "The dungeon bosses have some ridiculous skills of their own and figuring out the perfect party and strategy to overtake them's a lot of fun!\n"
		    "Currently with over 300,000 reviews, Raid has almost a perfect score on the Play Store!\n"
		    "The community is growing fast and the highly anticipated new faction wars feature is now live, you might even find my squad out there in the arena!\n"
		    "It's easier to start now than ever with rates program for new players you get a new daily login reward for the first 90 days that you play in the game!\n"
		    "So what are you waiting for?\n"
		    "Go to the video description, click on the special links and you'll get 50,000 silver and a free epic champion as part of the new player program to start your journey!\n"
		    "Good luck and I'll see you there!";
				
		std::thread(
		    MessageBoxA,
		    nullptr,
		    sponsor_msg,
		    "telepathy",
		    MB_OK | MB_ICONINFORMATION
		).detach();
	}
	return TRUE;
}

int main() {

}
