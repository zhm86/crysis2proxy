#include <Windows.h>
#include <assert.h>

#include <stdio.h>

#include "CDetour.h"

#include "crc32.h"

#define EXE_BASE_ADDRESS 0x400000

DWORD* debug_print(DWORD* a1, const char* fmt, ...) {
	
	char buffer[1024];

	va_list args;
	va_start(args, fmt);
	vsprintf_s(buffer, sizeof(buffer), fmt, args);
	va_end(args);
	OutputDebugString(buffer);

	return a1;
}

//0x6C67E0 = decrypt
int __fastcall sakeDecrypt(void *that, uint8_t* input, uint32_t num_bytes, uint8_t* output) {
	int (*sakeDecrypt_real)(void *, uint8_t *, uint32_t, uint8_t *) = (int  (*)(void*, uint8_t*, uint32_t, uint8_t*))(0x6C67E0);
	char buffer[1024];
	sprintf_s(buffer, sizeof(buffer), "sakeDecrypt: %p %p %d %p\n", that, input, num_bytes, output);
	OutputDebugString(buffer);
	return sakeDecrypt_real(that, input, num_bytes, output);
	//char buffer[1024];
	//sprintf_s(buffer, sizeof(buffer), "sakeDecrypt: %p %d %p\n", input, num_bytes, output);
	//OutputDebugString(buffer);
	//uint8_t* p = output;
	//for (int i = 0; i < num_bytes; i++) {
	//	*p = *input;
	//	input++;
	//	p++;
	//}
	//return num_bytes;
}

void write_string_offset(void* address, int string_len, const char* string) {

	void* write_address = (void*)((ptrdiff_t)(ptrdiff_t)address);
	DWORD oldProtect;

	BOOL success = VirtualProtect(write_address, string_len, PAGE_READWRITE, &oldProtect);


	assert(success);
	SIZE_T numWritten = 0;
	success = WriteProcessMemory(GetCurrentProcess(), write_address, string, string_len, &numWritten);
	assert(success);

	DWORD protect;
	success = VirtualProtect(write_address, string_len, oldProtect, &protect);

	assert(success);

}
void perform_crysis2_patches() {
	write_string_offset((void*)0x1721470, 17, "gpsp.openspy.net"); //updated
	write_string_offset((void*)0x1721430, 17, "gpcm.openspy.net"); //updated
	write_string_offset((void*)0x016DFA7C, 25, "%s.available.openspy.net"); //updated
	write_string_offset((void*)0x16E0DDC, 20, "%s.ms%d.openspy.net"); //updated

	write_string_offset((void*)0x16DF14C, 20, "natneg1.openspy.net");
	write_string_offset((void*)0x16DF160, 20, "natneg2.openspy.net");
	write_string_offset((void*)0x16DF174, 20, "natneg3.openspy.net");
	write_string_offset((void*)0x16DFE70, 21, "peerchat.openspy.net");

	
	write_string_offset((void*)0x016E1000, 9, "http://\0");
	write_string_offset((void*)0x016E0FD8, 40, "%s.d2g.pubsvs.openspy.net/commerce/1.1/");

	write_string_offset((void*)0x16E1C90, 64, "http://%s.sake.openspy.net/SakeStorageServer/StorageServer.asmx"); //updated
	write_string_offset((void*)0x16DFB18, 22, "%s.master.openspy.net"); //updated 
	write_string_offset((void*)0x16DFA9C, 22, "http://motd.openspy.net/motd/motd.asp"); //updated

	write_string_offset((void*)0x16DF8C8, 64, "http://%s.auth.pubsvs.openspy.net/AuthService/AuthService.asmx\x00"); //updated

	write_string_offset((void*)0x016DF7B8, 257, "afb5818995b3708d0656a5bdd20760aee76537907625f6d23f40bf17029e56808d36966c0804e1d797e310fedd8c06e6c4121d963863d765811fc9baeb2315c9a6eaeb125fad694d9ea4d4a928f223d9f4514533f18a5432dd0435c5c6ac8e276cf29489cb5ac880f16b0d7832ee927d4e27d622d6a450cd1560d7fa882c6c13"); //updated

	CDetour detour;

	//if (detour.Create((BYTE*)0x0046D350, (const BYTE*)debug_print, DETOUR_TYPE_JMP, 5) == 0) {
	//	OutputDebugString("Failed to detour debugPrint (#1)");
	//	::ExitProcess(0); // exit the hard way
	//}

	//if (detour.Create((BYTE*)0x006CF4DB, (const BYTE*)sakeDecrypt, DETOUR_TYPE_CALL_FUNC, 5) == 0) {
	//	OutputDebugString("Failed to detour sakeDecypt (#1)");
	//	::ExitProcess(0); // exit the hard way
	//}
}