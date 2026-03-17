#include <iostream>
#include <NtCallExt.h>

using namespace MemX;

int main() {
	DWORD64 ntdllBase = NtCallExt.GetSyscallNumber64(NtCallExt.GetNtdll64(), "NtClose"); //get ntdll base by a known function
	std::cout << "ntdll.dll base: 0x" << std::hex << ntdllBase << std::endl;
	system("pause");
    return 0;
}