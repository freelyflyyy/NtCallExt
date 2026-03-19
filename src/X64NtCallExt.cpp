#include "X64NtCallExt.h"

namespace MemX {
	DWORD64 NTAPI X64NtCallExt::GetProcAddress64(DWORD64 hMod, const char* funcName) {
		if ( !hMod || !funcName ) {
			return 0;
		}
		return (DWORD64) GetProcAddress((HMODULE) hMod, funcName);
	}

	DWORD64 X64NtCallExt::GetSyscallNumber64(DWORD64 hMod, const char* funcName) {
		if ( !hMod || !funcName ) return 0;
		DWORD64 funcAddr64 = GetProcAddress64(hMod, funcName);
		if ( !funcAddr64 ) return 0;

		//check the function addr was hooked
		auto CheckHook = [this] (DWORD64& funcAddr) -> WORD {
			BYTE* opcodes = (BYTE*) funcAddr;
			if ( opcodes[ 0 ] == 0x4C && opcodes[ 1 ] == 0x8B && opcodes[ 2 ] == 0xD1 && opcodes[ 3 ] == 0xB8 ) {
				return opcodes[ 5 ] << 8 | opcodes[ 4 ];
			}
			return 0;
		};

		auto _seachImpl = [CheckHook] (auto&& self, DWORD64 upAddr, DWORD64 downAddr, WORD depth = 0) -> WORD {
			if ( depth >= 500 ) return 0;

			WORD upSSN = CheckHook(upAddr);
			WORD downSSN = CheckHook(downAddr);

			if ( upSSN != 0 && downSSN != 0 ) {
				if ( downSSN - upSSN == depth * 2 ) {
					return upSSN + depth;
				}
			}
			return self(self, upAddr - 0x20, downAddr + 0x20, depth + 1);
		};

		//check the function self was hooked
		WORD baseSSN = CheckHook(funcAddr64);
		if ( baseSSN != 0 ) {
			return baseSSN;
		}

		return _seachImpl(_seachImpl, funcAddr64 - 0x20, funcAddr64 + 0x20, 1);
	}

	DWORD64 NTAPI X64NtCallExt::GetModuleLdrEntry64(const wchar_t* moduleName) {
		if ( !moduleName ) return 0;
		PEB64* _peb64 = (PEB64*) GetPeb64();
		if ( !_peb64->Ldr ) {
			return 0;
		}
		PEB_LDR_DATA64* _ldr64 = (PEB_LDR_DATA64*) _peb64->Ldr;
		DWORD64 head = _peb64->Ldr + offsetof(PEB_LDR_DATA64, InLoadOrderModuleList);
		DWORD64 current = _ldr64->InLoadOrderModuleList.Flink;
		while ( head != current && current != 0 ) {
			LDR_DATA_TABLE_ENTRY64* entry = (LDR_DATA_TABLE_ENTRY64*) current;
			if ( entry->BaseDllName.Buffer != 0 && entry->BaseDllName.Length > 0 ) {
				if ( !_wcsnicmp((WCHAR*) entry->BaseDllName.Buffer, moduleName, entry->BaseDllName.Length / sizeof(WCHAR)) ) {
					return current;
				}
			}
			current = entry->InLoadOrderLinks.Flink;
		}
		return 0;
	}

	DWORD64 NTAPI X64NtCallExt::GetModuleBase64(const wchar_t* moduleName) {
		if ( !moduleName ) {
			return 0;
		}
		LDR_DATA_TABLE_ENTRY64* entry = (LDR_DATA_TABLE_ENTRY64*) GetModuleLdrEntry64(moduleName);
		return entry->DllBase;
	}

	DWORD64 NTAPI X64NtCallExt::GetNtdll64() {
		static DWORD64 _ntdll64 = 0;
		if ( _ntdll64 != 0 ) {
			return _ntdll64;
		}
		_ntdll64 = (DWORD64) GetModuleBase64(L"ntdll.dll");
		return _ntdll64;
	}

	DWORD64 NTAPI X64NtCallExt::GetKernel64() {
		static DWORD64 _kernel64 = 0;
		if ( _kernel64 != 0 ) {
			return _kernel64;
		}
		_kernel64 = (DWORD64) GetModuleBase64(L"kernel32.dll");
		return _kernel64;
	}

	DWORD64 NTAPI X64NtCallExt::LoadLibrary64(const wchar_t* moduleName) {
		if ( !moduleName ) return 0;

		DWORD64 hMod = GetModuleBase64(moduleName);
		if ( hMod != 0 ) return hMod;

		static DWORD64 pLdrLoadDll = 0;
		if ( !pLdrLoadDll ) {
			pLdrLoadDll = GetProcAddress64(GetNtdll64(), "LdrLoadDll");
		}
		if ( !pLdrLoadDll ) return 0;

		BYTE buffer[ 64 ] = { 0 };
		MakeUTFStr < DWORD64 >(moduleName, buffer);

		DWORD64 hResult = { 0 };
		NTSTATUS status = X64Call(pLdrLoadDll, (DWORD64) 0, (DWORD64) 0, (DWORD64) buffer, (DWORD64) &hResult);

		if ( NT_SUCCESS(status) ) {
			return hResult;
		}

		return status;
	}

	DWORD64 NTAPI X64NtCallExt::GetTeb64() {
		Reg64 _teb64 = { 0 };
		#ifdef _WIN64
		_teb64.v = __readgsqword(FIELD_OFFSET(NT_TIB, Self));
		#endif
		return _teb64.v;
	}

	DWORD64 NTAPI X64NtCallExt::GetPeb64() {
		Reg64 _peb64 = { 0 };
		#ifdef _WIN64
		_peb64.v = __readgsqword(FIELD_OFFSET(TEB, ProcessEnvironmentBlock));
		#endif
		return _peb64.v;
	}

	DWORD64 X64NtCallExt::_X64BuildExecute(std::function<void(std::string&)> _shellcode, const DWORD64* _pParam, const DWORD& _argC) {
		BYTE prepare_env[] = {
			0x55,                                                       // push rbp
			0x48, 0x89, 0xE5,                                           // mov rbp, rsp
			0x53,                                                       // push rbx
			0x56,                                                       // push rsi
			0x57,                                                       // push rdi
			0x41, 0x54,                                                 // push r12
			0x48, 0xBE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rsi, _pParam
			0x49, 0xBC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r12, _argC
			0x4C, 0x89, 0xE0,                                           // mov rax, r12
			0x49, 0x83, 0xFC, 0x04,                                     // cmp r12, 4
			0x7F, 0x07,                                                 // jg +7
			0x48, 0xC7, 0xC0, 0x04, 0x00, 0x00, 0x00,                   // mov rax, 4
			0x48, 0xC1, 0xE0, 0x03,                                     // shl rax, 3
			0x48, 0x29, 0xC4,                                           // sub rsp, rax
			0x48, 0x83, 0xE4, 0xF0,                                     // and rsp, 0xFFFFFFFFFFFFFFF0
			0x48, 0x8B, 0x0E,                                           // mov rcx, [rsi]
			0x48, 0x8B, 0x56, 0x08,                                     // mov rdx, [rsi + 8]
			0x4C, 0x8B, 0x46, 0x10,                                     // mov r8, [rsi + 16]
			0x4C, 0x8B, 0x4E, 0x18,                                     // mov r9, [rsi + 24]
			0x49, 0x83, 0xFC, 0x04,                                     // cmp r12, 4
			0x7E, 0x17,                                                 // jle _ready
			0x49, 0xC7, 0xC3, 0x04, 0x00, 0x00, 0x00,                   // mov r11, 4
			// _loop:
			0x4A, 0x8B, 0x04, 0xDE,                                     // mov rax, [rsi + r11 * 8]
			0x4A, 0x89, 0x04, 0xDC,                                     // mov [rsp + r11 * 8], rax (★ 已修复为精准压栈)
			0x49, 0xFF, 0xC3,                                           // inc r11
			0x4D, 0x39, 0xE3,                                           // cmp r11, r12
			0x7C, 0xF0                                                  // jl _loop
			// _ready:
		};

		BYTE restore_env[] = {
			0x48, 0x8D, 0x65, 0xE0,                                     //lea rsp,[ rbp - 32 ]
			0x41, 0x5C,				                                    //pop r12
			0x5F,					                                    //pop rdi
			0x5E,					                                    //pop rsi
			0x5B,					                                    //pop rbx
			0x5D,					                                    //pop rbp
			0xC3					                                    //ret
		};

		*(DWORD64*) (prepare_env + 11) = (DWORD64) _pParam;
		*(DWORD64*) (prepare_env + 21) = (DWORD64) _argC;

		std::string shellcode;
		shellcode.append((char*) prepare_env, sizeof(prepare_env));
		_shellcode(shellcode);
		shellcode.append((char*) restore_env, sizeof(restore_env));

		return _X64DisptachExecute(shellcode);
	}
	DWORD64 X64NtCallExt::_X64DisptachExecute(std::string _shellcode) {
		if ( _shellcode.empty() ) return 0;
		DWORD64 result;
		#ifdef _WIN64
		LPVOID pExecuteMemory = VirtualAlloc(
			NULL,
			_shellcode.size(),
			MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE
		);
		if ( !pExecuteMemory ) return 0;
		memcpy(pExecuteMemory, _shellcode.data(), _shellcode.size());
		auto FnExecuteCode = (DWORD64(*)()) pExecuteMemory;

		result = FnExecuteCode();
		VirtualFree(pExecuteMemory, 0, MEM_RELEASE);
		#endif
		return result;
	}
}