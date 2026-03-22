#pragma once
#include "../ResolverBase.hpp"

namespace NtExt {
	#ifdef _WIN64
	class X64Resolver : public ResolverBase {
		public:
		static X64Resolver& GetInstance() {
			static X64Resolver instance;
			return instance;
		}

		~X64Resolver() override = default;

		DWORD64 NTAPI GetSyscallNumber64(DWORD64 hMod, const char* funcName) override;
		DWORD64 NTAPI GetModuleLdrEntry64(const wchar_t* moduleName) override;
		DWORD64 NTAPI GetModuleBase64(const wchar_t* moduleName) override;
		DWORD64 NTAPI GetTeb64() override;
		DWORD64 NTAPI GetPeb64() override;
		DWORD64 NTAPI GetNtdll64() override;
		DWORD64 NTAPI GetKernel64() override;
		DWORD64 NTAPI LoadLibrary64(const wchar_t* moduleName) override;

		protected:
		DWORD64 NTAPI _GetProcAddress64(DWORD64 hMod, const char* funcName) override;

		private:
		X64Resolver() = default;
	};
	#endif
}