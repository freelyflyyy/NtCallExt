#pragma once
#include "../pch/stdafx.h"

namespace NtExt {

	class ResolverBase {
        public:
		virtual ~ResolverBase() = default;

        ResolverBase(const ResolverBase&) = delete;
        ResolverBase& operator=(const ResolverBase&) = delete;

        virtual DWORD64 NTAPI GetSyscallNumber64(DWORD64 hMod, const char* funcName) = 0;
        virtual DWORD64 NTAPI GetModuleLdrEntry64(const wchar_t* moduleName) = 0;
        virtual DWORD64 NTAPI GetModuleBase64(const wchar_t* moduleName) = 0;
        virtual DWORD64 NTAPI GetTeb64() = 0;
        virtual DWORD64 NTAPI GetPeb64() = 0;
        virtual DWORD64 NTAPI GetNtdll64() = 0;
        virtual DWORD64 NTAPI GetKernel64() = 0;
        virtual DWORD64 NTAPI LoadLibrary64(const wchar_t* moduleName) = 0;

        template<typename T>
        VOID MakeUTFStr(LPCWSTR lpString, LPBYTE outBuffer) {
            _MakeUTFStrVa(lpString, outBuffer, sizeof(T));
        }

        template<typename T>
        VOID MakeUTFStr(LPCSTR lpString, LPBYTE outUnicodeStr) {
            int len = MultiByteToWideChar(CP_ACP, 0, lpString, -1, NULL, 0);
            std::wstring wStr(len, L'\0');
            MultiByteToWideChar(CP_ACP, 0, lpString, -1, wStr.data(), len);
            MakeUTFStr<T>(wStr.c_str(), outUnicodeStr);
        }

        template<typename T>
        VOID MakeANSIStr(LPCSTR lpString, LPBYTE outBuffer) {
            _MakeANSIStrVa(lpString, outBuffer, sizeof(T));
        }

        template<typename T>
        VOID MakeANSIStr(LPCWSTR lpString, LPBYTE outAnsiStr) {
            int len = WideCharToMultiByte(CP_ACP, 0, lpString, -1, NULL, 0, NULL, NULL);
            std::string aStr(len, '\0');
            WideCharToMultiByte(CP_ACP, 0, lpString, -1, aStr.data(), len, NULL, NULL);
            MakeANSIStr<T>(aStr.c_str(), outAnsiStr);
        }

        DWORD64 IsCached64(const std::string& funcName) {
            std::shared_lock<std::shared_mutex> lock(_mutex);
            auto it = _cache.find(funcName);
            if ( it != _cache.end() ) return it->second;
            return 0;
        }

        DWORD64 GetProcAddress64(DWORD64 hMod, const std::string& funcName) {
            if ( auto addr = IsCached64(funcName) ) return addr;
            if ( hMod == 0 ) return 0;
            DWORD64 procAddr = _GetProcAddress64(hMod, funcName.data()); 
            if ( procAddr ) {
                std::unique_lock<std::shared_mutex> lock(_mutex);
                _cache[ funcName ] = procAddr;
            }
            return procAddr;
        }

        DWORD64 GetProcAddress64(const std::wstring& moduleName, const std::string& funcName) {
            if ( auto addr = IsCached64(funcName) ) return addr;
            DWORD64 hMod = GetModuleBase64(moduleName.data());
            if ( hMod == 0 ) return 0;
            return GetProcAddress64(hMod, funcName);
        }

        DWORD64 GetFunc64(const std::string& funcName) {
            if ( auto addr = IsCached64(funcName) ) return addr;
            return GetProcAddress64(GetNtdll64(), funcName);
        }

        private:
        virtual DWORD64 NTAPI _GetProcAddress64(DWORD64 hMod, const char* funcName) = 0;

        VOID NTAPI _MakeUTFStrVa(LPCWSTR lpString, LPBYTE outBuffer, SIZE_T pointerSize);
        VOID NTAPI _MakeANSIStrVa(LPCSTR lpString, LPBYTE outBuffer, SIZE_T pointerSize);

        protected:
        ResolverBase() = default;

        std::unordered_map<std::string, DWORD64> _cache;
        std::shared_mutex _mutex;
	};
}