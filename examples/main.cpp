#pragma once
#include <iostream>
#include <NtCallExt.h>

using namespace MemX; // 使用你的专属命名空间

int main() {
    std::cout << "==================================================" << std::endl;
    std::cout << "    Wow64NtCallExt 天堂之门 跨维度测试启动 (32位环境) " << std::endl;
    std::cout << "==================================================\n" << std::endl;

    // 实例化你的 32位到64位 跨维度核武器
    Wow64NtCallExt nt;

    std::cout << "[*] 正在测试: 跨维度 6参数 内核直调 (NtAllocateVirtualMemory) ..." << std::endl;

    // 1. 获取 64位 ntdll 的基址（你写的代码非常棒，它能自动找到 64位的基址）
    DWORD64 ntdll64 = nt.GetNtdll64();
    if ( ntdll64 == 0 ) {
        std::cout << "    -> [!] 获取 64位 ntdll 失败！" << std::endl;
        system("pause");
        return -1;
    }

    // 2. 在 64位模块中解析 SSN
    WORD ssn = nt.GetSyscallNumber64(ntdll64, "NtAllocateVirtualMemory");

    if ( ssn != 0 ) {
        std::cout << "    -> 成功解析到 64位 NtAllocateVirtualMemory 的 SSN: 0x" << std::hex << ssn << std::dec << std::endl;

        DWORD64 baseAddress = 0;
        DWORD64 regionSize = 0x1000;

        std::cout << "    -> 准备叩开天堂之门，切入 64位 Ring0 内核..." << std::endl;

        // 3. 核心爆发！将 32位的数据打包，跨越维度执行 64位 Syscall
        DWORD64 retSysCall = nt.X64SysCall(
            ssn,
            (DWORD64) -1,                           // 参数1: 当前进程句柄
            (DWORD64) &baseAddress,                 // 参数2: 接收地址的指针
            (DWORD64) 0,                            // 参数3: ZeroBits
            (DWORD64) &regionSize,                  // 参数4: 申请大小的指针
            (DWORD64) (MEM_COMMIT | MEM_RESERVE),   // 参数5: 分配类型
            (DWORD64) PAGE_READWRITE                // 参数6: 内存保护属性
        );

        if ( retSysCall == 0 ) {
            std::cout << "    => 【震撼通关】天堂之门跨越成功！32位程序完美执行 6参数 64位系统调用！" << std::endl;
            std::cout << "    => 成功从 64位内核申请到内存，地址: 0x" << std::hex << baseAddress << std::dec << std::endl;

            // 用常规的 32位 API 释放内存（因为内存在同一个进程里是通用的）
            VirtualFree((LPVOID) (DWORD) baseAddress, 0, MEM_RELEASE);
        } else {
            std::cout << "    => 【警告】返回值不对，状态码: 0x" << std::hex << retSysCall << std::dec << std::endl;
        }
    } else {
        std::cout << "    -> [!] 解析 SSN 失败！\n" << std::endl;
    }

    std::cout << "\n==================================================" << std::endl;
    system("pause");
    return 0;
}