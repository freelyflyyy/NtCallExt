#include <iostream>
#include <NtCallExt.h>

using namespace MemX; // 使用你的专属命名空间

int main() {
    std::cout << "==================================================" << std::endl;
    std::cout << "      X64NtCallExt 终极双擎测试启动 (纯64位环境)  " << std::endl;
    std::cout << "==================================================\n" << std::endl;

    // 实例化你的底层核武器
    X64NtCallExt nt;

    // =====================================================================
    // 【测试一：X64Call】调用普通 64 位系统 API (MessageBoxA)
    // =====================================================================
    std::cout << "[*] 正在测试第一引擎: X64Call (普通 API 调用) ..." << std::endl;

    HMODULE hUser32 = LoadLibraryA("user32.dll");
    if ( hUser32 ) {
        // 1. 获取目标函数真实地址
        DWORD64 pMessageBoxA = (DWORD64) GetProcAddress(hUser32, "MessageBoxA");
        std::cout << "    -> 成功定位 MessageBoxA 地址: 0x" << std::hex << pMessageBoxA << std::dec << std::endl;

        // 2. 发起跨界调用！(4个参数完美验证影子空间机制)
        std::cout << "    -> 正在注入特权机器码并点火执行..." << std::endl;
        DWORD64 retCall = nt.X64Call(
            pMessageBoxA,
            0,
            (DWORD64) "如果看到这个弹窗，说明你的 X64Call 引擎完美无瑕！\n\n祝你早日康复出院！",
            (DWORD64) "MemX 底层测试",
            0
        );

        std::cout << "    -> MessageBoxA 执行完毕！返回值: " << retCall << " (1 代表点击了确定)\n" << std::endl;
    } else {
        std::cout << "    -> [!] 加载 user32.dll 失败！\n" << std::endl;
    }


    // =====================================================================
     // 【测试二：X64SysCall】穿透用户层，内核直调终极压力测试 (NtAllocateVirtualMemory)
     // =====================================================================
    std::cout << "[*] 正在测试第二引擎: X64SysCall (6参数终极压力测试) ..." << std::endl;

    DWORD64 ntdllBase = nt.GetNtdll64();
    // 换成所有 Windows 绝对100%导出的核心分配函数
    WORD ssn = nt.GetSyscallNumber64(ntdllBase, "NtAllocateVirtualMemory");

    if ( ssn != 0 ) {
        std::cout << "    -> 成功动态解析到 NtAllocateVirtualMemory 的 SSN: 0x" << std::hex << ssn << std::dec << std::endl;

        // 准备接收内核分配的内存地址
        DWORD64 baseAddress = 0;
        // 准备告诉内核我们要申请多大内存 (0x1000 就是 4096 字节，刚好一页)
        DWORD64 regionSize = 0x1000;

        std::cout << "    -> 正在向内核发起 6 参数并发请求，点火 Syscall..." << std::endl;

        // 【核心点火！】传入 6 个参数，疯狂压榨我们的底层引擎栈调度能力！
        DWORD64 retSysCall = nt.X64SysCall(
            ssn,
            (DWORD64) -1,                           // 参数1: 进程句柄 (-1 代表当前进程自己)
            (DWORD64) &baseAddress,                 // 参数2: 接收地址的指针
            (DWORD64) 10,                            // 参数3: ZeroBits (传 0)
            (DWORD64) &regionSize,                  // 参数4: 申请大小的指针
            (DWORD64) (MEM_COMMIT | MEM_RESERVE),   // 参数5: 分配类型
            (DWORD64) PAGE_READWRITE                // 参数6: 内存保护属性 (可读可写)
        );

        std::cout << "    -> 内核返回的原始状态码: 0x" << std::hex << retSysCall << std::dec << std::endl;

        if ( retSysCall == 0 ) { // 0 代表 STATUS_SUCCESS (成功)
            std::cout << "    => 【震撼通关】6参数压栈完美通过！你的 X64SysCall 引擎已天下无敌！" << std::endl;
            std::cout << "    => 成功从 Ring0 申请到特权内存，地址: 0x" << std::hex << baseAddress << std::dec << std::endl;

            // 优雅地打扫战场
            VirtualFree((LPVOID) baseAddress, 0, MEM_RELEASE);
        } else {
            std::cout << "    => 【警告】返回值不对，状态码: 0x" << std::hex << retSysCall << std::dec << std::endl;
        }
    } else {
        std::cout << "    -> [!] 解析 SSN 失败！\n" << std::endl;
    }
    system("pause");
    return 0;
}