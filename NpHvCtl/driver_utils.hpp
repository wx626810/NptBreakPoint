#pragma once

#include <windows.h>
#include <winternl.h>
#include <string>
#include <iostream>
#include "str_enc.h"

#pragma comment(lib, "advapi32.lib")

namespace DriverUtils {

    // 增加 RtlAdjustPrivilege 定义
    typedef NTSTATUS(NTAPI* pfnNtLoadDriver)(PUNICODE_STRING DriverServiceName);
    typedef NTSTATUS(NTAPI* pfnNtUnloadDriver)(PUNICODE_STRING DriverServiceName);
    typedef VOID(NTAPI* pfnRtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
    typedef NTSTATUS(NTAPI* pfnRtlAdjustPrivilege)(ULONG Privilege, BOOLEAN Enable, BOOLEAN ClientWhat, PBOOLEAN WasEnabled);

    // SeLoadDriverPrivilege 的常数值
    constexpr ULONG SE_LOAD_DRIVER_PRIVILEGE = 10ul;
    // SeDebugPrivilege:26200 上 SystemModuleInformation 的 ImageBase 需要此权限才返回真实基址
    constexpr ULONG SE_DEBUG_PRIVILEGE_VALUE = 20ul;

    // 提升当前进程权限 (通过 RtlAdjustPrivilege)
    inline bool EnablePrivilege(ULONG Privilege) {
        HMODULE hNtdll = GetModuleHandleW(WSX(L"ntdll.dll").c_str());
        if (!hNtdll) return false;

        auto RtlAdjustPrivilege = (pfnRtlAdjustPrivilege)GetProcAddress(hNtdll, SX("RtlAdjustPrivilege").c_str());
        if (!RtlAdjustPrivilege) return false;

        BOOLEAN wasEnabled;
        // ClientWhat = FALSE 代表调整的是进程的 Token，而非线程。
        NTSTATUS status = RtlAdjustPrivilege(Privilege, TRUE, FALSE, &wasEnabled);

        // 返回 NT_SUCCESS
        return (status >= 0);
    }

    // 创建驱动服务注册表项
    inline bool SetupRegistry(const std::wstring& serviceName, const std::wstring& driverPath) {
        std::wstring regPath = L"SYSTEM\\CurrentControlSet\\Services\\" + serviceName;
        HKEY hKey;

        // 创建注册表项
        if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, regPath.c_str(), 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hKey, NULL) != ERROR_SUCCESS) {
            return false;
        }

        // 设置 Type = 1 (Kernel Device Driver)
        DWORD type = 1;
        RegSetValueExW(hKey, L"Type", 0, REG_DWORD, (const BYTE*)&type, sizeof(type));

        // 设置 ErrorControl = 1 (Normal)
        DWORD errorControl = 1;
        RegSetValueExW(hKey, L"ErrorControl", 0, REG_DWORD, (const BYTE*)&errorControl, sizeof(errorControl));

        // 设置 ImagePath (需要转换为 NT 路径格式 \??\C:\path\to\driver.sys)
        std::wstring imagePath = WSX(L"\\??\\") + driverPath;
        RegSetValueExW(hKey, L"ImagePath", 0, REG_SZ, (const BYTE*)imagePath.c_str(), (DWORD)(imagePath.size() * sizeof(wchar_t) + sizeof(wchar_t)));

        RegCloseKey(hKey);
        return true;
    }

    // 删除驱动服务注册表项
    inline bool RemoveRegistry(const std::wstring& serviceName) {
        std::wstring regPath = L"SYSTEM\\CurrentControlSet\\Services\\" + serviceName;
        return (RegDeleteKeyW(HKEY_LOCAL_MACHINE, regPath.c_str()) == ERROR_SUCCESS);
    }

    inline bool IsDriverLoaded(const std::wstring& serviceName) {
        SC_HANDLE hScm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!hScm) return false;

        SC_HANDLE hSvc = OpenServiceW(hScm, serviceName.c_str(), SERVICE_QUERY_STATUS);
        if (!hSvc) {
            CloseServiceHandle(hScm);
            return false;
        }

        SERVICE_STATUS_PROCESS ssp{};
        DWORD bytesNeeded = 0;
        bool loaded = false;

        if (QueryServiceStatusEx(
            hSvc,
            SC_STATUS_PROCESS_INFO,
            reinterpret_cast<LPBYTE>(&ssp),
            sizeof(ssp),
            &bytesNeeded)) {
            loaded = (ssp.dwCurrentState == SERVICE_RUNNING);
        }

        CloseServiceHandle(hSvc);
        CloseServiceHandle(hScm);
        return loaded;
    }


    inline bool LoadDriver(const std::wstring& driverPath, const std::wstring& serviceName) {
        if (IsDriverLoaded(serviceName)) {
            std::wcout << L"[+] driver already loaded" << std::endl;
            return true;
        }
        if (!EnablePrivilege(SE_LOAD_DRIVER_PRIVILEGE)) {
            std::wcerr << L"[-] Failed to enable privilege. Please run as administrator." << std::endl;
            return false;
        }


        if (!SetupRegistry(serviceName, driverPath)) {
            std::wcerr << L"[-] Failed to create registry key." << std::endl;
            return false;
        }

        // 3. Dynamically get API from ntdll.dll
        HMODULE hNtdll = GetModuleHandleW(WSX(L"ntdll.dll").c_str());
        if (!hNtdll) return false;

        auto NtLoadDriver = (pfnNtLoadDriver)GetProcAddress(hNtdll, SX("NtLoadDriver").c_str());
        auto RtlInitUnicodeString = (pfnRtlInitUnicodeString)GetProcAddress(hNtdll, SX("RtlInitUnicodeString").c_str());

        if (!NtLoadDriver || !RtlInitUnicodeString) {
            std::wcerr << L"[-] Failed to resolve function addresses from ntdll.dll." << std::endl;
            return false;
        }

        // 4. Format the Registry NT path and initialize UNICODE_STRING
        std::wstring ntRegPath = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + serviceName;
        UNICODE_STRING usDriverServiceName;
        RtlInitUnicodeString(&usDriverServiceName, ntRegPath.c_str());

        // 5. Call NtLoadDriver
        NTSTATUS status = NtLoadDriver(&usDriverServiceName);

        // STATUS_SUCCESS (0x00000000) or STATUS_IMAGE_ALREADY_LOADED (0xC000010E) are considered success
        if (status == 0x00000000 || status == 0xC000010E) {
            return true;
        }
        else {
            std::wcerr << L"[-] " << WSX(L"LD") << L" failed, NTSTATUS error code: 0x" << std::hex << status << std::endl;
            // Failed to load, clean up registry
            RemoveRegistry(serviceName);
            return false;
        }
    }

    // Core unload function
    inline bool UnloadDriver(const std::wstring& serviceName) {
        // 1. Elevate privilege (in case unload is called directly in another lifecycle)
        if (!EnablePrivilege(SE_LOAD_DRIVER_PRIVILEGE)) {
            return false;
        }

        // 2. Dynamically get API from ntdll.dll
        HMODULE hNtdll = GetModuleHandleW(WSX(L"ntdll.dll").c_str());
        if (!hNtdll) return false;

        auto NtUnloadDriver = (pfnNtUnloadDriver)GetProcAddress(hNtdll, SX("NtUnloadDriver").c_str());
        auto RtlInitUnicodeString = (pfnRtlInitUnicodeString)GetProcAddress(hNtdll, SX("RtlInitUnicodeString").c_str());

        if (!NtUnloadDriver || !RtlInitUnicodeString) return false;

        // 3. Format the Registry NT path
        std::wstring ntRegPath = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + serviceName;
        UNICODE_STRING usDriverServiceName;
        RtlInitUnicodeString(&usDriverServiceName, ntRegPath.c_str());

        // 4. Call NtUnloadDriver
        NTSTATUS status = NtUnloadDriver(&usDriverServiceName);

        // 5. Regardless of unload success, clean up the registry (keep the system clean)
        RemoveRegistry(serviceName);

        if (status == 0x00000000) {
            return true;
        }
        else {
            std::wcerr << L"[-] " << WSX(L"UD") << L" failed, NTSTATUS error code: 0x" << std::hex << status << std::endl;
            return false;
        }
    }
}