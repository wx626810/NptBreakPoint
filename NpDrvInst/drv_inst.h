#pragma once
// NpDrvInst.dll C ABI：传输(Hypercall优先+IOCTL兜底) + hypercall + 窗口联动 + BYOVD安装链。
// 由 Tauri Rust 后端内嵌调用（include_bytes!），最终仍是单EXE。
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define NPT_API __declspec(dllexport)
#define NPT_NEED_ADMIN 0xE0000001u
#define NPT_SECGATE_BLOCKED 0xE0000002u
NPT_API uint32_t NpT_IsAdmin(void);                                     // 1=admin 0=no
NPT_API uint32_t NpT_SecGate(wchar_t* msgOut, uint32_t msgCap);        // 0=通过 1=被拦(msg已填)
NPT_API uint32_t NpT_Open(void);                                        // 打开/复用传输句柄，0=ok 否则GetLastError
NPT_API void     NpT_Close(void);
NPT_API uint32_t NpT_Ioctl(uint32_t code, uint8_t* buf, uint32_t len, uint32_t* outRet); // 复合buffer直通，0=ok
NPT_API uint32_t NpT_HcStatus(uint8_t out24[24]);                      // 1=命中 0=miss
NPT_API uint32_t NpT_HcDbgHide(uint32_t en);                           // 1=成功 0=走IOCTL兜底
NPT_API uint32_t NpT_HcProtect(uint32_t pid, uint32_t p);
NPT_API uint32_t NpT_HcMode(uint32_t mode);
NPT_API uint32_t NpT_HcLicenseSet(const char* token);                  // 1=驱动验签通过并授权 0=失败
NPT_API uint32_t NpT_DbgLink(uint32_t enable, uint32_t* renamedOut);   // 窗口改名/恢复联动
NPT_API uint32_t NpT_Install(wchar_t* svcOut, uint32_t svcCap, wchar_t* logOut, uint32_t logCap);   // 0=ok（内嵌兜底）
NPT_API uint32_t NpT_InstallPkg(const wchar_t* npPath, const wchar_t* hwPath, wchar_t* svcOut, uint32_t svcCap, wchar_t* logOut, uint32_t logCap); // 云端包安装：npPath 必填，hwPath 空=内嵌兜底
typedef void (CALLBACK* NPT_LOG_CB)(const wchar_t* line);
NPT_API void NpT_SetLogCallback(NPT_LOG_CB cb);   // 注册后每条安装/卸载日志实时回调
NPT_API uint32_t NpT_Uninstall(wchar_t* logOut, uint32_t logCap);      // 返回卸载数
#ifdef __cplusplus
}
#endif
