/*!
    @file       NptHook.hpp

    @brief      NptHook 框架聚合头。包含各层模块的独立头文件：
                - include/NpConfig.h   : 编译期配置
                - include/NpSvm.h      : AMD SVM 硬件描述（VMCB/NPT）
                - include/NpTypes.h    : 公共类型（Guest 寄存器/Hook/每 CPU 数据）
                - include/NpHv.h       : core 层接口（生命周期/事件/VMEXIT 上下文）
                - include/NpHook.h     : services/NpHook 接口
                - include/NpLog.h      : services/NpLog 接口
                - include/NpPlatform.h : platform 层接口
                - include/NpAsm.h      : x64.asm 导出声明

    @details    新模块开发时优先包含对应子头（NpHv.h / NpHook.h / ...），
                仅组装层（DriverEntry）包含本聚合头。

                设计参考：
                - SimpleSvm (tandasat) : 极简 AMD SVM 教学 Hypervisor
                - 看雪《从0到1实现NPT无痕Hook》设计长文
                - SimpleSvmHook (tandasat) : 功能对应实现

                核心思想：不修改任何 Guest 内存字节，而是通过 Hypervisor
                持有的 NPT 控制“同一个 GPA 在不同时刻映射到不同的 HPA”，
                从而让“读”看到干净代码、“执行”看到 INT3。
 */
#pragma once

#include "NpConfig.h"
#include "NpSvm.h"
#include "NpTypes.h"
#include "NpHv.h"
#include "NpHook.h"
#include "NpBreakPoint.h"
#include "NpDebugHide.h"
#include "NpLog.h"
#include "NpPlatform.h"
#include "NpAsm.h"

// 向后兼容：旧代码直接调用 NpHvLogPrint，映射到日志服务。
#include <ntstrsafe.h>
