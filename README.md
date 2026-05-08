# Beacon Object File Visual Studio Template

[This repository](https://github.com/Cobalt-Strike/bof-vs) contains the Beacon Object File Visual Studio (BOF-VS) template project. You can read more about rationale and design decisions from this blog [post](https://www.cobaltstrike.com/blog/simplifying-bof-development).

---

## Async BOF Framework / Async BOF 框架

This template extends the standard BOF-VS template with the **Async BOF Framework**, implementing the research from Outflank's "[Async BOFs - Wake Me Up, Before You Go Go](https://www.outflank.nl/blog/2025/07/16/async-bofs-wake-me-up-before-you-go-go/)" blog post.

本模板在标准 BOF-VS 模板基础上扩展了 **Async BOF 框架**，实现了 Outflank 研究文章 "[Async BOFs - Wake Me Up, Before You Go Go](https://www.outflank.nl/blog/2025/07/16/async-bofs-wake-me-up-before-you-go-go/)" 中的技术成果。

Async BOFs allow BOFs to run as background monitoring tasks while the Beacon is sleepmasked. When the Async BOF detects a significant event (e.g., an admin logon), it can immediately wake the Beacon to relay the information.

Async BOF 允许 BOF 作为后台监控任务运行，同时 Beacon 处于 sleepmask 状态。当 Async BOF 检测到重要事件（如管理员登录）时，可以立即唤醒 Beacon 以传递信息。

### Architecture Overview / 架构概览

```
┌─────────────────────────────────────────┐
│   Cobalt Strike Teamserver             │
│   ┌─────────────────────────────────┐  │
│   │   async_bof.cna (Aggressor)     │  │
│   │   • Job lifecycle management     │  │
│   │   • Stop event handling          │  │
│   │   • Output interception          │  │
│   │   • Wakeup signal processing    │  │
│   └─────────────────────────────────┘  │
└─────────────────────────────────────────┘
                    │
    ┌───────────────┴───────────────┐
    │   Beacon Process             │
    ▼                              ▼
┌─────────────────┐      ┌─────────────────┐
│  Main Beacon    │      │  Async BOF      │
│  Thread         │◄─────│  Thread         │
│  (Sleep/C2)     │ wake │  (Monitoring)   │
└─────────────────┘      └─────────────────┘
```

### Key Features / 核心特性

| Feature | Description | 特性 | 说明 |
|---------|-------------|------|------|
| **Non-blocking** | BOF runs in background without blocking main Beacon | **非阻塞执行** | BOF 在后台线程运行，不阻塞主 Beacon |
| **Event wakeup** | Async BOF can wake Beacon immediately on events | **事件唤醒** | Async BOF 可在检测到事件时立即唤醒 Beacon |
| **Graceful shutdown** | BOF can detect stop signals from operator | **优雅关闭** | BOF 可检测操作员发送的停止信号 |
| **Sleepmask compatible** | IAT patching for calling Beacon APIs while sleepmasked | **Sleepmask 兼容** | 支持在 Beacon 加密状态下调用 Beacon API |
| **OPSEC enhanced** | Thread pool, stack spoofing, API hashing | **OPSEC 增强** | 线程池执行、栈欺骗、API 哈希化 |

---

## Quick Start / 快速开始

### Prerequisites / 前提条件

| Requirement | Description | 要求 | 说明 |
|-------------|-------------|------|------|
| Windows | x64 Windows 10/11 | Windows | x64 Windows 10/11 |
| Visual Studio | 2022 Community/Pro/Enterprise with C++ workload | Visual Studio | 2022 Community/Pro/Enterprise 已安装 C++ 工作负载 |
| Cobalt Strike | 4.x (for loading compiled BOFs) | Cobalt Strike | 4.x（用于加载编译后的 BOF）|
| Python | 3.x for boflint (optional) | Python | 3.x 用于 boflint（可选）|

### Installation / 安装

1. Load the Aggressor Script / 加载 Aggressor 脚本：
   ```
   Aggressor Scripts → Load → BOF-Template/cna/async_bof.cna
   ```

2. Open the BOF-VS project in Visual Studio / 在 Visual Studio 中打开 BOF-VS 项目

3. Build your Async BOF / 编译 Async BOF：
   - Select **Release | x64** / 选择 **Release | x64** 配置
   - Build (Ctrl+Shift+B) / 编译（Ctrl+Shift+B）

4. Upload the `.x64.o` file to your teamserver / 上传 `.x64.o` 文件到 teamserver

### Basic Usage / 基本用法

```cpp
#include "async/async_bof.h"

void go(char* args, int len) {
    // Initialize with stop event handle / 使用 stop event handle 初始化
    async_init(args, len);

    if (!async_is_initialized()) {
        BeaconPrintf(CALLBACK_ERROR, "[!] This BOF requires async_bof.cna");
        return;
    }

    HANDLE hStop = async_get_stop_event();

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Async BOF started");

    // Main monitoring loop / 主监控循环
    while (!async_should_stop(1000)) {
        // Check for target event / 检查目标事件

        if (event_detected) {
            ASYNC_ALERT("[!] Important event detected!");
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Async BOF stopped");
}
```

### Beacon Commands / Beacon 命令

```
beacon> async_bof <bof_file.o> [args...]
        Execute an Async BOF / 执行 Async BOF

beacon> async_jobs
        List all async jobs / 列出所有异步任务

beacon> async_stop <job_handle>
        Stop a specific job / 停止指定任务

beacon> async_stop_all
        Stop all jobs / 停止所有任务
```

---

## API Reference / API 参考

### Core Functions / 核心函数

| Function | Description | 函数 | 说明 |
|----------|-------------|------|------|
| `async_init(args, len)` | Initialize, parse stop event from args | `async_init(args, len)` | 初始化，从 args 解析 stop event |
| `async_get_stop_event()` | Get stop event handle | `async_get_stop_event()` | 获取 stop event 句柄 |
| `async_should_stop(ms)` | Check if stop signal received | `async_should_stop(ms)` | 检查是否收到停止信号 |
| `async_wakeup()` | Signal Beacon to wake up | `async_wakeup()` | 发送唤醒信号给 Beacon |
| `async_printf(type, fmt, ...)` | Print output to console | `async_printf(type, fmt, ...)` | 输出到 Beacon 控制台 |
| `async_stopping()` | Send STOPPING notification | `async_stopping()` | 发送 STOPPING 通知 |
| `async_stopped()` | Send STOPPED notification | `async_stopped()` | 发送 STOPPED 通知 |

### Helper Macros / 辅助宏

```cpp
// Alert: print and immediately wake Beacon / 警报：输出并立即唤醒 Beacon
#define ASYNC_ALERT(fmt, ...) \
    do { async_printf(CALLBACK_OUTPUT, fmt, ##__VA_ARGS__); async_wakeup(); } while(0)

// Check stop signal with 0ms timeout / 检查停止信号（0ms 超时）
#define ASYNC_CHECK_STOP() async_should_stop(0)
```

### Protocol Messages / 协议消息

Async BOF communicates with CNA loader via special output messages:

Async BOF 通过特殊输出消息与 CNA loader 通信：

```
\x00ASYNCPROTO\x00[CMD]\x00[PAYLOAD]
```

| Command | Direction | Description | 命令 | 方向 | 说明 |
|---------|-----------|-------------|------|------|------|
| `WAKEUP` | BOF → CNA | Request Beacon wakeup | `WAKEUP` | BOF → CNA | 请求 Beacon 唤醒 |
| `STOPPING` | BOF → CNA | BOF preparing to stop | `STOPPING` | BOF → CNA | BOF 准备停止 |
| `STOPPED` | BOF → CNA | BOF has stopped | `STOPPED` | BOF → CNA | BOF 已停止 |
| `DATA` | BOF → CNA | Normal output data | `DATA` | BOF → CNA | 正常输出数据 |

---

## Example BOFs / 示例 BOF

### async_monitor_logon.c

Monitors Windows Security Event Log for logon events (4624/4625). Wakes Beacon when administrator logon is detected.

监控 Windows 安全日志中的登录事件（4624/4625）。检测到管理员登录时唤醒 Beacon。

```cpp
// Execute / 执行
beacon> async_bof async_monitor_logon.x64.o

// Output / 输出
[!] LOGON EVENT DETECTED
[!] User: DOMAIN\Administrator
[!] Logon Type: 2
[!] ADMIN LOGON: DOMAIN\Administrator
```

### async_monitor_process.c

Monitors for specific process startup using NtQuerySystemInformation.

使用 NtQuerySystemInformation 监控指定进程启动。

```cpp
// Monitor notepad.exe, check every 2000ms / 监控 notepad.exe，每 2000ms 检查一次
beacon> async_bof async_monitor_process.x64.o notepad.exe 2000

// Output / 输出
[!] PROCESS START DETECTED
[!] Process: notepad.exe
[!] PID: 1234
[!] PROCESS START: notepad.exe (PID: 1234)
```

---

## Mock Testing / Mock 测试

The framework includes mock testing support in `base/mock_async.h` / `base/mock_async.cpp`.

框架在 `base/mock_async.h` / `base/mock_async.cpp` 中包含 mock 测试支持。

```cpp
#ifdef _DEBUG
#undef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT
#include "base/mock_async.h"
#endif

extern "C" {
    #include "beacon.h"
    #include "async/async_bof.h"
}

extern void go(char* args, int len);

// Test wakeup was triggered / 测试唤醒是否被触发
TEST(AsyncBofTest, WakeupTriggered) {
    bof::async_mock::reset();
    auto output = bof::runMockedAsync<>(go, "admin");
    ASSERT_TRUE(bof::async_mock::wasWakeupCalled());
}

// Test stop event works / 测试 stop 事件
TEST(AsyncBofTest, StopEventWorks) {
    bof::async_mock::reset();
    bof::async_mock::triggerStopEvent();  // Trigger manually / 手动触发
    auto output = bof::runMockedAsync<>(go);
}
```

### Mock API / Mock API

| Function | Description | 函数 | 说明 |
|----------|-------------|------|------|
| `bof::async_mock::reset()` | Reset mock state | `bof::async_mock::reset()` | 重置 mock 状态 |
| `bof::async_mock::setMockStopEvent(h)` | Set mock stop event | `bof::async_mock::setMockStopEvent(h)` | 设置 mock stop event |
| `bof::async_mock::wasWakeupCalled()` | Check if wakeup triggered | `bof::async_mock::wasWakeupCalled()` | 检查唤醒是否被触发 |
| `bof::async_mock::getLastAsyncMessage()` | Get last ASYNCPROTO message | `bof::async_mock::getLastAsyncMessage()` | 获取最后的 ASYNCPROTO 消息 |
| `bof::async_mock::triggerStopEvent()` | Trigger stop event | `bof::async_mock::triggerStopEvent()` | 触发 stop 事件 |

---

## Sleepmask Compatibility / Sleepmask 兼容性

The framework supports calling Beacon APIs while Beacon is sleepmasked through IAT (Import Address Table) patching. When Beacon's memory is encrypted, direct calls to `BeaconPrintf` would crash. IAT patch redirects calls to a proxy function outside the encrypted region.

框架通过 IAT（导入地址表）修补支持在 Beacon sleepmask 状态下调用 Beacon API。当 Beacon 内存被加密时，直接调用 `BeaconPrintf` 会崩溃。IAT patch 将调用重定向到加密区域外的代理函数。

### How It Works / 工作原理

```
Standard BOF (crashes during sleepmask) / 标准 BOF（sleepmask 时崩溃）:
  BeaconPrintf@IAT → 0xBeaconMemory (encrypted/已加密)

Patched BOF (safe) / 已修补 BOF（安全）:
  BeaconPrintf@IAT → AsyncBOF_ProxyPrintf (unencrypted stub/非加密存根)
```

### COFF Patching API / COFF 修补 API

```cpp
#include "async/async_bof_patch.h"

ASYNC_PATCH_RESULT result;

// Patch single import / 修补单个导入
async_bof_patch_imports(
    pCoffData,            // COFF object buffer / COFF 对象缓冲区
    dwCoffSize,           // Buffer size / 缓冲区大小
    "beacon",             // Module name / 模块名
    "BeaconPrintf",       // Function name / 函数名
    pProxyFunctionAddr,   // New address / 新地址
    &result               // Result / 结果
);

// Auto-patch all Beacon imports / 自动修补所有 Beacon 导入
async_bof_patch_coff(pCoffData, dwCoffSize, &result);
```

---

## Traditional BOF Development / 传统 BOF 开发

The template maintains full support for standard BOF development.

模板完整支持标准 BOF 开发。

### Dynamic Function Resolution / 动态函数解析

```cpp
// Global function pointer / 全局函数指针
DFR(KERNEL32, OpenProcess)
#define OpenProcess KERNEL32$OpenProcess

// Local function pointer / 局部函数指针
void func() {
    DFR_LOCAL(KERNEL32, CreateFileA);
    CreateFileA(...);
}
```

### Argument Packer / 参数打包器

```cpp
bof::mock::BofData data;
data.pack<int, short, const char*>(6502, 42, "Hello");
go(data.get(), data.size());
```

### Unit Tests / 单元测试

```cpp
TEST(ExampleBofTest, TestCase1) {
    auto actual = bof::runMocked<int>(go, 6502);
    std::vector<bof::output::OutputEntry> expected = {
        {CALLBACK_OUTPUT, "Hello: 6502"}
    };
    ASSERT_EQ(expected, actual);
}
```

---

## Build Configurations / 构建配置

| Configuration | Purpose | Output | 配置 | 用途 | 输出 |
|--------------|---------|--------|------|------|------|
| **Debug** | Run BOF as executable with mock Beacon | `.exe` | **Debug** | 使用 mock Beacon 将 BOF 作为可执行文件运行 | `.exe` |
| **Release** | Compile to COFF object for Cobalt Strike | `.x64.o` | **Release** | 编译为 COFF object 文件供 Cobalt Strike 使用 | `.x64.o` |
| **UnitTest** | Build with GoogleTest framework | `.exe` | **UnitTest** | 使用 GoogleTest 框架构建 | `.exe` |

---

## BOF Linter / BOF 静态分析器

`boflint` runs during Release builds for static analysis:

`boflint` 在 Release 构建期间运行静态分析：

- **Relocation types**: Validates only supported relocations / **重定位类型**：验证仅使用支持的重定位
- **Entry point**: Verifies `go` or `sleep_mask` exists / **入口点**：验证 `go` 或 `sleep_mask` 存在
- **Imports**: Flags undefined imports / **导入**：标记未定义的导入
- **Stack variables**: Detects unresolvable stack probing / **栈变量**：检测无法解析的栈探测
- **Exception handling**: Warns against unsupported exceptions / **异常处理**：警告不支持的异常

Manual run / 手动运行：
```
python ./utils/boflint.py --loader cs x64/Release/bof.x64.o
```

---

## File Structure / 文件结构

```
BOF-Template/
├── async/
│   ├── async_bof.h           # Async BOF API / Async BOF API
│   ├── async_bof.c           # Core implementation / 核心实现
│   ├── async_bof_patch.h    # IAT patching interface / IAT 修补接口
│   ├── async_bof_patch.c    # COFF patching / COFF 修补
│   ├── async_protocol.h     # Protocol constants / 协议常量
│   └── async_protocol.c      # Message encoding / 消息编码
├── base/
│   ├── helpers.h             # DFR macros
│   ├── mock.h / mock.cpp    # Beacon API mock
│   └── mock_async.h / mock_async.cpp  # Async mock
├── cna/
│   └── async_bof.cna         # Aggressor Script loader
├── examples/
│   ├── async_monitor_logon.c   # Logon monitor / 登录监控
│   └── async_monitor_process.c # Process monitor / 进程监控
├── utils/
│   └── boflint.py            # BOF static analyzer / BOF 静态分析器
└── BOF-Template.vcxproj      # Visual Studio project
```

---

## References / 参考资料

| Source | Description |
|--------|-------------|
| [Outflank: Async BOFs](https://www.outflank.nl/blog/2025/07/16/async-bofs-wake-me-up-before-you-go-go/) | Original Async BOF research |
| [Cobalt Strike BOF Docs](https://www.cobaltstrike.com/help-bof) | Official BOF documentation |
| [Simplifying BOF Development](https://www.cobaltstrike.com/blog/simplifying-bof-development) | BOF-VS template rationale |

| 来源 | 说明 |
|------|------|
| [Outflank: Async BOFs](https://www.outflank.nl/blog/2025/07/16/async-bofs-wake-me-up-before-you-go-go/) | 原始 Async BOF 研究 |
| [Cobalt Strike BOF 文档](https://www.cobaltstrike.com/help-bof) | 官方 BOF 文档 |
| [简化 BOF 开发](https://www.cobaltstrike.com/blog/simplifying-bof-development) | BOF-VS 模板设计理念 |
