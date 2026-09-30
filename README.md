# checkOwner: Windows 剪贴板属主前置验证探针

用于诊断与验证 Windows 10 沙箱环境中剪贴板复制事件的**属主窗口 (`GetClipboardOwner`)**、**前台焦点窗口 (`GetForegroundWindow`)**、**关联进程签名**与**剪贴板格式**，帮助精确鉴别“本地用户主动复制”与“aTrust 外部后台注入”。

---

## 一、 快速开始 (在 Windows 10 运行)

进入项目目录直接执行：
```bash
cargo run --release
```

程序启动后会自动注册 Windows `AddClipboardFormatListener` 隐藏消息监听窗口，并在控制台实时输出每一个剪贴板事件的详尽诊断报告。

---

## 二、 核心测试步骤与观察要点

在程序运行期间，请分别进行以下测试操作，观察控制台输出的差异：

### 1. 测试用例 1：沙箱内本地用户主动复制 (合法操作)
* **操作**：
  * 在沙箱内打开记事本，输入字符并按 `Ctrl+C`；
  * 或在沙箱资源管理器中选中文件按 `Ctrl+C`。
* **预期特征**：
  * `GetClipboardOwner` 的 HWND 不为 NULL，类名为 `Notepad` 或 `CabinetWClass` 等。
  * `GetForegroundWindow` 的 HWND / PID 与属主完全吻合（`owner.pid == fg.pid`）。
  * 诊断结论为：`[ACCEPT / LOCAL_USER_COPY]`。

### 2. 测试用例 2：宿主机触发复制，观察 aTrust 向沙箱注入 (外部回流)
* **操作**：
  * 将焦点切回宿主机（Host），在宿主机记事本或宿主机资源管理器中复制内容。
* **观察重点（aTrust 的行为模式）**：
  * **属主是否为 NULL**：许多后台注入服务会直接调用 `OpenClipboard(NULL)`，导致 `GetClipboardOwner()` 返回 0x00000000。
  * **前台焦点是否错位**：用户在宿主机操作时，沙箱内处于非激活状态（`GetForegroundWindow()` 可能为 NULL，或者停留在沙箱内无关的后台窗口，导致 `owner.pid != fg.pid`）。
  * **属主进程特征**：若 aTrust 绑定了代理窗口写入，其进程名通常包含 `aTrustAgent.exe`、`ECAgent.exe` 等。
  * 诊断结论通常命中：`[INTERCEPT / NULL_OWNER]`、`[INTERCEPT / EXTERNAL_AGENT]` 或 `[SUSPICIOUS / PID_MISMATCH]`。

---

## 三、 输出日志结构说明

每次收到 `WM_CLIPBOARDUPDATE`，探针输出 4 部分信息：
1. **剪贴板属主窗口 (GetClipboardOwner)**：
   * HWND、窗口标题 (Title)、窗口类名 (ClassName)、PID/TID、进程 Executable 绝对路径及文件名。
2. **当前前台活动窗口 (GetForegroundWindow)**：
   * 当前用户焦点的窗口句柄、类名、标题与所属进程信息。
3. **剪贴板格式与内容探测**：
   * 包含的系统/私有剪贴板格式（`CF_UNICODETEXT`, `CF_HDROP` 等）；
   * 文件列表预览（路径、数量）或文本截断预览。
4. **规则评估结论 (Diagnostic Verdict)**：
   * 明确给出属于合法用户复制还是应当拦截的外部注入。
