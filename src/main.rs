#[cfg(windows)]
use chrono::Local;

#[cfg(windows)]
mod win_impl {
    use super::*;
    use std::path::PathBuf;
    use std::ptr::{null, null_mut};
    use std::sync::atomic::{AtomicIsize, AtomicU64, Ordering};
    use std::time::Duration;
    use windows_sys::Win32::Foundation::*;
    use windows_sys::Win32::System::DataExchange::*;
    use windows_sys::Win32::System::Memory::*;
    use windows_sys::Win32::System::Threading::*;
    use windows_sys::Win32::UI::Shell::*;
    use windows_sys::Win32::UI::WindowsAndMessaging::*;

    static EVENT_COUNTER: AtomicU64 = AtomicU64::new(0);
    static LISTENER_HWND: AtomicIsize = AtomicIsize::new(0);

    pub const CF_TEXT: u32 = 1;
    pub const CF_BITMAP: u32 = 2;
    pub const CF_UNICODETEXT: u32 = 13;
    pub const CF_HDROP: u32 = 15;
    pub const CF_LOCALE: u32 = 16;
    pub const CF_DIB: u32 = 8;
    pub const CF_DIBV5: u32 = 17;

    #[derive(Debug, Default)]
    pub struct WindowDetails {
        pub hwnd: isize,
        pub title: String,
        pub class_name: String,
        pub pid: u32,
        pub tid: u32,
        pub exe_name: String,
        pub full_path: String,
    }

    pub fn inspect_window(hwnd: HWND) -> Option<WindowDetails> {
        if hwnd.is_null() {
            return None;
        }

        unsafe {
            // 1. 窗口标题
            let text_len = GetWindowTextLengthW(hwnd);
            let mut title_buf = vec![0u16; (text_len + 2) as usize];
            let actual_len = GetWindowTextW(hwnd, title_buf.as_mut_ptr(), title_buf.len() as i32);
            let title = if actual_len > 0 {
                String::from_utf16_lossy(&title_buf[..actual_len as usize])
            } else {
                String::new()
            };

            // 2. 类名
            let mut class_buf = [0u16; 256];
            let class_len = GetClassNameW(hwnd, class_buf.as_mut_ptr(), class_buf.len() as i32);
            let class_name = if class_len > 0 {
                String::from_utf16_lossy(&class_buf[..class_len as usize])
            } else {
                String::new()
            };

            // 3. 线程与进程 ID
            let mut pid: u32 = 0;
            let tid = GetWindowThreadProcessId(hwnd, &mut pid);

            // 4. 进程可执行文件路径与文件名
            let mut full_path = String::new();
            let mut exe_name = String::new();

            if pid != 0 {
                let h_proc = OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION,
                    0,
                    pid,
                );
                let h_proc = if h_proc.is_null() {
                    OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid)
                } else {
                    h_proc
                };

                if !h_proc.is_null() {
                    let mut path_buf = [0u16; 1024];
                    let mut path_len: u32 = path_buf.len() as u32;
                    if QueryFullProcessImageNameW(h_proc, 0, path_buf.as_mut_ptr(), &mut path_len) != 0 {
                        full_path = String::from_utf16_lossy(&path_buf[..path_len as usize]);
                        if let Some(pos) = full_path.rfind('\\') {
                            exe_name = full_path[pos + 1..].to_string();
                        } else {
                            exe_name = full_path.clone();
                        }
                    }
                    CloseHandle(h_proc);
                }
            }

            Some(WindowDetails {
                hwnd: hwnd as isize,
                title,
                class_name,
                pid,
                tid,
                exe_name,
                full_path,
            })
        }
    }

    fn open_clipboard_with_retry(hwnd: HWND, max_retries: u32) -> bool {
        for _ in 0..max_retries {
            if unsafe { OpenClipboard(hwnd) } != 0 {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    }

    pub struct ClipboardSnapshot {
        pub formats: Vec<(u32, String)>,
        pub text_preview: Option<String>,
        pub files: Option<Vec<PathBuf>>,
    }

    pub fn snapshot_clipboard() -> Option<ClipboardSnapshot> {
        if !open_clipboard_with_retry(null_mut(), 10) {
            return None;
        }

        let mut formats = Vec::new();
        let mut cur_fmt: u32 = 0;
        unsafe {
            loop {
                cur_fmt = EnumClipboardFormats(cur_fmt);
                if cur_fmt == 0 {
                    break;
                }
                let name = match cur_fmt {
                    CF_TEXT => "CF_TEXT (1)".to_string(),
                    CF_BITMAP => "CF_BITMAP (2)".to_string(),
                    CF_DIB => "CF_DIB (8)".to_string(),
                    CF_UNICODETEXT => "CF_UNICODETEXT (13)".to_string(),
                    CF_HDROP => "CF_HDROP (15)".to_string(),
                    CF_LOCALE => "CF_LOCALE (16)".to_string(),
                    CF_DIBV5 => "CF_DIBV5 (17)".to_string(),
                    other => {
                        let mut name_buf = [0u16; 128];
                        let len = GetClipboardFormatNameW(other, name_buf.as_mut_ptr(), name_buf.len() as i32);
                        if len > 0 {
                            format!("0x{:04X} ({})", other, String::from_utf16_lossy(&name_buf[..len as usize]))
                        } else {
                            format!("0x{:04X} (Custom/Private)", other)
                        }
                    }
                };
                formats.push((cur_fmt, name));
            }
        }

        // 探测文件列表 (CF_HDROP 优先)
        let mut files = None;
        if unsafe { IsClipboardFormatAvailable(CF_HDROP) } != 0 {
            let h_drop = unsafe { GetClipboardData(CF_HDROP) } as HDROP;
            if !h_drop.is_null() {
                let file_count = unsafe { DragQueryFileW(h_drop, 0xFFFFFFFF, null_mut(), 0) };
                let mut path_list = Vec::new();
                for i in 0..file_count {
                    let len = unsafe { DragQueryFileW(h_drop, i, null_mut(), 0) };
                    if len > 0 {
                        let mut buf = vec![0u16; (len + 1) as usize];
                        unsafe { DragQueryFileW(h_drop, i, buf.as_mut_ptr(), len + 1) };
                        buf.pop();
                        path_list.push(PathBuf::from(String::from_utf16_lossy(&buf)));
                    }
                }
                files = Some(path_list);
            }
        }

        // 探测纯文本
        let mut text_preview = None;
        if files.is_none() && unsafe { IsClipboardFormatAvailable(CF_UNICODETEXT) } != 0 {
            let h_data = unsafe { GetClipboardData(CF_UNICODETEXT) };
            if !h_data.is_null() {
                let max_bytes = unsafe { GlobalSize(h_data) };
                let max_chars = max_bytes / std::mem::size_of::<u16>();
                let p_data = unsafe { GlobalLock(h_data) } as *const u16;
                if !p_data.is_null() {
                    let mut len = 0;
                    unsafe {
                        while len < max_chars && *p_data.add(len) != 0 {
                            len += 1;
                        }
                        let slice = std::slice::from_raw_parts(p_data, len.min(120));
                        text_preview = Some(String::from_utf16_lossy(slice));
                        GlobalUnlock(h_data);
                    }
                }
            }
        }

        unsafe { CloseClipboard() };

        Some(ClipboardSnapshot {
            formats,
            text_preview,
            files,
        })
    }

    unsafe extern "system" fn wnd_proc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        match msg {
            WM_DESTROY => {
                let _ = RemoveClipboardFormatListener(hwnd);
                PostQuitMessage(0);
                0
            }
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }

    pub fn run_owner_checker() {
        let current_pid = unsafe { GetCurrentProcessId() };
        println!("================================================================================");
        println!("  [checkOwner] 剪贴板属主验证探针 (GetClipboardOwner Diagnostic CLI)");
        println!("  当前探针进程 PID: {}", current_pid);
        println!("  监听模式: AddClipboardFormatListener (等待剪贴板变化)...");
        println!("  提示: 请尝试在沙箱内复制文本/文件、以及在宿主机复制触发 aTrust 注入进行观察对比");
        println!("================================================================================\n");

        unsafe {
            let class_name = "CHECK_OWNER_PROBE_WND\0".encode_utf16().collect::<Vec<u16>>();
            let wnd_class = WNDCLASSEXW {
                cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
                style: 0,
                lpfnWndProc: Some(wnd_proc),
                cbClsExtra: 0,
                cbWndExtra: 0,
                hInstance: 0 as _,
                hIcon: 0 as _,
                hCursor: 0 as _,
                hbrBackground: 0 as _,
                lpszMenuName: null(),
                lpszClassName: class_name.as_ptr(),
                hIconSm: 0 as _,
            };

            RegisterClassExW(&wnd_class);

            let hwnd = CreateWindowExW(
                0,
                class_name.as_ptr(),
                null(),
                0,
                0,
                0,
                0,
                0,
                HWND_MESSAGE,
                0 as _,
                0 as _,
                null(),
            );

            if hwnd.is_null() {
                eprintln!("[ERROR] 创建隐藏监听窗口失败: {}", std::io::Error::last_os_error());
                return;
            }

            LISTENER_HWND.store(hwnd as isize, Ordering::Release);

            if AddClipboardFormatListener(hwnd) == 0 {
                eprintln!("[ERROR] AddClipboardFormatListener 注册失败: {}", std::io::Error::last_os_error());
                DestroyWindow(hwnd);
                return;
            }

            println!("[READY] 剪贴板监听器已就绪 (HWND: 0x{:08X})，请开始测试复制操作...\n", hwnd as usize);

            let mut msg: MSG = std::mem::zeroed();
            while GetMessageW(&mut msg, 0 as _, 0, 0) > 0 {
                if msg.message == WM_CLIPBOARDUPDATE {
                    handle_clipboard_event(current_pid);
                }
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }

            RemoveClipboardFormatListener(hwnd);
        }
    }

    fn handle_clipboard_event(current_pid: u32) {
        let event_id = EVENT_COUNTER.fetch_add(1, Ordering::Relaxed) + 1;
        let now = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");

        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("[{}] 🔔 收到剪贴板更新事件 [EVENT #{}]", now, event_id);
        println!("────────────────────────────────────────────────────────────────────────────────");

        // 1. 属主窗口 (GetClipboardOwner)
        let owner_hwnd = unsafe { GetClipboardOwner() };
        let owner_info = inspect_window(owner_hwnd);

        println!("1. 剪贴板属主窗口 (GetClipboardOwner):");
        if owner_hwnd.is_null() {
            println!("   * HWND: 0x00000000 (NULL)");
            println!("   * 说明: 属主窗口句柄为 NULL（源程序调用了 OpenClipboard(NULL) 后写入并清空）");
        } else if let Some(ref o) = owner_info {
            println!("   * HWND: 0x{:08X}", o.hwnd);
            println!("   * 类名 (ClassName): {:?}", o.class_name);
            println!("   * 标题 (Title):     {:?}", o.title);
            println!("   * 属主进程 (Process):");
            println!("     - PID: {}, TID: {}", o.pid, o.tid);
            println!("     - 进程文件名: {:?}", o.exe_name);
            println!("     - 完整路径:   {:?}", o.full_path);
        } else {
            println!("   * HWND: 0x{:08X} (无法获取窗口详情，可能已销毁)", owner_hwnd as usize);
        }

        // 2. 当前前台焦点窗口 (GetForegroundWindow)
        let fg_hwnd = unsafe { GetForegroundWindow() };
        let fg_info = inspect_window(fg_hwnd);

        println!("\n2. 当前前台活动窗口 (GetForegroundWindow):");
        if fg_hwnd.is_null() {
            println!("   * HWND: 0x00000000 (NULL - 当前系统无前台活动窗口)");
        } else if let Some(ref fg) = fg_info {
            println!("   * HWND: 0x{:08X}", fg.hwnd);
            println!("   * 类名 (ClassName): {:?}", fg.class_name);
            println!("   * 标题 (Title):     {:?}", fg.title);
            println!("   * 前台进程 (Process):");
            println!("     - PID: {}, TID: {}", fg.pid, fg.tid);
            println!("     - 进程文件名: {:?}", fg.exe_name);
            println!("     - 完整路径:   {:?}", fg.full_path);
        } else {
            println!("   * HWND: 0x{:08X} (无法获取窗口详情)", fg_hwnd as usize);
        }

        // 3. 剪贴板内容快照与格式探测
        println!("\n3. 剪贴板格式与内容探测:");
        if let Some(snapshot) = snapshot_clipboard() {
            let fmt_names: Vec<&str> = snapshot.formats.iter().map(|(_, name)| name.as_str()).collect();
            println!("   * 可用格式列表 ({} 种): {:?}", fmt_names.len(), fmt_names);

            if let Some(ref files) = snapshot.files {
                println!("   * [CF_HDROP] 检测到文件/文件夹复制 (共 {} 项):", files.len());
                for (idx, path) in files.iter().enumerate().take(5) {
                    println!("     [{}] {:?}", idx + 1, path);
                }
                if files.len() > 5 {
                    println!("     ... 剩余 {} 项已折叠", files.len() - 5);
                }
            } else if let Some(ref text) = snapshot.text_preview {
                println!("   * [CF_UNICODETEXT] 检测到文本内容 (前 120 字符):");
                println!("     {:?}", text);
            } else {
                println!("   * [OTHER] 未检测到 CF_HDROP 或 CF_UNICODETEXT，属于其他私有或图片格式");
            }
        } else {
            println!("   * ⚠️ OpenClipboard 失败 (可能被占用或在微秒级时间内已被关闭)");
        }

        // 4. 前置有效性规则评估 (Rule Evaluation & Verdict)
        println!("\n4. 判定规则比对与诊断结果 (Diagnostic Verdict):");
        let (verdict_level, verdict_msg) = evaluate_rules(
            current_pid,
            owner_hwnd,
            owner_info.as_ref(),
            fg_hwnd,
            fg_info.as_ref(),
        );

        println!("   * 诊断结论: [{}] {}", verdict_level, verdict_msg);
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    }

    fn evaluate_rules(
        current_pid: u32,
        owner_hwnd: HWND,
        owner: Option<&WindowDetails>,
        _fg_hwnd: HWND,
        fg: Option<&WindowDetails>,
    ) -> (&'static str, String) {
        // 规则 1: 属主是否属于自身进程
        if let Some(o) = owner {
            if o.pid == current_pid {
                return (
                    "IGNORE / SELF",
                    "属主进程即为探针自身进程 (PID match)，属于自发自收回环，应直接忽略".to_string(),
                );
            }
        }

        // 规则 2: 属主窗口是否为 NULL
        if owner_hwnd.is_null() {
            return (
                "INTERCEPT / NULL_OWNER",
                "⚠️ 属主窗口为 NULL！极可能属于外部服务后台调用 OpenClipboard(NULL) 静默注入 (建议拦截回流)".to_string(),
            );
        }

        // 规则 3: 属主进程是否带有明显的外部/aTrust 特征
        if let Some(o) = owner {
            let lower_name = o.exe_name.to_lowercase();
            let lower_path = o.full_path.to_lowercase();
            if lower_name.contains("atrust")
                || lower_name.contains("sangfor")
                || lower_name.contains("ecagent")
                || lower_path.contains("atrust")
                || lower_path.contains("sangfor")
            {
                return (
                    "INTERCEPT / EXTERNAL_AGENT",
                    format!(
                        "⚠️ 属主进程命中已知 aTrust/Sangfor 代理签名 ('{}' PID: {})，百分之百属于外部注入，必须拦截！",
                        o.exe_name, o.pid
                    ),
                );
            }
        }

        // 规则 4: 属主进程与前台焦点进程一致性检查
        match (owner, fg) {
            (Some(o), Some(f)) => {
                if o.pid == f.pid {
                    (
                        "ACCEPT / LOCAL_USER_COPY",
                        format!(
                            "✅ 属主进程 ('{}' PID: {}) 与当前用户前台活动进程一致！确认属于沙箱内用户主动复制操作，应正常同步向 Host",
                            o.exe_name, o.pid
                        ),
                    )
                } else {
                    (
                        "SUSPICIOUS / PID_MISMATCH",
                        format!(
                            "⚠️ 属主进程 ('{}' PID: {}) 与前台活动进程 ('{}' PID: {}) 不一致！可能属于后台服务注入或后台软件复制",
                            o.exe_name, o.pid, f.exe_name, f.pid
                        ),
                    )
                }
            }
            (Some(o), None) => {
                (
                    "SUSPICIOUS / NO_FOREGROUND",
                    format!(
                        "⚠️ 当前沙箱无前台活动窗口，但属主为 '{}' (PID: {})。当用户在宿主机操作时沙箱常处于无焦点状态，倾向于判定为外部注入",
                        o.exe_name, o.pid
                    ),
                )
            }
            _ => (
                "UNKNOWN",
                "无法完整判定属主或前台信息".to_string(),
            ),
        }
    }
}

#[cfg(windows)]
fn main() {
    win_impl::run_owner_checker();
}

#[cfg(not(windows))]
fn main() {
    println!("checkOwner 是一个专用于 Windows 10 平台的剪贴板属主探针工具。");
    println!("请在 Windows 10 机器或沙箱内使用 `cargo run --release` 编译运行。");
}
