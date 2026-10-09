//! 注册表搜索模块（多线程版：工作窃取队列）
//!
//! 白名单从 whitelist.yaml 加载（取 system_critical 部分），
//! 若文件缺失或解析失败则使用空白名单（不跳过任何路径）。
//!
//! 多线程策略：
//! - search_all 把 6 个物理根作为种子任务放入共享工作队列：
//!     * HKLM\Software\Classes  +  HKCU\Software\Classes
//!       （两者合并 = HKEY_CLASSES_ROOT 的全部内容，展示路径仍为 HKEY_CLASSES_ROOT）
//!     * HKEY_CURRENT_USER / HKEY_LOCAL_MACHINE / HKEY_USERS / HKEY_CURRENT_CONFIG
//! - 多个 worker 线程从队列取任务，取到后用 (根 HKEY, 相对路径) 重新打开该键；
//! - 对每个子键，向队列 push 一个新任务（相对路径 = 父相对路径 + "\\" + 子键名）；
//! - worker 内维护本地 processed / found 计数，批量 flush 到共享原子；
//! - 队列 pending 计数归零时唤醒所有 worker 退出，主线程 join 后合并结果。
//!
//! 不漏注册表：所有根键、所有子键、所有值均入队/枚举，不做任何剪枝。
//!
//! 注意：`winreg::HKEY` 是 `*mut c_void`，**不是 `Send`**，
//! 因此队列任务里存 `isize`（HKEY 的数值），worker 内再还原为 `HKEY` 常量。

use std::collections::VecDeque;
use std::fmt;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use winreg::enums::*;
use winreg::{RegKey, RegValue};

use serde::Deserialize;

/// 只请求需要的权限：读值 + 枚举子键。
/// 不请求 KEY_NOTIFY / READ_CONTROL 等，减少权限检查开销。
const MINIMAL_READ: u32 = KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS;

/// 对应 YAML 根结构（只取 system_critical）
#[derive(Debug, Deserialize)]
struct YamlWhitelist {
    system_critical: Vec<String>,
}

// ============================================================
// 根键标签（保留 API 兼容）
// ============================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RootKey {
    ClassesRoot,
    CurrentUser,
    LocalMachine,
    Users,
    CurrentConfig,
}

impl RootKey {
    #[allow(dead_code)]
    #[inline]
    fn to_hkey(self) -> winreg::HKEY {
        match self {
            RootKey::ClassesRoot => HKEY_CLASSES_ROOT,
            RootKey::CurrentUser => HKEY_CURRENT_USER,
            RootKey::LocalMachine => HKEY_LOCAL_MACHINE,
            RootKey::Users => HKEY_USERS,
            RootKey::CurrentConfig => HKEY_CURRENT_CONFIG,
        }
    }

    #[allow(dead_code)]
    #[inline]
    fn name(self) -> &'static str {
        match self {
            RootKey::ClassesRoot => "HKEY_CLASSES_ROOT",
            RootKey::CurrentUser => "HKEY_CURRENT_USER",
            RootKey::LocalMachine => "HKEY_LOCAL_MACHINE",
            RootKey::Users => "HKEY_USERS",
            RootKey::CurrentConfig => "HKEY_CURRENT_CONFIG",
        }
    }

    #[inline]
    fn from_name(name: &str) -> Option<Self> {
        match name {
            "HKEY_CLASSES_ROOT" => Some(RootKey::ClassesRoot),
            "HKEY_CURRENT_USER" => Some(RootKey::CurrentUser),
            "HKEY_LOCAL_MACHINE" => Some(RootKey::LocalMachine),
            "HKEY_USERS" => Some(RootKey::Users),
            "HKEY_CURRENT_CONFIG" => Some(RootKey::CurrentConfig),
            _ => None,
        }
    }
}

// ============================================================
// 物理根（用于工作队列种子，HKCR 拆为两个）
// ============================================================

#[derive(Debug, Clone, Copy)]
enum PhysRoot {
    /// HKEY_LOCAL_MACHINE\Software\Classes（HKCR 的 LM 部分）
    HkcrLm,
    /// HKEY_CURRENT_USER\Software\Classes（HKCR 的 CU 部分）
    HkcrCu,
    /// 原始 HKEY_CLASSES_ROOT（仅 search_root 单根语义使用）
    ClassesRoot,
    CurrentUser,
    LocalMachine,
    Users,
    CurrentConfig,
}

impl PhysRoot {
    #[inline]
    fn to_hkey(self) -> winreg::HKEY {
        match self {
            PhysRoot::HkcrLm | PhysRoot::LocalMachine => HKEY_LOCAL_MACHINE,
            PhysRoot::HkcrCu | PhysRoot::CurrentUser => HKEY_CURRENT_USER,
            PhysRoot::ClassesRoot => HKEY_CLASSES_ROOT,
            PhysRoot::Users => HKEY_USERS,
            PhysRoot::CurrentConfig => HKEY_CURRENT_CONFIG,
        }
    }

    /// 种子任务相对于根 HKEY 的子路径（None 表示根本身）
    #[inline]
    fn seed_subpath(self) -> Option<&'static str> {
        match self {
            PhysRoot::HkcrLm => Some("Software\\Classes"),
            PhysRoot::HkcrCu => Some("Software\\Classes"),
            _ => None,
        }
    }

    /// 展示用根标签（HkcrLm/HkcrCu/ClassesRoot 统一显示为 HKEY_CLASSES_ROOT）
    #[inline]
    fn display_label(self) -> &'static str {
        match self {
            PhysRoot::HkcrLm | PhysRoot::HkcrCu | PhysRoot::ClassesRoot => "HKEY_CLASSES_ROOT",
            PhysRoot::CurrentUser => "HKEY_CURRENT_USER",
            PhysRoot::LocalMachine => "HKEY_LOCAL_MACHINE",
            PhysRoot::Users => "HKEY_USERS",
            PhysRoot::CurrentConfig => "HKEY_CURRENT_CONFIG",
        }
    }
}

// ============================================================
// 白名单（按首字节分桶）
// ============================================================

#[derive(Debug, Clone)]
pub struct Whitelist {
    buckets: Vec<Vec<String>>,
    empty: bool,
}

impl Whitelist {
    pub fn new(prefixes: Vec<String>) -> Self {
        let mut buckets: Vec<Vec<String>> = vec![Vec::new(); 256];
        for p in prefixes {
            if p.is_empty() {
                continue;
            }
            let lower = p.to_lowercase();
            let first = lower.as_bytes()[0];
            buckets[first as usize].push(lower);
        }
        let empty = buckets.iter().all(|v| v.is_empty());
        Self { buckets, empty }
    }

    #[inline]
    pub fn is_whitelisted(&self, path: &str) -> bool {
        if self.empty {
            return false;
        }
        let bytes = path.as_bytes();
        if bytes.is_empty() {
            return false;
        }
        let first = bytes[0].to_ascii_lowercase();
        let list = &self.buckets[first as usize];
        if list.is_empty() {
            return false;
        }
        list.iter().any(|p| {
            let pb = p.as_bytes();
            if pb.is_empty() || pb[0] != first {
                return false;
            }
            bytes.len() >= pb.len() && bytes[..pb.len()].eq_ignore_ascii_case(pb)
        })
    }

    pub fn from_yaml_file(path: &str) -> Option<Self> {
        let content = std::fs::read_to_string(path).ok()?;
        let parsed: YamlWhitelist = serde_yaml::from_str(&content).ok()?;
        Some(Self::new(parsed.system_critical))
    }
}

// ============================================================
// 匹配类型 / 搜索结果 / 搜索配置
// ============================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchType {
    Item,
    Key,
    Value,
}

impl fmt::Display for MatchType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MatchType::Item => write!(f, "键名"),
            MatchType::Key => write!(f, "值名"),
            MatchType::Value => write!(f, "值数据"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SearchResult {
    pub key_path: String,
    pub value_name: Option<String>,
    pub value_data: Option<String>,
    pub match_type: MatchType,
}

impl SearchResult {
    pub fn new(key_path: String, match_type: MatchType) -> Self {
        Self {
            key_path,
            value_name: None,
            value_data: None,
            match_type,
        }
    }

    pub fn with_value_name(mut self, name: String) -> Self {
        self.value_name = Some(name);
        self
    }

    pub fn with_value_data(mut self, data: String) -> Self {
        self.value_data = Some(data);
        self
    }
}

#[derive(Debug, Clone)]
pub struct SearchConfig {
    pub search_key_names: bool,
    pub search_value_names: bool,
    pub search_value_data: bool,
}

impl Default for SearchConfig {
    fn default() -> Self {
        Self {
            search_key_names: true,
            search_value_names: true,
            search_value_data: true,
        }
    }
}

// ============================================================
// 字符串大小写不敏感匹配（BMH，重复字符取最小 skip）
// ============================================================

fn bytes_contains_ascii_ci(haystack: &[u8], needle_lower: &[u8]) -> bool {
    let n = needle_lower.len();
    if n == 0 {
        return true;
    }
    let h = haystack.len();
    if h < n {
        return false;
    }
    if n == 1 {
        let c = needle_lower[0];
        return haystack.iter().any(|&b| b.to_ascii_lowercase() == c);
    }

    let mut skip = [n as u8; 256];
    for i in 0..n - 1 {
        let d = (n - 1 - i) as u8;
        let lo = needle_lower[i];
        let up = lo.to_ascii_uppercase();
        if skip[lo as usize] == n as u8 || d < skip[lo as usize] {
            skip[lo as usize] = d;
        }
        if up != lo && (skip[up as usize] == n as u8 || d < skip[up as usize]) {
            skip[up as usize] = d;
        }
    }

    let last = n - 1;
    let mut i = 0usize;
    while i + n <= h {
        let hb = haystack[i + last].to_ascii_lowercase();
        if hb == needle_lower[last] {
            let mut ok = true;
            for j in 0..last {
                if haystack[i + j].to_ascii_lowercase() != needle_lower[j] {
                    ok = false;
                    break;
                }
            }
            if ok {
                return true;
            }
        }
        i += skip[hb as usize] as usize;
    }
    false
}

fn str_contains_ci(haystack: &str, needle_lower: &str) -> bool {
    if needle_lower.is_empty() {
        return true;
    }
    let h = haystack.as_bytes();
    let n = needle_lower.as_bytes();
    if h.len() < n.len() {
        return false;
    }

    if needle_lower.is_ascii() {
        if bytes_contains_ascii_ci(h, n) {
            return true;
        }
        if haystack.is_ascii() {
            return false;
        }
        haystack.to_lowercase().contains(needle_lower)
    } else {
        haystack.to_lowercase().contains(needle_lower)
    }
}

// ============================================================
// 动画状态
// ============================================================

struct Spinner {
    processed: Arc<AtomicUsize>,
    found: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
    start_time: Instant,
    enabled: bool,
}

impl Spinner {
    fn new(found: Arc<AtomicUsize>, enabled: bool) -> Self {
        let processed = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));

        let handle = if enabled {
            let processed_c = processed.clone();
            let found_c = found.clone();
            let stop_c = stop.clone();
            let start = Instant::now();
            Some(thread::spawn(move || {
                const FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
                let mut i = 0usize;
                print!("\r\x1b[2K  {} 准备中…", FRAMES[0]);
                let _ = std::io::Write::flush(&mut std::io::stdout());
                while !stop_c.load(Ordering::Relaxed) {
                    thread::sleep(Duration::from_millis(80));
                    if stop_c.load(Ordering::Relaxed) {
                        break;
                    }
                    let p = processed_c.load(Ordering::Relaxed);
                    let f = found_c.load(Ordering::Relaxed);
                    let elapsed = format_duration(start.elapsed());
                    print!(
                        "\r\x1b[2K  {} 已处理: {} 个键 · 命中: {} · 已用: {}",
                        FRAMES[i % FRAMES.len()],
                        p,
                        f,
                        elapsed
                    );
                    let _ = std::io::Write::flush(&mut std::io::stdout());
                    i += 1;
                }
            }))
        } else {
            None
        };

        Self {
            processed,
            found,
            stop,
            handle,
            start_time: Instant::now(),
            enabled,
        }
    }

    fn finish(mut self) {
        if !self.enabled {
            return;
        }
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        let p = self.processed.load(Ordering::Relaxed);
        let f = self.found.load(Ordering::Relaxed);
        print!("\r\x1b[2K");
        println!(
            "  ✅ 已处理: {} 个键 · 命中: {} · 用时: {}",
            p,
            f,
            format_duration(self.start_time.elapsed())
        );
        let _ = std::io::Write::flush(&mut std::io::stdout());
    }
}

fn format_duration(duration: Duration) -> String {
    let total_secs = duration.as_secs();
    let hours = total_secs / 3600;
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;
    if hours > 0 {
        format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
    } else {
        format!("{:02}:{:02}", minutes, seconds)
    }
}

// ============================================================
// 值匹配辅助
// ============================================================

fn utf16_bytes_contains_ascii_ci(bytes: &[u8], needle_lower: &[u8]) -> bool {
    let n = needle_lower.len();
    if n == 0 {
        return true;
    }
    let hay_len = bytes.len() / 2;
    if hay_len < n {
        return false;
    }
    if n == 1 {
        let c = needle_lower[0];
        let mut idx = 0usize;
        while idx + 1 < bytes.len() {
            if bytes[idx + 1] == 0 && bytes[idx].to_ascii_lowercase() == c {
                return true;
            }
            idx += 2;
        }
        return false;
    }

    let last = n - 1;
    let mut skip = [n as u8; 256];
    for i in 0..last {
        let d = (last - i) as u8;
        let lo = needle_lower[i];
        let up = lo.to_ascii_uppercase();
        if skip[lo as usize] == n as u8 || d < skip[lo as usize] {
            skip[lo as usize] = d;
        }
        if up != lo && (skip[up as usize] == n as u8 || d < skip[up as usize]) {
            skip[up as usize] = d;
        }
    }

    let limit = hay_len - n;
    let mut start = 0usize;
    'outer: while start <= limit {
        let end_idx = (start + last) * 2;
        let hi = bytes[end_idx + 1];
        if hi != 0 {
            let step = skip[hi as usize] as usize;
            start += if step == 0 { 1 } else { step };
            continue;
        }
        let lo = bytes[end_idx];
        let hb = lo.to_ascii_lowercase();
        if hb == needle_lower[last] {
            for j in 0..last {
                let idx = (start + j) * 2;
                if bytes[idx + 1] != 0 || bytes[idx].to_ascii_lowercase() != needle_lower[j] {
                    let step = skip[hb as usize] as usize;
                    start += if step == 0 { 1 } else { step };
                    continue 'outer;
                }
            }
            return true;
        }
        let step = skip[hb as usize] as usize;
        start += if step == 0 { 1 } else { step };
    }
    false
}

fn utf16_bytes_contains_ci(bytes: &[u8], keyword_lower: &str, needle_lower_ascii: &[u8]) -> bool {
    if utf16_bytes_contains_ascii_ci(bytes, needle_lower_ascii) {
        return true;
    }
    let mut has_non_ascii = false;
    let mut i = 1usize;
    while i < bytes.len() {
        if bytes[i] != 0 {
            has_non_ascii = true;
            break;
        }
        i += 2;
    }
    if !has_non_ascii {
        return false;
    }
    utf16_bytes_to_string(bytes)
        .to_lowercase()
        .contains(keyword_lower)
}

fn utf16_bytes_to_string(bytes: &[u8]) -> String {
    let len = bytes.len() / 2 * 2;
    let chars: Vec<u16> = bytes[..len]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&c| c != 0)
        .collect();
    String::from_utf16_lossy(&chars)
}

#[inline]
fn fmt_u64_into(buf: &mut [u8; 24], mut n: u64) -> &str {
    if n == 0 {
        buf[0] = b'0';
        return std::str::from_utf8(&buf[..1]).unwrap();
    }
    let mut i = buf.len();
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    std::str::from_utf8(&buf[i..]).unwrap()
}

#[inline]
fn fmt_u64_hex_into(buf: &mut [u8; 20], mut n: u64) -> &str {
    let digits = if n == 0 {
        1
    } else {
        let mut d = 0usize;
        let mut t = n;
        while t > 0 {
            d += 1;
            t >>= 4;
        }
        d
    };
    let total = 2 + digits;
    buf[0] = b'0';
    buf[1] = b'x';
    let mut i = total;
    if n == 0 {
        i -= 1;
        buf[i] = b'0';
    } else {
        while n > 0 {
            i -= 1;
            let d = (n & 0xF) as u8;
            buf[i] = if d < 10 { b'0' + d } else { b'a' + (d - 10) };
            n >>= 4;
        }
    }
    std::str::from_utf8(&buf[..total]).unwrap()
}

fn dword_qword_match(n: u64, _width: usize, keyword_lower: &str) -> bool {
    let klen = keyword_lower.len();
    if klen == 0 {
        return true;
    }
    let mut buf = [0u8; 24];
    let dec = fmt_u64_into(&mut buf, n);
    if dec.len() >= klen && str_contains_ci(dec, keyword_lower) {
        return true;
    }
    let mut hbuf = [0u8; 20];
    let hex = fmt_u64_hex_into(&mut hbuf, n);
    if hex.len() >= klen && str_contains_ci(hex, keyword_lower) {
        return true;
    }
    if hex.len() > 2 && hex.len() - 2 >= klen && str_contains_ci(&hex[2..], keyword_lower) {
        return true;
    }
    false
}

fn value_matches(value: &RegValue, keyword_lower: &str, keyword_lower_ascii: &[u8]) -> bool {
    match value.vtype {
        REG_SZ | REG_EXPAND_SZ | REG_MULTI_SZ => {
            utf16_bytes_contains_ci(&value.bytes, keyword_lower, keyword_lower_ascii)
        }
        REG_DWORD => {
            if value.bytes.len() < 4 {
                return false;
            }
            let n = u32::from_le_bytes([
                value.bytes[0],
                value.bytes[1],
                value.bytes[2],
                value.bytes[3],
            ]) as u64;
            dword_qword_match(n, 4, keyword_lower)
        }
        REG_QWORD => {
            if value.bytes.len() < 8 {
                return false;
            }
            let n = u64::from_le_bytes([
                value.bytes[0],
                value.bytes[1],
                value.bytes[2],
                value.bytes[3],
                value.bytes[4],
                value.bytes[5],
                value.bytes[6],
                value.bytes[7],
            ]);
            dword_qword_match(n, 8, keyword_lower)
        }
        REG_BINARY => {
            if keyword_lower_ascii.is_empty() {
                return true;
            }
            if !keyword_lower_ascii.is_ascii() {
                return false;
            }
            bytes_contains_ascii_ci(&value.bytes, keyword_lower_ascii)
        }
        _ => false,
    }
}

// ============================================================
// 线程共享的只读上下文
// ============================================================

struct SharedCtx {
    config: SearchConfig,
    whitelist: Whitelist,
    pattern: String,
    keyword_lower_ascii: Vec<u8>,
    found_count: Arc<AtomicUsize>,
    processed: Arc<AtomicUsize>,
}

// ============================================================
// 工作队列
// ============================================================

/// 一个待扫描的任务：根 HKEY（数值形式，Send）+ 相对根的路径 + 展示用完整路径前缀。
struct WorkItem {
    /// 根 HKEY 的数值形式（isize 是 Send）
    hkey_raw: isize,
    /// 相对于根 HKEY 的子路径（用于 open_subkey_with_flags），根本身为空串
    rel_path: String,
    /// 展示用完整路径（根标签 + rel_path 的拼接），用于结果 key_path
    display_path: String,
}

struct WorkQueue {
    inner: Mutex<VecDeque<WorkItem>>,
    /// 未完成任务数（含尚未入队的子任务）
    pending: AtomicUsize,
    cv: Condvar,
    shutdown: AtomicBool,
}

impl WorkQueue {
    fn new() -> Self {
        Self {
            inner: Mutex::new(VecDeque::new()),
            pending: AtomicUsize::new(0),
            cv: Condvar::new(),
            shutdown: AtomicBool::new(false),
        }
    }

    /// 入队一个任务（pending +1）
    #[inline]
    fn push(&self, item: WorkItem) {
        self.pending.fetch_add(1, Ordering::Relaxed);
        let mut g = self.inner.lock().unwrap();
        g.push_back(item);
        self.cv.notify_one();
    }

    /// 取一个任务；若无任务且 pending 为 0，返回 None 表示全部完成。
    fn pop(&self) -> Option<WorkItem> {
        let mut g = self.inner.lock().unwrap();
        loop {
            if let Some(x) = g.pop_front() {
                return Some(x);
            }
            if self.pending.load(Ordering::Acquire) == 0 {
                return None;
            }
            g = self.cv.wait(g).unwrap();
            if self.shutdown.load(Ordering::Relaxed) && g.is_empty() {
                return None;
            }
        }
    }

    /// 完成一个任务（pending -1）；若归零则唤醒所有等待者。
    #[inline]
    fn done(&self) {
        if self.pending.fetch_sub(1, Ordering::AcqRel) == 1 {
            let _g = self.inner.lock().unwrap();
            self.cv.notify_all();
        }
    }
}

// ============================================================
// 注册表搜索器
// ============================================================

pub struct RegistrySearcher {
    config: SearchConfig,
    found_count: Arc<AtomicUsize>,
    whitelist: Whitelist,
    workers: usize,
}

impl RegistrySearcher {
    pub fn new() -> Self {
        let whitelist = Whitelist::from_yaml_file("whitelist.yaml").unwrap_or_else(|| {
            eprintln!("  ⚠️  未找到 whitelist.yaml 或解析失败，使用空白名单（不跳过任何路径）");
            Whitelist::new(Vec::new())
        });

        Self {
            config: SearchConfig::default(),
            found_count: Arc::new(AtomicUsize::new(0)),
            whitelist,
            workers: default_workers(),
        }
    }

    #[allow(dead_code)]
    pub fn with_whitelist(mut self, whitelist: Whitelist) -> Self {
        self.whitelist = whitelist;
        self
    }

    /// 设置 worker 线程数（1..=64）
    #[allow(dead_code)]
    pub fn with_workers(mut self, workers: usize) -> Self {
        self.workers = workers.clamp(1, 64);
        self
    }

    pub fn search_all(
        &self,
        keyword: &str,
    ) -> Result<Vec<SearchResult>, Box<dyn std::error::Error>> {
        let pattern = keyword.to_lowercase();
        let keyword_lower_ascii = pattern.clone().into_bytes();

        // ---------- 顶部标题 ----------
        println!();
        println!("  ─────────────────────────────────────────────────────");
        println!("              🔍 注册表搜索（工作窃取队列）");
        println!("  ─────────────────────────────────────────────────────");
        println!("     关键字  : {}", keyword);
        let items = format!(
            "{}{}{}",
            if self.config.search_key_names {
                "键名 "
            } else {
                ""
            },
            if self.config.search_value_names {
                "值名 "
            } else {
                ""
            },
            if self.config.search_value_data {
                "值数据"
            } else {
                ""
            },
        );
        println!("     搜索项  : {}", items.trim());
        println!("     线程数  : {}（工作窃取）", self.workers);
        println!("  ─────────────────────────────────────────────────────");
        println!();

        self.found_count.store(0, Ordering::Relaxed);
        let spinner = Spinner::new(self.found_count.clone(), true);
        let search_start = Instant::now();

        let shared = Arc::new(SharedCtx {
            config: self.config.clone(),
            whitelist: self.whitelist.clone(),
            pattern: pattern.clone(),
            keyword_lower_ascii: keyword_lower_ascii.clone(),
            found_count: self.found_count.clone(),
            processed: spinner.processed.clone(),
        });

        // 6 个物理根种子任务
        let seeds: [PhysRoot; 6] = [
            PhysRoot::HkcrLm,
            PhysRoot::HkcrCu,
            PhysRoot::CurrentUser,
            PhysRoot::LocalMachine,
            PhysRoot::Users,
            PhysRoot::CurrentConfig,
        ];

        let queue = Arc::new(WorkQueue::new());
        for pr in seeds.iter() {
            let hkey_raw = pr.to_hkey() as isize;
            let (rel_path, display_path) = match pr.seed_subpath() {
                Some(sub) => {
                    let disp = format!("{}\\{}", pr.display_label(), sub);
                    (sub.to_string(), disp)
                }
                None => (String::new(), pr.display_label().to_string()),
            };
            queue.push(WorkItem {
                hkey_raw,
                rel_path,
                display_path,
            });
        }

        // spawn workers
        let n_workers = self.workers.max(1).min(64);
        let mut handles: Vec<thread::JoinHandle<Vec<SearchResult>>> = Vec::with_capacity(n_workers);

        for _ in 0..n_workers {
            let q = queue.clone();
            let ctx = shared.clone();
            let h = thread::spawn(move || worker_loop(q, ctx));
            handles.push(h);
        }

        // join 并合并
        let mut all_results: Vec<SearchResult> = Vec::new();
        for h in handles {
            match h.join() {
                Ok(mut partial) => all_results.append(&mut partial),
                Err(_) => {
                    eprintln!("  ⚠️  某个搜索线程 panic，已跳过");
                }
            }
        }

        let elapsed = search_start.elapsed();
        spinner.finish();

        let found = self.found_count.load(Ordering::Relaxed);
        println!();
        println!("  ─────────────────────────────────────────────────────");
        println!("              ✅ 搜索完成");
        println!("  ─────────────────────────────────────────────────────");
        println!("     匹配项  : {}", found);
        println!("     搜索耗时: {}", format_duration(elapsed));
        println!("  ─────────────────────────────────────────────────────");
        println!();

        Ok(all_results)
    }

    #[allow(dead_code)]
    pub fn search_root(
        &self,
        root_key: winreg::HKEY,
        root_name: &str,
        keyword: &str,
    ) -> Result<Vec<SearchResult>, Box<dyn std::error::Error>> {
        let root = RootKey::from_name(root_name)
            .ok_or_else(|| format!("search_root: 未知根键名 {}", root_name))?;
        let _ = root_key;

        // 单根语义：HKCR 直接走合并视图
        let phys = match root {
            RootKey::ClassesRoot => PhysRoot::ClassesRoot,
            RootKey::CurrentUser => PhysRoot::CurrentUser,
            RootKey::LocalMachine => PhysRoot::LocalMachine,
            RootKey::Users => PhysRoot::Users,
            RootKey::CurrentConfig => PhysRoot::CurrentConfig,
        };

        let pattern = keyword.to_lowercase();
        let keyword_lower_ascii = pattern.clone().into_bytes();

        self.found_count.store(0, Ordering::Relaxed);

        println!();
        println!("  🔍 开始搜索 {}（单根工作队列）…", root_name);
        println!();

        let spinner = Spinner::new(self.found_count.clone(), true);
        let search_start = Instant::now();

        let shared = Arc::new(SharedCtx {
            config: self.config.clone(),
            whitelist: self.whitelist.clone(),
            pattern,
            keyword_lower_ascii,
            found_count: self.found_count.clone(),
            processed: spinner.processed.clone(),
        });

        let queue = Arc::new(WorkQueue::new());
        let hkey_raw = phys.to_hkey() as isize;
        let (rel_path, display_path) = match phys.seed_subpath() {
            Some(sub) => {
                let disp = format!("{}\\{}", phys.display_label(), sub);
                (sub.to_string(), disp)
            }
            None => (String::new(), phys.display_label().to_string()),
        };
        queue.push(WorkItem {
            hkey_raw,
            rel_path,
            display_path,
        });

        let n_workers = self.workers.max(1).min(64);
        let mut handles = Vec::with_capacity(n_workers);
        for _ in 0..n_workers {
            let q = queue.clone();
            let ctx = shared.clone();
            handles.push(thread::spawn(move || worker_loop(q, ctx)));
        }

        let mut results: Vec<SearchResult> = Vec::new();
        for h in handles {
            if let Ok(mut partial) = h.join() {
                results.append(&mut partial);
            }
        }

        let elapsed = search_start.elapsed();
        spinner.finish();

        let found = self.found_count.load(Ordering::Relaxed);
        println!();
        println!(
            "  ✅ 搜索完成：命中 {} 项，耗时 {}",
            found,
            format_duration(elapsed)
        );
        println!();

        Ok(results)
    }

    #[allow(dead_code)]
    pub fn get_found_count(&self) -> usize {
        self.found_count.load(Ordering::Relaxed)
    }
}

impl Default for RegistrySearcher {
    fn default() -> Self {
        Self::new()
    }
}

fn default_workers() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .clamp(2, 16)
}

// ============================================================
// Worker 主循环（工作窃取）
// ============================================================

fn worker_loop(queue: Arc<WorkQueue>, ctx: Arc<SharedCtx>) -> Vec<SearchResult> {
    let mut results: Vec<SearchResult> = Vec::with_capacity(64);
    let mut local_processed = 0usize;
    let mut local_found = 0usize;

    while let Some(item) = queue.pop() {
        process_item(
            &item,
            &queue,
            &ctx,
            &mut results,
            &mut local_processed,
            &mut local_found,
        );
        queue.done();
        flush_counters(&ctx, &mut local_processed, &mut local_found);
    }

    // 收尾 flush
    if local_processed > 0 {
        ctx.processed.fetch_add(local_processed, Ordering::Relaxed);
    }
    if local_found > 0 {
        ctx.found_count.fetch_add(local_found, Ordering::Relaxed);
    }

    results
}

fn process_item(
    item: &WorkItem,
    queue: &Arc<WorkQueue>,
    ctx: &Arc<SharedCtx>,
    results: &mut Vec<SearchResult>,
    local_processed: &mut usize,
    local_found: &mut usize,
) {
    // 白名单检查
    if ctx.whitelist.is_whitelisted(&item.display_path) {
        *local_processed += 1;
        return;
    }

    // 打开当前键
    let root = RegKey::predef(item.hkey_raw as winreg::HKEY);
    let key = if item.rel_path.is_empty() {
        match root.open_subkey_with_flags("", MINIMAL_READ) {
            Ok(k) => k,
            // 根本身：直接用预定义句柄（不需要 open）
            Err(_) => root,
        }
    } else {
        match root.open_subkey_with_flags(&item.rel_path, MINIMAL_READ) {
            Ok(k) => k,
            Err(_) => {
                *local_processed += 1;
                return;
            }
        }
    };

    // 本键匹配
    let root_label_len = ctx_root_label_len(item);
    let rel_for_match = if item.display_path.len() > root_label_len {
        &item.display_path[root_label_len..]
    } else {
        ""
    };
    scan_current_key(
        &key,
        &item.display_path,
        rel_for_match,
        ctx,
        results,
        local_found,
    );
    *local_processed += 1;

    // 枚举子键，入队
    let base_rel_len = item.rel_path.len();
    let base_disp_len = item.display_path.len();

    // 复用缓冲区，避免每子键 String 分配两次
    let mut child_rel = String::with_capacity(base_rel_len + 64);
    let mut child_disp = String::with_capacity(base_disp_len + 64);

    for subkey_name in key.enum_keys().flatten() {
        // 构建子任务 rel_path / display_path
        child_rel.clear();
        child_rel.push_str(&item.rel_path);
        if !child_rel.is_empty() {
            child_rel.push('\\');
        }
        child_rel.push_str(&subkey_name);

        child_disp.clear();
        child_disp.push_str(&item.display_path);
        child_disp.push('\\');
        child_disp.push_str(&subkey_name);

        // 白名单可在入队前剪枝（避免无谓的 open）
        if ctx.whitelist.is_whitelisted(&child_disp) {
            continue;
        }

        queue.push(WorkItem {
            hkey_raw: item.hkey_raw,
            rel_path: child_rel.clone(),
            display_path: child_disp.clone(),
        });
    }
}

/// 计算 display_path 中"根标签"的长度
fn ctx_root_label_len(item: &WorkItem) -> usize {
    // display_path = 根标签 + ("\\" + rel_path) 或仅根标签
    // 根标签不含 '\\'（HKCR 等标签都是纯大写+下划线）
    // 所以第一个 '\\' 之前的长度就是根标签长度
    match item.display_path.find('\\') {
        Some(i) => i,
        None => item.display_path.len(),
    }
}

#[inline]
fn flush_counters(ctx: &SharedCtx, processed: &mut usize, found: &mut usize) {
    if *processed >= 256 {
        ctx.processed.fetch_add(*processed, Ordering::Relaxed);
        *processed = 0;
    }
    if *found >= 64 {
        ctx.found_count.fetch_add(*found, Ordering::Relaxed);
        *found = 0;
    }
}

// ============================================================
// 当前键扫描
// ============================================================

fn scan_current_key(
    key: &RegKey,
    full_path: &str,
    rel_path: &str,
    ctx: &Arc<SharedCtx>,
    results: &mut Vec<SearchResult>,
    local_found: &mut usize,
) {
    if ctx.config.search_key_names && !rel_path.is_empty() {
        if str_contains_ci(rel_path, &ctx.pattern) {
            results.push(SearchResult::new(full_path.to_string(), MatchType::Item));
            *local_found += 1;
        }
    }

    if ctx.config.search_value_names || ctx.config.search_value_data {
        scan_values(key, full_path, ctx, results, local_found);
    }
}

fn scan_values(
    key: &RegKey,
    full_path: &str,
    ctx: &Arc<SharedCtx>,
    results: &mut Vec<SearchResult>,
    local_found: &mut usize,
) {
    for value_result in key.enum_values() {
        let (name, value) = match value_result {
            Ok(v) => v,
            Err(_) => continue,
        };

        let mut matched_type: Option<MatchType> = None;

        if ctx.config.search_value_names && str_contains_ci(&name, &ctx.pattern) {
            matched_type = Some(MatchType::Key);
        } else if ctx.config.search_value_data
            && value_matches(&value, &ctx.pattern, &ctx.keyword_lower_ascii)
        {
            matched_type = Some(MatchType::Value);
        }

        if let Some(mt) = matched_type {
            let data = format_registry_value(&value);
            results.push(
                SearchResult::new(full_path.to_string(), mt)
                    .with_value_name(name)
                    .with_value_data(data),
            );
            *local_found += 1;
        }
    }
}

// ============================================================
// 注册表值格式化
// ============================================================

pub fn format_registry_value(value: &RegValue) -> String {
    match value.vtype {
        REG_SZ | REG_EXPAND_SZ => format_string_value(value),
        REG_DWORD => format_dword_value(value),
        REG_QWORD => format_qword_value(value),
        REG_MULTI_SZ => format_multi_string_value(value),
        REG_BINARY => format_binary_value(value),
        _ => format!("[类型: {:?}, {}字节]", value.vtype, value.bytes.len()),
    }
}

fn format_string_value(value: &RegValue) -> String {
    let bytes = &value.bytes;
    if bytes.len() < 2 {
        return String::new();
    }
    let len = bytes.len() / 2 * 2;
    let chars: Vec<u16> = bytes[..len]
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .take_while(|&code| code != 0)
        .collect();
    String::from_utf16_lossy(&chars)
}

fn format_dword_value(value: &RegValue) -> String {
    if value.bytes.len() >= 4 {
        let num = u32::from_le_bytes([
            value.bytes[0],
            value.bytes[1],
            value.bytes[2],
            value.bytes[3],
        ]);
        format!("{} (0x{:X})", num, num)
    } else {
        "无效的DWORD".to_string()
    }
}

fn format_qword_value(value: &RegValue) -> String {
    if value.bytes.len() >= 8 {
        let num = u64::from_le_bytes([
            value.bytes[0],
            value.bytes[1],
            value.bytes[2],
            value.bytes[3],
            value.bytes[4],
            value.bytes[5],
            value.bytes[6],
            value.bytes[7],
        ]);
        format!("{} (0x{:X})", num, num)
    } else {
        "无效的QWORD".to_string()
    }
}

fn format_multi_string_value(value: &RegValue) -> String {
    let bytes = &value.bytes;
    let mut strings = Vec::new();
    let mut current = Vec::new();

    let len = bytes.len() / 2 * 2;
    for chunk in bytes[..len].chunks_exact(2) {
        let code = u16::from_le_bytes([chunk[0], chunk[1]]);
        if code == 0 {
            if !current.is_empty() {
                strings.push(String::from_utf16_lossy(&current));
                current.clear();
            }
        } else {
            current.push(code);
        }
    }
    if !current.is_empty() {
        strings.push(String::from_utf16_lossy(&current));
    }

    strings.join("; ")
}

fn format_binary_value(value: &RegValue) -> String {
    if value.bytes.is_empty() {
        "[空二进制]".to_string()
    } else {
        let mut hex = String::with_capacity(value.bytes.len() * 3 + 2);
        hex.push('[');
        for (i, b) in value.bytes.iter().enumerate() {
            if i > 0 {
                hex.push(' ');
            }
            let _ = write!(hex, "{:02X}", b);
        }
        hex.push(']');
        hex
    }
}
