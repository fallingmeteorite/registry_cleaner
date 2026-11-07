//! 注册表搜索模块（多线程版：工作窃取队列）
//!
//! 白名单从 whitelist.yaml 加载（取 system_critical 部分），
//! 若文件缺失或解析失败则使用空白名单（不跳过任何路径）。
//!
//! 多线程策略：
//! - search_with_progress 把 6 个物理根作为种子任务放入共享工作队列：
//!     * HKLM\Software\Classes  +  HKCU\Software\Classes
//!       （两者合并 = HKEY_CLASSES_ROOT 的全部内容，展示路径为 HKEY_CLASSES_ROOT）
//!     * HKEY_CURRENT_USER / HKEY_LOCAL_MACHINE / HKEY_USERS / HKEY_CURRENT_CONFIG
//! - 多个 worker 线程从队列取任务，取到后用 (根 HKEY, 相对路径) 重新打开该键；
//! - 对每个子键，向队列 push 一个新任务（相对路径 = 父相对路径 + "\\" + 子键名）；
//! - worker 内维护本地 processed / found 计数，批量 flush 到共享原子；
//! - 队列 pending 计数归零时唤醒所有 worker 退出，主线程 join 后合并结果。
//!
//! 为什么用 6 个种子（而不是直接用预定义 HKEY_CLASSES_ROOT）：
//!   1. HKCU\Software\Classes 里被 HKLM 同名项遮蔽的键，通过 HKCR 视图**看不到**，
//!      必须单独按 HKCU 全量枚举才能覆盖到；
//!   2. HKCR 的每次 open_subkey 都要合并查 HKLM + HKCU 两侧，开销约为单路 2 倍，
//!      直接枚举 HKCR 反而更慢。
//!
//! 展示路径（display_path）与物理路径（rel_path）解耦：
//!   - 物理：HKLM + "Software\\Classes\\..." / HKCU + "Software\\Classes\\..."
//!   - 展示：统一为 "HKEY_CLASSES_ROOT\\..."（去掉 Software\\Classes 前缀）
//!
//! 注意：`winreg::HKEY` 是 `*mut c_void`，**不是 `Send`**，
//! 因此队列任务里存 `isize`（HKEY 的数值），worker 内再还原为 `HKEY` 常量。
//!
//! ★ 修复要点（相对旧版）：
//!   1. `enum_keys()` / `enum_values()` 的 `Err(_)` 分支在旧版用 `.flatten()` /
//!      `continue` 处理，但 winreg 在枚举出错时不会前进 index，会**死循环**，
//!      同时导致该子树子键不入队 → 整棵子树漏搜。本版改为手动 `loop`，
//!      任一 `Err` 立即 `break`，保证 `done()` 一定执行、子任务不丢。
//!   2. 打开键先尝试 `MINIMAL_READ`，失败再退化为 `KEY_READ`，避免部分系统键
//!      因 ACL 拒绝 `KEY_ENUMERATE_SUB_KEYS` 就整棵子树被跳过。
//!   3. 种子任务用 `is_seed=true` 标记，**不参与白名单剪枝**，
//!      避免一条宽前缀（如 `HKEY_LOCAL_MACHINE`）把整棵根树剪掉。
//!   4. worker 主循环用 `catch_unwind` 包裹单次 `process_item`，
//!      单个 item panic 不会让整个 worker 停摆 / 结果丢失。
//!   5. 主线程 join `Err` 时打印警告，不再静默丢弃该 worker 已找到的结果。
//!   6. 修复 display_path：HKCR 种子展示为 "HKEY_CLASSES_ROOT"，
//!      子键拼出 "HKEY_CLASSES_ROOT\\.txt" 而不是 "HKEY_CLASSES_ROOT\\Software\\Classes\\.txt"。

use std::collections::VecDeque;
use std::fmt;
use std::fmt::Write as _;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;
use winreg::enums::*;
use winreg::{RegKey, RegValue};

use serde::Deserialize;

/// 只请求需要的权限：读值 + 枚举子键。
/// 若某些键拒绝该组合，`open_key_with_fallback` 会再用 `KEY_READ` 重试。
const MINIMAL_READ: u32 = KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS;

/// 对应 YAML 根结构（只取 system_critical）
#[derive(Debug, Deserialize)]
struct YamlWhitelist {
    system_critical: Vec<String>,
}

// ---------------- 物理根（工作队列种子，HKCR 拆为两个） ----------------

#[derive(Debug, Clone, Copy)]
enum PhysRoot {
    HkcrLm,
    HkcrCu,
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
            PhysRoot::Users => HKEY_USERS,
            PhysRoot::CurrentConfig => HKEY_CURRENT_CONFIG,
        }
    }

    #[inline]
    fn seed_subpath(self) -> Option<&'static str> {
        match self {
            PhysRoot::HkcrLm => Some("Software\\Classes"),
            PhysRoot::HkcrCu => Some("Software\\Classes"),
            _ => None,
        }
    }

    #[inline]
    fn display_label(self) -> &'static str {
        match self {
            PhysRoot::HkcrLm | PhysRoot::HkcrCu => "HKEY_CLASSES_ROOT",
            PhysRoot::CurrentUser => "HKEY_CURRENT_USER",
            PhysRoot::LocalMachine => "HKEY_LOCAL_MACHINE",
            PhysRoot::Users => "HKEY_USERS",
            PhysRoot::CurrentConfig => "HKEY_CURRENT_CONFIG",
        }
    }

    /// 种子的展示起始路径。
    /// HKCR 种子故意**不带** "Software\\Classes" 前缀，
    /// 这样枚举出的子键展示为 `HKEY_CLASSES_ROOT\.txt` 而非
    /// `HKEY_CLASSES_ROOT\Software\Classes\.txt`。
    #[inline]
    fn seed_display_path(self) -> &'static str {
        self.display_label()
    }
}

// ---------------- 白名单（按首字节分桶） ----------------

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

// ---------------- 匹配类型 / 搜索结果 / 搜索配置 ----------------

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

// ---------------- 字符串大小写不敏感匹配（BMH，重复字符取最小 skip） ----------------

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

// ---------------- 值匹配辅助 ----------------

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

// ---------------- 线程共享的只读上下文 ----------------

struct SharedCtx {
    config: SearchConfig,
    whitelist: Whitelist,
    pattern: String,
    keyword_lower_ascii: Vec<u8>,
    found_count: Arc<AtomicUsize>,
    processed: Arc<AtomicUsize>,
}

// ---------------- 工作队列 ----------------

struct WorkItem {
    hkey_raw: isize,
    rel_path: String,
    display_path: String,
    /// 种子任务（6 个物理根）不参与白名单剪枝，
    /// 避免 `whitelist.yaml` 里一条宽前缀把整棵根树剪掉。
    is_seed: bool,
}

struct WorkQueue {
    inner: Mutex<VecDeque<WorkItem>>,
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

    #[inline]
    fn push(&self, item: WorkItem) {
        self.pending.fetch_add(1, Ordering::Relaxed);
        let mut g = self.inner.lock().unwrap();
        g.push_back(item);
        self.cv.notify_one();
    }

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

    #[inline]
    fn done(&self) {
        if self.pending.fetch_sub(1, Ordering::AcqRel) == 1 {
            let _g = self.inner.lock().unwrap();
            self.cv.notify_all();
        }
    }
}

// ---------------- 注册表搜索器 ----------------

pub struct RegistrySearcher {
    config: SearchConfig,
    found_count: Arc<AtomicUsize>,
    whitelist: Whitelist,
    whitelist_loaded: bool,
    workers: usize,
}

impl RegistrySearcher {
    pub fn new() -> Self {
        let (whitelist, whitelist_loaded) = match Whitelist::from_yaml_file("whitelist.yaml") {
            Some(w) => (w, true),
            None => (Whitelist::new(Vec::new()), false),
        };

        Self {
            config: SearchConfig::default(),
            found_count: Arc::new(AtomicUsize::new(0)),
            whitelist,
            whitelist_loaded,
            workers: default_workers(),
        }
    }

    pub fn whitelist_loaded(&self) -> bool {
        self.whitelist_loaded
    }

    pub fn search_with_progress<F>(
        &self,
        keyword: &str,
        progress: F,
    ) -> Result<Vec<SearchResult>, Box<dyn std::error::Error>>
    where
        F: Fn(usize, usize) + Send + Sync + 'static,
    {
        let pattern = keyword.to_lowercase();
        let keyword_lower_ascii = pattern.clone().into_bytes();
        self.found_count.store(0, Ordering::Relaxed);

        let processed = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let progress = Arc::new(progress);

        // 进度监视线程：80ms 刷新一次
        {
            let p = processed.clone();
            let f = self.found_count.clone();
            let s = stop.clone();
            let cb = progress.clone();
            thread::spawn(move || {
                let mut last = (usize::MAX, usize::MAX);
                while !s.load(Ordering::Relaxed) {
                    thread::sleep(Duration::from_millis(80));
                    let cur = (p.load(Ordering::Relaxed), f.load(Ordering::Relaxed));
                    if cur != last {
                        cb(cur.0, cur.1);
                        last = cur;
                    }
                }
                cb(p.load(Ordering::Relaxed), f.load(Ordering::Relaxed));
            });
        }

        let shared = Arc::new(SharedCtx {
            config: self.config.clone(),
            whitelist: self.whitelist.clone(),
            pattern,
            keyword_lower_ascii,
            found_count: self.found_count.clone(),
            processed: processed.clone(),
        });

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
                // 物理：HKLM/HKCU + "Software\Classes"
                // 展示：HKEY_CLASSES_ROOT（不带 Software\Classes 前缀）
                Some(sub) => (sub.to_string(), pr.seed_display_path().to_string()),
                None => (String::new(), pr.seed_display_path().to_string()),
            };
            queue.push(WorkItem {
                hkey_raw,
                rel_path,
                display_path,
                is_seed: true,
            });
        }

        let n = self.workers.max(1).min(64);
        let mut handles: Vec<thread::JoinHandle<Vec<SearchResult>>> = Vec::with_capacity(n);
        for _ in 0..n {
            let q = queue.clone();
            let ctx = shared.clone();
            handles.push(thread::spawn(move || worker_loop(q, ctx)));
        }

        let mut all = Vec::new();
        for h in handles {
            match h.join() {
                Ok(mut v) => all.append(&mut v),
                Err(_) => eprintln!("[registry] worker panicked; its partial results were lost"),
            }
        }
        stop.store(true, Ordering::Relaxed);
        Ok(all)
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

// ---------------- Worker 主循环 ----------------

fn worker_loop(queue: Arc<WorkQueue>, ctx: Arc<SharedCtx>) -> Vec<SearchResult> {
    let mut results: Vec<SearchResult> = Vec::with_capacity(64);
    let mut local_processed = 0usize;
    let mut local_found = 0usize;

    while let Some(item) = queue.pop() {
        // 单 item panic 不能拖垮整个 worker：
        // 无论 process_item 是否 panic，都要 done() + flush，
        // 否则 pending 不归零会让所有 worker 卡死在 pop()。
        let panic_res = catch_unwind(AssertUnwindSafe(|| {
            process_item(
                &item,
                &queue,
                &ctx,
                &mut results,
                &mut local_processed,
                &mut local_found,
            );
        }));
        if panic_res.is_err() {
            eprintln!(
                "[registry] worker panicked while processing: {}",
                item.display_path
            );
        }
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

/// 先 MINIMAL_READ，失败再 KEY_READ 兜底，
/// 避免部分系统键因 ACL 拒绝 KEY_ENUMERATE_SUB_KEYS 就整棵子树被跳过。
#[inline]
fn open_key_with_fallback(root: &RegKey, rel: &str) -> Option<RegKey> {
    if let Ok(k) = root.open_subkey_with_flags(rel, MINIMAL_READ) {
        return Some(k);
    }
    root.open_subkey_with_flags(rel, KEY_READ).ok()
}

fn process_item(
    item: &WorkItem,
    queue: &Arc<WorkQueue>,
    ctx: &Arc<SharedCtx>,
    results: &mut Vec<SearchResult>,
    local_processed: &mut usize,
    local_found: &mut usize,
) {
    // 种子不剪枝；子键已在入队前被剪掉，这里的兜底检查保留即可。
    if !item.is_seed && ctx.whitelist.is_whitelisted(&item.display_path) {
        *local_processed += 1;
        return;
    }

    let root = RegKey::predef(item.hkey_raw as winreg::HKEY);
    let key = if item.rel_path.is_empty() {
        // 根本身直接用预定义句柄（RegKey::predef 的 Drop 不会关闭它）。
        root
    } else {
        match open_key_with_fallback(&root, &item.rel_path) {
            Some(k) => k,
            None => {
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

    // 枚举子键，入队（复用缓冲区）
    let base_rel_len = item.rel_path.len();
    let base_disp_len = item.display_path.len();
    let mut child_rel = String::with_capacity(base_rel_len + 64);
    let mut child_disp = String::with_capacity(base_disp_len + 64);

    // 手动 loop：winreg 在枚举出错时不会前进内部 index，
    // 若用 `.flatten()` / `Err(_) => continue` 会死循环。
    let mut it = key.enum_keys();
    loop {
        match it.next() {
            Some(Ok(subkey_name)) => {
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

                // 入队前剪枝：命中白名单的子键整棵跳过，避免无谓 open。
                if ctx.whitelist.is_whitelisted(&child_disp) {
                    continue;
                }

                queue.push(WorkItem {
                    hkey_raw: item.hkey_raw,
                    rel_path: child_rel.clone(),
                    display_path: child_disp.clone(),
                    is_seed: false,
                });
            }
            Some(Err(_)) => break, // 放弃该键剩余子键，但让 done() 正常执行
            None => break,
        }
    }
}

fn ctx_root_label_len(item: &WorkItem) -> usize {
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

// ---------------- 当前键扫描 ----------------

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
    // 同 process_item：手动 loop，避免 winreg 枚举出错时死循环。
    let mut it = key.enum_values();
    loop {
        let (name, value) = match it.next() {
            Some(Ok(pair)) => pair,
            Some(Err(_)) => break,
            None => break,
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

// ---------------- 注册表值格式化 ----------------

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