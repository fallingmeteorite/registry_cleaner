//! 注册表清理工具 - 应用逻辑层
//!
//! 该模块**不依赖任何 GUI 库**：只负责状态、后台线程通信、
//! 搜索/删除动作的调度与后台消息的收集。
//! 所有渲染代码位于 `crate::ui`。

use crate::registry_delete::{DeleteResult, RegistryDeleter};
use crate::registry_search::{MatchType, RegistrySearcher, SearchResult};

use std::collections::HashSet;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

#[cfg(windows)]
use winapi::um::securitybaseapi::{AllocateAndInitializeSid, CheckTokenMembership, FreeSid};
#[cfg(windows)]
use winapi::um::winnt::{
    DOMAIN_ALIAS_RID_ADMINS, PSID, SECURITY_BUILTIN_DOMAIN_RID, SID_IDENTIFIER_AUTHORITY,
};

// ---------------- 权限检查 ----------------

#[cfg(windows)]
fn is_running_as_admin() -> bool {
    unsafe {
        let mut sia = SID_IDENTIFIER_AUTHORITY {
            Value: [0, 0, 0, 0, 0, 5],
        };
        let mut sid: PSID = std::ptr::null_mut();
        let mut member = 0;
        if AllocateAndInitializeSid(
            &mut sia,
            2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0,
            0,
            0,
            0,
            0,
            0,
            &mut sid,
        ) == 0
        {
            return false;
        }
        let ok = CheckTokenMembership(std::ptr::null_mut(), sid, &mut member);
        FreeSid(sid);
        ok != 0 && member != 0
    }
}

#[cfg(not(windows))]
fn is_running_as_admin() -> bool {
    false
}

// ---------------- 后台消息 ----------------

pub(crate) enum SearchMsg {
    Progress { processed: usize, found: usize },
    Done(Vec<SearchResult>),
    Error(String),
}

pub(crate) enum DeleteMsg {
    Progress { current: usize, total: usize },
    Done(Vec<DeleteResult>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AppMode {
    Idle,
    Searching,
    Results,
    Deleting,
    Done,
}

// ---------------- App 状态 ----------------

pub(crate) struct CleanerApp {
    // ---- 启动时一次性判定 ----
    pub(crate) is_admin: bool,
    pub(crate) whitelist_loaded: bool,

    // ---- 搜索输入与结果 ----
    pub(crate) keyword: String,
    pub(crate) mode: AppMode,
    pub(crate) results: Vec<SearchResult>,
    pub(crate) selected: Vec<bool>,
    pub(crate) focused: Option<usize>,

    searcher: Arc<RegistrySearcher>,

    // ---- 后台通信 ----
    rx_search: Option<Receiver<SearchMsg>>,
    rx_delete: Option<Receiver<DeleteMsg>>,

    // ---- 搜索进度 ----
    pub(crate) processed: usize,
    pub(crate) found: usize,
    pub(crate) search_start: Option<Instant>,
    /// 搜索结束时冻结的耗时；`Results` / `Done` 模式展示用。
    pub(crate) search_elapsed: Option<Duration>,

    // ---- 删除进度与统计 ----
    pub(crate) delete_current: usize,
    pub(crate) delete_total: usize,
    pub(crate) delete_success: usize,
    pub(crate) delete_failed: usize,
    pub(crate) delete_already: usize,
    pub(crate) delete_skipped: usize,
    pub(crate) delete_results: Vec<DeleteResult>,

    // ---- 弹窗类 ----
    pub(crate) show_confirm: bool,
    pub(crate) toast: Option<(String, Instant)>,
    pub(crate) info_dialog: Option<String>,
}

impl CleanerApp {
    pub(crate) fn new() -> Self {
        let searcher = Arc::new(RegistrySearcher::new());
        let whitelist_loaded = searcher.whitelist_loaded();

        Self {
            is_admin: is_running_as_admin(),
            whitelist_loaded,
            keyword: String::new(),
            mode: AppMode::Idle,
            results: Vec::new(),
            selected: Vec::new(),
            focused: None,
            searcher,
            rx_search: None,
            rx_delete: None,
            processed: 0,
            found: 0,
            search_start: None,
            search_elapsed: None,
            delete_current: 0,
            delete_total: 0,
            delete_success: 0,
            delete_failed: 0,
            delete_already: 0,
            delete_skipped: 0,
            delete_results: Vec::new(),
            show_confirm: false,
            toast: None,
            info_dialog: None,
        }
    }

    pub(crate) fn reset_ui(&mut self) {
        self.keyword.clear();
        self.mode = AppMode::Idle;
        self.results.clear();
        self.selected.clear();
        self.focused = None;
        self.processed = 0;
        self.found = 0;
        self.search_start = None;
        self.search_elapsed = None;
        self.delete_current = 0;
        self.delete_total = 0;
        self.delete_success = 0;
        self.delete_failed = 0;
        self.delete_already = 0;
        self.delete_skipped = 0;
        self.delete_results.clear();
        self.show_confirm = false;
        self.toast = None;
        self.info_dialog = None;
    }

    pub(crate) fn selected_item_keys(&self) -> HashSet<String> {
        self.results
            .iter()
            .enumerate()
            .filter(|(i, r)| self.selected[*i] && r.match_type == MatchType::Item)
            .map(|(_, r)| r.key_path.clone())
            .collect()
    }

    pub(crate) fn build_display_order(&self) -> Vec<usize> {
        let mut order: Vec<usize> = (0..self.results.len()).collect();
        order.sort_by(|&a, &b| {
            let ra = &self.results[a];
            let rb = &self.results[b];
            ra.key_path
                .cmp(&rb.key_path)
                .then_with(|| {
                    match_type_weight(&ra.match_type).cmp(&match_type_weight(&rb.match_type))
                })
        });
        order
    }

    pub(crate) fn start_search(&mut self) {
        let keyword = self.keyword.trim().to_string();
        if keyword.is_empty() {
            self.toast = Some(("请输入关键字".to_string(), Instant::now()));
            return;
        }

        let (tx, rx) = mpsc::channel();
        self.rx_search = Some(rx);
        self.mode = AppMode::Searching;
        self.processed = 0;
        self.found = 0;
        self.search_start = Some(Instant::now());
        self.search_elapsed = None;
        self.results.clear();
        self.selected.clear();
        self.focused = None;
        self.info_dialog = None;

        self.delete_success = 0;
        self.delete_failed = 0;
        self.delete_already = 0;
        self.delete_skipped = 0;
        self.delete_results.clear();

        let searcher = Arc::clone(&self.searcher);

        thread::spawn(move || {
            let tx2 = tx.clone();
            let result = searcher.search_with_progress(&keyword, move |p, f| {
                let _ = tx2.send(SearchMsg::Progress {
                    processed: p,
                    found: f,
                });
            });
            match result {
                Ok(rs) => {
                    let _ = tx.send(SearchMsg::Done(rs));
                }
                Err(e) => {
                    let _ = tx.send(SearchMsg::Error(e.to_string()));
                }
            }
        });
    }

    pub(crate) fn start_delete(&mut self) {
        let selected_item_keys = self.selected_item_keys();

        let mut items: Vec<(String, Option<String>)> = self
            .results
            .iter()
            .enumerate()
            .filter(|(i, r)| {
                if !self.selected[*i] {
                    return false;
                }
                match r.match_type {
                    MatchType::Item => true,
                    _ => !selected_item_keys.contains(&r.key_path),
                }
            })
            .map(|(_, r)| (r.key_path.clone(), r.value_name.clone()))
            .collect();

        if items.is_empty() {
            self.toast = Some(("未选择任何项目".to_string(), Instant::now()));
            return;
        }

        items.sort_unstable_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

        let (tx, rx) = mpsc::channel();
        self.rx_delete = Some(rx);
        self.mode = AppMode::Deleting;
        self.delete_current = 0;
        self.delete_total = items.len();
        self.delete_success = 0;
        self.delete_failed = 0;
        self.delete_already = 0;
        self.delete_skipped = 0;
        self.delete_results.clear();
        self.show_confirm = false;

        thread::spawn(move || {
            let deleter = RegistryDeleter::new();
            let mut results = Vec::with_capacity(items.len());
            for (i, (path, value)) in items.iter().enumerate() {
                let r = match value {
                    Some(v) => deleter.delete_value(path, v),
                    None => deleter.delete_key(path),
                };
                results.push(r);
                let _ = tx.send(DeleteMsg::Progress {
                    current: i + 1,
                    total: items.len(),
                });
            }
            let _ = tx.send(DeleteMsg::Done(results));
        });
    }

    pub(crate) fn poll_background(&mut self) {
        if let Some(rx) = self.rx_search.take() {
            let mut keep = true;
            loop {
                match rx.try_recv() {
                    Ok(SearchMsg::Progress { processed, found }) => {
                        self.processed = processed;
                        self.found = found;
                    }
                    Ok(SearchMsg::Done(results)) => {
                        // 冻结耗时
                        self.search_elapsed = self.search_start.map(|t| t.elapsed());

                        // 消费通道里排在 Done 之后、监视线程最后发出的 Progress
                        while let Ok(SearchMsg::Progress { processed, found }) =
                            rx.try_recv()
                        {
                            self.processed = processed;
                            self.found = found;
                        }

                        if results.is_empty() {
                            self.info_dialog = Some(format!(
                                "未找到与「{}」相关的注册表项",
                                self.keyword.trim()
                            ));
                            self.mode = AppMode::Idle;
                            self.results.clear();
                            self.selected.clear();
                            self.focused = None;
                        } else {
                            self.selected = vec![true; results.len()];
                            self.focused = Some(0);
                            self.found = results.len();
                            self.results = results;
                            self.mode = AppMode::Results;
                        }
                        keep = false;
                        break;
                    }
                    Ok(SearchMsg::Error(e)) => {
                        self.search_elapsed = self.search_start.map(|t| t.elapsed());
                        self.info_dialog = Some(format!("搜索失败：{}", e));
                        self.mode = AppMode::Idle;
                        keep = false;
                        break;
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        self.search_elapsed = self.search_start.map(|t| t.elapsed());
                        self.mode = AppMode::Idle;
                        keep = false;
                        break;
                    }
                }
            }
            if keep {
                self.rx_search = Some(rx);
            }
        }

        if let Some(rx) = self.rx_delete.take() {
            let mut keep = true;
            loop {
                match rx.try_recv() {
                    Ok(DeleteMsg::Progress { current, total }) => {
                        self.delete_current = current;
                        self.delete_total = total;
                    }
                    Ok(DeleteMsg::Done(results)) => {
                        let skipped = results.iter().filter(|r| r.skipped).count();
                        let already = results.iter().filter(|r| r.already_deleted).count();
                        let success = results
                            .iter()
                            .filter(|r| r.success && !r.already_deleted)
                            .count();
                        let failed = results.len().saturating_sub(skipped + already + success);

                        self.delete_success = success;
                        self.delete_already = already;
                        self.delete_skipped = skipped;
                        self.delete_failed = failed;
                        self.delete_results = results;
                        self.mode = AppMode::Done;
                        keep = false;
                        break;
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        self.mode = AppMode::Results;
                        keep = false;
                        break;
                    }
                }
            }
            if keep {
                self.rx_delete = Some(rx);
            }
        }
    }
}

// ---------------- 逻辑辅助函数 ----------------

/// 耗时格式化：
/// - < 10s  : "3.2s"
/// - < 60s  : "17s"
/// - >= 60s : "1m 23s"
pub(crate) fn fmt_elapsed(d: Duration) -> String {
    let secs = d.as_secs_f64();
    if secs < 10.0 {
        format!("{:.1}s", secs)
    } else if secs < 60.0 {
        format!("{}s", secs as u64)
    } else {
        let m = secs as u64 / 60;
        let s = secs as u64 % 60;
        format!("{}m {}s", m, s)
    }
}

pub(crate) fn match_type_weight(mt: &MatchType) -> u8 {
    match mt {
        MatchType::Item => 0,
        MatchType::Key => 1,
        MatchType::Value => 2,
    }
}