//! 注册表搜索模块

use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Instant, Duration};
use winreg::enums::*;
use winreg::{RegKey, RegValue};

/// 匹配类型
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchType {
    Item,   // 键名匹配
    Key,    // 值名匹配
    Value,  // 值数据匹配
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

/// 搜索结果
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

/// 搜索配置
#[derive(Debug, Clone)]
pub struct SearchConfig {
    pub search_key_names: bool,
    pub search_value_names: bool,
    pub search_value_data: bool,
    pub case_sensitive: bool,
}

impl Default for SearchConfig {
    fn default() -> Self {
        Self {
            search_key_names: true,
            search_value_names: true,
            search_value_data: true,
            case_sensitive: false,
        }
    }
}

/// 进度条结构
struct ProgressBar {
    total: usize,
    current: usize,
    width: usize,
    start_time: Instant,
    last_update: Instant,
    enabled: bool,
}

impl ProgressBar {
    fn new(total: usize, enabled: bool) -> Self {
        Self {
            total,
            current: 0,
            width: 40,
            start_time: Instant::now(),
            last_update: Instant::now(),
            enabled,
        }
    }

    fn update(&mut self, current: usize) {
        if !self.enabled {
            return;
        }

        self.current = current;

        // 限制更新频率，避免闪烁
        let now = Instant::now();
        if now.duration_since(self.last_update) < Duration::from_millis(100) && current < self.total {
            return;
        }
        self.last_update = now;

        self.render();
    }

    fn render(&self) {
        if !self.enabled {
            return;
        }

        let percent = if self.total > 0 {
            self.current as f64 / self.total as f64 * 100.0  // 移除了不必要的括号
        } else {
            0.0
        };

        let filled = ((percent / 100.0) * self.width as f64) as usize;
        let empty = self.width - filled;

        let elapsed = self.start_time.elapsed();
        let elapsed_str = format_duration(elapsed);

        // 估算剩余时间
        let eta = if self.current > 0 && self.total > 0 && self.current < self.total {
            let elapsed_secs = elapsed.as_secs_f64();
            let total_secs = elapsed_secs / (self.current as f64) * (self.total as f64);
            let remaining_secs = total_secs - elapsed_secs;
            if remaining_secs > 0.0 && remaining_secs < 3600.0 * 24.0 {
                format_duration(Duration::from_secs_f64(remaining_secs))
            } else {
                "计算中...".to_string()
            }
        } else if self.current >= self.total {
            "已完成".to_string()
        } else {
            "计算中...".to_string()
        };

        // 使用ANSI转义序列清除当前行并移动光标到行首
        print!("\r\x1b[2K");
        print!("[{}{}] {:>3}% ({}/{}) | 已用: {} | 剩余: {}",
               "█".repeat(filled),
               " ".repeat(empty),
               percent as usize,
               self.current,
               self.total,
               elapsed_str,
               eta
        );

        // 如果完成，换行
        if self.current >= self.total {
            println!();
        }
    }

    fn finish(&mut self) {
        if !self.enabled {
            return;
        }
        self.current = self.total;
        self.render();
    }
}

/// 格式化时间
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

/// 注册表搜索器
pub struct RegistrySearcher {
    config: SearchConfig,
    found_count: AtomicUsize,
}

impl RegistrySearcher {
    pub fn new() -> Self {
        Self {
            config: SearchConfig::default(),
            found_count: AtomicUsize::new(0),
        }
    }

    pub fn search_all(&self, keyword: &str) -> Result<Vec<SearchResult>, Box<dyn std::error::Error>> {
        let roots = [
            (HKEY_CLASSES_ROOT, "HKEY_CLASSES_ROOT"),
            (HKEY_CURRENT_USER, "HKEY_CURRENT_USER"),
            (HKEY_LOCAL_MACHINE, "HKEY_LOCAL_MACHINE"),
            (HKEY_USERS, "HKEY_USERS"),
            (HKEY_CURRENT_CONFIG, "HKEY_CURRENT_CONFIG"),
        ];

        let mut all_results = Vec::new();

        // 计算总键数用于进度条
        println!("正在统计注册表键数量...");
        let total_keys = self.count_total_keys(&roots)?;
        let mut progress = ProgressBar::new(total_keys, true);
        println!("开始搜索注册表 (共 {} 个键)...", total_keys);

        let mut processed = 0;
        for (root_key, root_name) in roots {
            let results = self.search_root_with_progress(
                root_key, root_name, keyword, &mut progress, &mut processed
            )?;
            all_results.extend(results);
        }

        progress.finish();
        println!("搜索完成！找到 {} 个匹配项", self.found_count.load(Ordering::Relaxed));

        Ok(all_results)
    }

    #[allow(dead_code)]
    pub fn search_root(
        &self,
        root_key: winreg::HKEY,
        root_name: &str,
        keyword: &str,
    ) -> Result<Vec<SearchResult>, Box<dyn std::error::Error>> {
        let key = RegKey::predef(root_key);
        let pattern = if self.config.case_sensitive {
            keyword.to_string()
        } else {
            keyword.to_lowercase()
        };

        self.found_count.store(0, Ordering::Relaxed);
        let mut results = Vec::new();

        // 计算当前根键下的总键数
        let total_keys = self.count_keys_recursive(&key)?;
        let mut progress = ProgressBar::new(total_keys, true);
        println!("正在搜索 {} (共 {} 个键)...", root_name, total_keys);

        let mut processed = 0;
        self.search_recursive(&key, "", root_name, &pattern, &mut results, &mut progress, &mut processed)?;

        progress.finish();
        println!("搜索完成！找到 {} 个匹配项", self.found_count.load(Ordering::Relaxed));

        Ok(results)
    }

    /// 计算注册表根键下的总键数
    fn count_total_keys(&self, roots: &[(winreg::HKEY, &str)]) -> Result<usize, Box<dyn std::error::Error>> {
        let mut total = 0;
        for (root_key, _) in roots {
            let key = RegKey::predef(*root_key);
            total += self.count_keys_recursive(&key)?;
        }
        Ok(total)
    }

    fn count_keys_recursive(&self, key: &RegKey) -> Result<usize, Box<dyn std::error::Error>> {
        let mut count = 1; // 当前键
        let subkeys: Vec<String> = key.enum_keys().filter_map(Result::ok).collect();
        for subkey_name in subkeys {
            if let Ok(subkey) = key.open_subkey(&subkey_name) {
                count += self.count_keys_recursive(&subkey)?;
            }
        }
        Ok(count)
    }

    fn search_root_with_progress(
        &self,
        root_key: winreg::HKEY,
        root_name: &str,
        keyword: &str,
        progress: &mut ProgressBar,
        processed: &mut usize,
    ) -> Result<Vec<SearchResult>, Box<dyn std::error::Error>> {
        let key = RegKey::predef(root_key);
        let pattern = if self.config.case_sensitive {
            keyword.to_string()
        } else {
            keyword.to_lowercase()
        };

        let mut results = Vec::new();
        self.search_recursive(&key, "", root_name, &pattern, &mut results, progress, processed)?;

        Ok(results)
    }

    fn search_recursive(
        &self,
        key: &RegKey,
        current_path: &str,
        root_name: &str,
        keyword: &str,
        results: &mut Vec<SearchResult>,
        progress: &mut ProgressBar,
        processed: &mut usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let full_path = if current_path.is_empty() {
            root_name.to_string()
        } else {
            format!("{}\\{}", root_name, current_path)
        };

        self.search_current_key(key, &full_path, current_path, keyword, results);

        // 更新进度
        *processed += 1;
        progress.update(*processed);

        self.search_subkeys(key, current_path, root_name, keyword, results, progress, processed)?;

        Ok(())
    }

    fn search_current_key(
        &self,
        key: &RegKey,
        full_path: &str,
        current_path: &str,
        keyword: &str,
        results: &mut Vec<SearchResult>,
    ) {
        if self.config.search_key_names && !current_path.is_empty() {
            let path_to_check = if self.config.case_sensitive {
                current_path.to_string()
            } else {
                current_path.to_lowercase()
            };

            if path_to_check.contains(keyword) {
                let result = SearchResult::new(full_path.to_string(), MatchType::Item);
                results.push(result);
                self.found_count.fetch_add(1, Ordering::Relaxed);
            }
        }

        if self.config.search_value_names || self.config.search_value_data {
            self.search_values(key, full_path, keyword, results);
        }
    }

    fn search_values(&self, key: &RegKey, full_path: &str, keyword: &str, results: &mut Vec<SearchResult>) {
        for value_result in key.enum_values() {
            if let Ok((name, value)) = value_result {
                if self.config.search_value_names {
                    let name_to_check = if self.config.case_sensitive {
                        name.clone()
                    } else {
                        name.to_lowercase()
                    };

                    if name_to_check.contains(keyword) {
                        let data = format_registry_value(&value);
                        let result = SearchResult::new(full_path.to_string(), MatchType::Key)
                            .with_value_name(name.clone())
                            .with_value_data(data);
                        results.push(result);
                        self.found_count.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                }

                if self.config.search_value_data {
                    let data = format_registry_value(&value);
                    let data_to_check = if self.config.case_sensitive {
                        data.clone()
                    } else {
                        data.to_lowercase()
                    };

                    if data_to_check.contains(keyword) {
                        let result = SearchResult::new(full_path.to_string(), MatchType::Value)
                            .with_value_name(name)
                            .with_value_data(data);
                        results.push(result);
                        self.found_count.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
    }

    fn search_subkeys(
        &self,
        key: &RegKey,
        current_path: &str,
        root_name: &str,
        keyword: &str,
        results: &mut Vec<SearchResult>,
        progress: &mut ProgressBar,
        processed: &mut usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let subkeys: Vec<String> = key.enum_keys().filter_map(Result::ok).collect();

        for subkey_name in subkeys {
            let new_path = if current_path.is_empty() {
                subkey_name.clone()
            } else {
                format!("{}\\{}", current_path, subkey_name)
            };

            if let Ok(subkey) = key.open_subkey(&subkey_name) {
                self.search_recursive(&subkey, &new_path, root_name, keyword, results, progress, processed)?;
            }
        }

        Ok(())
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

/// 格式化注册表值为可读字符串
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
    // 确保是偶数长度
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
            value.bytes[0], value.bytes[1], value.bytes[2], value.bytes[3],
        ]);
        format!("{} (0x{:X})", num, num)
    } else {
        "无效的DWORD".to_string()
    }
}

fn format_qword_value(value: &RegValue) -> String {
    if value.bytes.len() >= 8 {
        let num = u64::from_le_bytes([
            value.bytes[0], value.bytes[1], value.bytes[2], value.bytes[3],
            value.bytes[4], value.bytes[5], value.bytes[6], value.bytes[7],
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
    // 处理最后一个非空字符串
    if !current.is_empty() {
        strings.push(String::from_utf16_lossy(&current));
    }

    strings.join("; ")
}

fn format_binary_value(value: &RegValue) -> String {
    if value.bytes.is_empty() {
        "[空二进制]".to_string()
    } else if value.bytes.len() > 20 {
        format!("[二进制数据, {}字节]", value.bytes.len())
    } else {
        let hex: String = value.bytes.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ");
        format!("[{}]", hex)
    }
}