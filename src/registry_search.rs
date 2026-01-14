//! 注册表搜索库
//!
//! 提供Windows注册表搜索功能，支持递归搜索键名、值名和值数据。
//! 包含进度报告和统计功能。

use winreg::RegKey;
use winreg::RegValue;
use winreg::enums::*;

/// 定义搜索结果结构体
#[derive(Debug, Clone)]
pub struct SearchResult {
    /// 注册表键的完整路径（包含根键）
    pub key_path: String,
    /// 值名称（如果匹配的是值）
    pub value_name: String,
    /// 值的数据内容（格式化后的字符串）
    pub value_data: String,
    /// 匹配类型：键路径、值名、值数据
    pub match_type: String,
}

/// 进度回调函数类型
pub type ProgressCallback = dyn FnMut(usize, usize, usize) + Send;

/// 搜索状态跟踪结构体
struct SearchState<'a> {
    /// 已处理的键数
    processed_keys: usize,
    /// 总键数（预估）
    total_keys: usize,
    /// 找到的匹配项数量
    found_matches: usize,
    /// 进度回调函数
    progress_callback: Option<&'a mut ProgressCallback>,
}

impl<'a> SearchState<'a> {
    /// 更新进度并调用回调函数
    fn update_progress(&mut self) {
        // 递增已处理键数
        self.processed_keys += 1;

        // 计算进度百分比
        let progress_percent = calculate_progress_percent(self.processed_keys, self.total_keys);

        // 定期报告进度
        if should_report_progress(self.processed_keys, self.total_keys) {
            // 调用用户提供的回调函数
            if let Some(callback) = &mut self.progress_callback {
                callback(self.processed_keys, self.total_keys, self.found_matches);
            }

            // 控制台进度显示
            log_progress_console(
                self.processed_keys,
                self.total_keys,
                progress_percent,
                self.found_matches,
            );
        }
    }

    /// 增加匹配计数
    fn add_match(&mut self) {
        self.found_matches += 1;
    }
}

/// 递归搜索注册表中的匹配项
///
/// # 参数
/// * `root_key` - 要搜索的根键句柄
/// * `root_name` - 根键的显示名称
/// * `keyword` - 搜索关键词
/// * `total_keys` - 预估的总键数（用于进度计算）
/// * `progress_callback` - 进度回调函数
///
/// # 返回值
/// * `Ok(Vec<SearchResult>)` - 搜索结果列表
/// * `Err(Box<dyn std::error::Error>)` - 搜索过程中的错误
pub fn search_registry(
    root_key: winreg::HKEY,
    root_name: &str,
    keyword: &str,
    total_keys: usize,
    progress_callback: Option<&mut ProgressCallback>,
) -> Result<Vec<SearchResult>, Box<dyn std::error::Error>> {
    // 开始搜索日志
    log_search_start(root_name, keyword, total_keys);

    let mut results = Vec::new();
    let keyword_lower = keyword.to_lowercase(); // 优化：一次性转为小写

    // 打开根键
    let root_key_result = RegKey::predef(root_key).open_subkey("");
    match root_key_result {
        Ok(key) => {
            log_root_key_open_success(root_name);
            let start_time = std::time::Instant::now(); // 记录开始时间

            // 初始化搜索状态
            let mut state = SearchState {
                processed_keys: 0,
                total_keys,
                found_matches: 0,
                progress_callback,
            };

            // 开始递归搜索
            search_in_subkey(
                &key,
                "",
                root_name,
                &keyword_lower,
                &mut results,
                &mut state,
            )?;

            // 搜索完成日志
            let elapsed_time = start_time.elapsed();
            log_search_complete(elapsed_time, state.processed_keys, state.found_matches);
        }
        Err(e) => {
            log_root_key_open_failure(root_name, &e);
            return Err(Box::new(e));
        }
    }

    Ok(results)
}

/// 递归统计注册表键数
///
/// # 参数
/// * `root_key` - 要统计的根键句柄
///
/// # 返回值
/// * `Ok(usize)` - 键的总数
/// * `Err(Box<dyn std::error::Error>)` - 统计过程中的错误
pub fn count_keys(root_key: winreg::HKEY) -> Result<usize, Box<dyn std::error::Error>> {
    log_counting_start();
    let start_time = std::time::Instant::now(); // 记录开始时间

    // 打开根键并开始统计
    let key_result = RegKey::predef(root_key).open_subkey("");
    match key_result {
        Ok(key) => {
            let total_count = count_keys_recursive(&key, "")?;
            let elapsed_time = start_time.elapsed();
            log_counting_complete(elapsed_time, total_count);
            Ok(total_count)
        }
        Err(e) => {
            log_counting_failure(&e);
            Err(Box::new(e))
        }
    }
}

/// 在子键中递归搜索
fn search_in_subkey(
    key: &RegKey,
    current_path: &str,
    root_name: &str,
    keyword: &str,
    results: &mut Vec<SearchResult>,
    state: &mut SearchState<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    // 更新搜索进度
    state.update_progress();

    // 构建完整路径
    let full_path = build_full_path(root_name, current_path);

    // 检查当前键路径是否匹配
    let key_matched = check_key_path_match(keyword, current_path, &full_path, results, state);

    // 如果键路径已匹配，则不检查值和值名（避免重复）
    if !key_matched {
        // 检查所有值是否匹配
        check_values_match(key, keyword, &full_path, results, state);
    }

    // 递归搜索所有子键（无论当前键是否匹配，都需要继续搜索子键）
    search_subkeys_recursive(key, current_path, root_name, keyword, results, state)?;

    Ok(())
}

/// 构建完整路径
fn build_full_path(root_name: &str, current_path: &str) -> String {
    if current_path.is_empty() {
        // 根键情况
        root_name.to_string()
    } else {
        format!("{}\\{}", root_name, current_path)
    }
}

/// 检查键路径是否匹配，返回是否匹配
fn check_key_path_match(
    keyword: &str,
    current_path: &str,
    full_path: &str,
    results: &mut Vec<SearchResult>,
    state: &mut SearchState<'_>,
) -> bool {
    // 将路径转为小写进行比较
    if current_path.to_lowercase().contains(keyword) {
        let result = SearchResult {
            key_path: full_path.to_string(),
            value_name: String::new(),
            value_data: String::new(),
            match_type: "项".to_string(),
        };
        results.push(result);
        state.add_match();
        log_key_path_match(full_path);
        true
    } else {
        false
    }
}

/// 检查所有值是否匹配
fn check_values_match(
    key: &RegKey,
    keyword: &str,
    full_path: &str,
    results: &mut Vec<SearchResult>,
    state: &mut SearchState<'_>,
) {
    // 获取所有值
    let values: Vec<(String, RegValue)> = key.enum_values().filter_map(Result::ok).collect();

    // 检查每个值
    for (value_name, value) in values {
        let value_name_lower = value_name.to_lowercase();
        let value_str = format_reg_value(&value);
        let value_str_lower = value_str.to_lowercase();

        // 优先检查值名是否匹配
        if value_name_lower.contains(keyword) {
            handle_value_match(full_path, &value_name, &value_str, "键", results, state);
            continue; // 值名已匹配，跳过值数据检查
        }

        // 然后检查值数据是否匹配
        if value_str_lower.contains(keyword) {
            handle_value_match(full_path, &value_name, &value_str, "值", results, state);
            // 值数据已匹配，继续下一个值
        }
    }
}

/// 统一处理值匹配（避免重复）
fn handle_value_match(
    full_path: &str,
    value_name: &str,
    value_str: &str,
    match_type: &str,
    results: &mut Vec<SearchResult>,
    state: &mut SearchState<'_>,
) {
    let match_type_str = match match_type {
        "值名" => "键",
        "值数据" => "值",
        _ => match_type,
    };

    let result = SearchResult {
        key_path: full_path.to_string(),
        value_name: value_name.to_string(),
        value_data: value_str.to_string(),
        match_type: match_type_str.to_string(),
    };
    results.push(result);
    state.add_match();

    // 根据匹配类型记录日志
    match match_type {
        "值名" => log_value_name_match(full_path, value_name),
        "值数据" => log_value_data_match(full_path, value_name),
        _ => {}
    }
}

/// 递归搜索所有子键
fn search_subkeys_recursive(
    key: &RegKey,
    current_path: &str,
    root_name: &str,
    keyword: &str,
    results: &mut Vec<SearchResult>,
    state: &mut SearchState<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    // 获取所有子键名
    let subkey_names: Vec<String> = key.enum_keys().filter_map(Result::ok).collect();

    // 递归搜索每个子键
    for subkey_name in subkey_names {
        let new_path = build_new_path(current_path, &subkey_name);

        // 尝试打开子键
        let subkey_result = key.open_subkey(&subkey_name);
        match subkey_result {
            Ok(subkey) => {
                search_in_subkey(&subkey, &new_path, root_name, keyword, results, state)?;
            }
            Err(_) => {
                // 无法打开的子键跳过
                log_subkey_open_warning(current_path, &subkey_name);
            }
        }
    }

    Ok(())
}

/// 构建新路径
fn build_new_path(current_path: &str, subkey_name: &str) -> String {
    if current_path.is_empty() {
        subkey_name.to_string()
    } else {
        format!("{}\\{}", current_path, subkey_name)
    }
}

/// 递归统计键数
fn count_keys_recursive(
    key: &RegKey,
    current_path: &str,
) -> Result<usize, Box<dyn std::error::Error>> {
    // 当前键计数为1
    let mut count = 1;

    // 获取所有子键
    let subkey_names: Vec<String> = key.enum_keys().filter_map(Result::ok).collect();

    // 递归统计子键
    for subkey_name in subkey_names {
        let new_path = build_new_path(current_path, &subkey_name);

        // 尝试打开子键
        match key.open_subkey(&subkey_name) {
            Ok(subkey) => {
                count += count_keys_recursive(&subkey, &new_path)?;
            }
            Err(e) => {
                // 无法打开的键记录警告但继续统计
                log_subkey_count_warning(current_path, &subkey_name, &e);
            }
        }
    }

    Ok(count)
}

/// 格式化注册表值为可读字符串
fn format_reg_value(value: &RegValue) -> String {
    match value.vtype {
        REG_SZ | REG_EXPAND_SZ => format_string_value(value),
        REG_DWORD => format_dword_value(value),
        REG_QWORD => format_qword_value(value),
        REG_MULTI_SZ => format_multi_string_value(value),
        REG_BINARY => format_binary_value(value),
        _ => format_other_value(value),
    }
}

/// 格式化字符串类型值
fn format_string_value(value: &RegValue) -> String {
    let bytes = &value.bytes;
    let mut chars = Vec::with_capacity(bytes.len() / 2);

    // 处理UTF-16字符串
    for chunk in bytes.chunks_exact(2) {
        let code = u16::from_le_bytes([chunk[0], chunk[1]]);
        if code == 0 {
            break;
        }
        chars.push(code);
    }

    String::from_utf16_lossy(&chars)
}

/// 格式化DWORD类型值
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
        String::from("无效的DWORD")
    }
}

/// 格式化QWORD类型值
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
        String::from("无效的QWORD")
    }
}

/// 格式化多字符串类型值
fn format_multi_string_value(value: &RegValue) -> String {
    let bytes = &value.bytes;
    let mut result = String::new();
    let mut current_string = Vec::new();

    // 处理多字符串
    for chunk in bytes.chunks_exact(2) {
        let code = u16::from_le_bytes([chunk[0], chunk[1]]);
        if code == 0 {
            if !current_string.is_empty() {
                if !result.is_empty() {
                    result.push(';');
                }
                result.push_str(&String::from_utf16_lossy(&current_string));
                current_string.clear();
            }
        } else {
            current_string.push(code);
        }
    }

    // 处理最后一个字符串
    if !current_string.is_empty() {
        if !result.is_empty() {
            result.push(';');
        }
        result.push_str(&String::from_utf16_lossy(&current_string));
    }

    if result.is_empty() {
        String::from("[多字符串值]")
    } else {
        result
    }
}

/// 格式化二进制类型值
fn format_binary_value(value: &RegValue) -> String {
    if value.bytes.is_empty() {
        String::from("[空二进制]")
    } else {
        let len = value.bytes.len();
        if len > 20 {
            // 大型二进制数据只显示大小
            format!("[二进制数据，{}字节]", len)
        } else {
            // 小型二进制数据显示十六进制
            let mut hex_string = String::with_capacity(len * 3);
            for (i, byte) in value.bytes.iter().enumerate() {
                if i > 0 {
                    hex_string.push(' ');
                }
                hex_string.push_str(&format!("{:02X}", byte));
            }
            format!("[{}]", hex_string)
        }
    }
}

/// 格式化其他类型值
fn format_other_value(value: &RegValue) -> String {
    format!("[类型: {:?}，大小: {}字节]", value.vtype, value.bytes.len())
}

/// 计算进度百分比
fn calculate_progress_percent(processed: usize, total: usize) -> usize {
    if total > 0 {
        (processed as f64 / total as f64 * 100.0) as usize
    } else {
        0
    }
}

/// 判断是否需要报告进度
fn should_report_progress(processed: usize, total: usize) -> bool {
    processed % 100 == 0 || processed == total
}

/// 记录搜索开始
fn log_search_start(root_name: &str, keyword: &str, total_keys: usize) {
    println!("开始搜索注册表根键: {}", root_name);
    println!("搜索关键词: {}", keyword);
    println!("预估总键数: {}", total_keys);
}

/// 记录根键打开成功
fn log_root_key_open_success(root_name: &str) {
    println!("成功打开根键: {}", root_name);
}

/// 记录根键打开失败
fn log_root_key_open_failure(root_name: &str, error: &impl std::fmt::Display) {
    eprintln!("无法打开根键 {}: {}", root_name, error);
}

/// 记录搜索完成
fn log_search_complete(
    elapsed_time: std::time::Duration,
    processed_keys: usize,
    found_matches: usize,
) {
    println!("搜索完成,耗时: {:.2?}", elapsed_time);
    println!(
        "共处理 |{}| 个键,找到 |{}| 个匹配项",
        processed_keys, found_matches
    );
}

/// 记录控制台进度
fn log_progress_console(processed: usize, total: usize, percent: usize, found: usize) {
    // 使用 \r 返回行首，然后用空格清除旧内容
    let clear_line = " ".repeat(80);
    print!("\r{}", clear_line);

    // 输出进度信息（不换行）
    print!(
        "\r进度: {}/{} ({}%)，找到匹配: {}",
        processed, total, percent, found
    );

    // 当进度完成时换行
    if processed >= total {
        println!();
    }
}

/// 记录键路径匹配
fn log_key_path_match(full_path: &str) {
    println!("匹配键路径: {}", full_path);
}

/// 记录值名匹配
fn log_value_name_match(full_path: &str, value_name: &str) {
    println!("匹配键: {}\\{}", full_path, value_name);
}

/// 记录值数据匹配
fn log_value_data_match(full_path: &str, value_name: &str) {
    println!("匹配值: {}\\{}", full_path, value_name);
}

/// 记录子键打开警告
fn log_subkey_open_warning(current_path: &str, subkey_name: &str) {
    println!("警告: 无法打开子键 {}\\{}", current_path, subkey_name);
}

/// 记录统计开始
fn log_counting_start() {
    println!("开始统计注册表键数...");
}

/// 记录统计完成
fn log_counting_complete(elapsed_time: std::time::Duration, total_count: usize) {
    println!("统计完成,耗时: {:.2?}", elapsed_time);
    println!("总键数: {}", total_count);
}

/// 记录统计失败
fn log_counting_failure(error: &impl std::fmt::Display) {
    eprintln!("无法打开根项进行统计: {}", error);
}

/// 记录子键统计警告
fn log_subkey_count_warning(current_path: &str, subkey_name: &str, error: &impl std::fmt::Display) {
    println!(
        "警告: 无法打开子键 {}\\{}: {}",
        current_path, subkey_name, error
    );
}
