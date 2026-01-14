//! fallingmeteorite
// registry_delete.rs
use winreg::HKEY;
use winreg::RegKey;
use winreg::enums::*;

// 引入 registry_check 模块中的类型
use crate::registry_check::RegistryImportance;

/// 注册表删除结果
#[derive(Debug, Clone)]
pub struct DeleteResult {
    /// 删除是否成功
    pub success: bool,
    /// 注册表键路径
    pub key_path: String,
    /// 值名称（可选）
    pub value_name: Option<String>,
    /// 操作结果消息
    pub message: String,
    /// 新增：是否已经删除/不存在
    pub already_deleted: bool,
    /// 新增：是否删除了父GUID目录
    pub deleted_parent_guid: bool,
}

/// 注册表删除器
pub struct RegistryDeleter;

impl RegistryDeleter {
    /// 创建新的删除器实例
    pub fn new() -> Self {
        RegistryDeleter
    }

    /// 删除注册表键值
    pub fn delete_registry_value(&self, key_path: &str, value_name: &str) -> DeleteResult {
        // 记录删除开始
        log_deletion_start(key_path, Some(value_name));

        // 检查是否需要删除父GUID目录
        if let Some(parent_guid_path) = Self::should_delete_parent_guid(key_path) {
            log_guid_parent_detection(&parent_guid_path);
            return self.delete_guid_parent_directory(
                &parent_guid_path,
                key_path,
                Some(value_name),
            );
        }

        // 解析注册表路径
        let parse_result = Self::parse_registry_path(key_path);
        let (root_key, subkey) = match parse_result {
            Ok((root, sub)) => {
                log_parse_success(&root, &sub);
                (root, sub)
            }
            Err(e) => {
                log_parse_failure(&e);
                return create_failure_result(
                    key_path,
                    Some(value_name.to_string()),
                    e,
                    false,
                    false,
                );
            }
        };

        // 尝试打开注册表键
        let key_result = Self::open_registry_key(root_key, &subkey, KEY_READ | KEY_WRITE);
        match key_result {
            Ok(key) => {
                log_key_open_success();
                self.delete_value_from_key(&key, key_path, value_name)
            }
            Err(e) => {
                // 检查是否因为键不存在而失败
                if e.raw_os_error() == Some(2) {
                    log_key_not_found();
                    return create_already_deleted_result(
                        key_path,
                        Some(value_name.to_string()),
                        "键不存在（可能已被删除）",
                    );
                }
                log_key_open_failure(&e);
                create_failure_result(
                    key_path,
                    Some(value_name.to_string()),
                    format!("无法打开注册表键: {}", e),
                    false,
                    false,
                )
            }
        }
    }

    /// 删除整个注册表键（递归）
    pub fn delete_registry_key(&self, key_path: &str) -> DeleteResult {
        // 记录删除开始
        log_deletion_start(key_path, None);

        // 检查是否需要删除父GUID目录
        if let Some(parent_guid_path) = Self::should_delete_parent_guid(key_path) {
            log_guid_parent_detection(&parent_guid_path);
            return self.delete_guid_parent_directory(&parent_guid_path, key_path, None);
        }

        // 解析注册表路径
        let parse_result = Self::parse_registry_path(key_path);
        let (root_key, subkey) = match parse_result {
            Ok((root, sub)) => {
                log_parse_success(&root, &sub);
                (root, sub)
            }
            Err(e) => {
                log_parse_failure(&e);
                return create_failure_result(key_path, None, e, false, false);
            }
        };

        // 检查是否是根键（不能删除根键）
        if Self::is_root_key(&subkey) {
            log_root_key_deletion_attempt();
            return create_failure_result(
                key_path,
                None,
                "无法删除注册表根键".to_string(),
                false,
                false,
            );
        }

        // 获取父键路径和子键名
        let split_result = Self::split_key_path(&subkey);
        let (parent_path, key_name) = split_result;

        // 验证键名
        if key_name.is_empty() {
            log_invalid_key_path();
            return create_failure_result(key_path, None, "无效的键路径".to_string(), false, false);
        }

        // 打开父键
        let parent_key_result =
            Self::open_registry_key(root_key, parent_path, KEY_READ | KEY_WRITE);
        match parent_key_result {
            Ok(parent_key) => {
                log_parent_key_open_success();
                self.delete_key_from_parent(&parent_key, key_path, key_name)
            }
            Err(e) => {
                // 检查是否因为父键不存在而失败
                if e.raw_os_error() == Some(2) {
                    log_key_not_found();
                    return create_already_deleted_result(
                        key_path,
                        None,
                        "父键不存在（目标键可能已被删除）",
                    );
                }
                log_parent_key_open_failure(&e);
                create_failure_result(key_path, None, format!("无法打开父键: {}", e), false, false)
            }
        }
    }

    /// 安全删除注册表项（根据重要等级）
    pub fn safe_delete(
        &self,
        key_path: &str,
        value_name: Option<&str>,
        importance: RegistryImportance,
    ) -> DeleteResult {
        // 记录安全删除开始
        log_safe_delete_start(key_path, value_name, importance);

        // 根据重要等级检查是否允许删除
        if Self::is_deletion_blocked(importance) {
            log_deletion_blocked();
            return create_failure_result(
                key_path,
                value_name.map(|s| s.to_string()),
                "此项目被标记为系统关键，禁止删除".to_string(),
                false,
                false,
            );
        }

        log_deletion_allowed();

        // 检查是否需要删除父GUID目录
        if let Some(parent_guid_path) = Self::should_delete_parent_guid(key_path) {
            log_guid_parent_detection(&parent_guid_path);
            return self.delete_guid_parent_directory(&parent_guid_path, key_path, value_name);
        }

        // 执行删除操作
        match value_name {
            Some(name) => self.delete_registry_value(key_path, name),
            None => self.delete_registry_key(key_path),
        }
    }

    /// 批量删除注册表项
    pub fn batch_delete(
        &self,
        items: &[(&str, Option<&str>, RegistryImportance)],
    ) -> Vec<DeleteResult> {
        // 记录批量删除开始
        log_batch_delete_start(items.len());

        let mut results = Vec::with_capacity(items.len());
        let mut success_count = 0;
        let mut fail_count = 0;
        let mut guid_delete_count = 0;

        // 处理每个项目
        for (i, (key_path, value_name, importance)) in items.iter().enumerate() {
            let result =
                self.process_single_item(i, key_path, *value_name, *importance, items.len());

            // 统计结果
            if result.deleted_parent_guid {
                guid_delete_count += 1;
            }

            if !result.success && !result.already_deleted {
                fail_count += 1;
            } else {
                success_count += 1;
            }

            results.push(result);
        }

        // 显示统计结果
        display_batch_delete_summary(items.len(), success_count, fail_count, guid_delete_count);

        results
    }

    /// 从打开的键中删除值
    fn delete_value_from_key(
        &self,
        key: &RegKey,
        key_path: &str,
        value_name: &str,
    ) -> DeleteResult {
        log_value_existence_check();

        // 检查值是否存在
        let value_exists = self.check_value_exists(key, value_name);

        // 如果值不存在，直接返回成功
        if !value_exists {
            log_value_already_deleted();
            return create_already_deleted_result(
                key_path,
                Some(value_name.to_string()),
                "值不存在（可能已被删除）",
            );
        }

        log_deletion_attempt();

        // 执行删除操作
        match key.delete_value(value_name) {
            Ok(_) => self.handle_value_deletion_success(key_path, value_name),
            Err(e) => {
                // 检查是否因为值不存在而失败
                if e.raw_os_error() == Some(2) {
                    log_value_already_deleted();
                    return create_already_deleted_result(
                        key_path,
                        Some(value_name.to_string()),
                        "值不存在（可能已被删除）",
                    );
                }
                self.handle_value_deletion_failure(key_path, value_name, &e)
            }
        }
    }

    /// 从父键中删除子键
    fn delete_key_from_parent(
        &self,
        parent_key: &RegKey,
        key_path: &str,
        key_name: &str,
    ) -> DeleteResult {
        log_subkey_existence_check();

        // 检查子键是否存在
        let subkey_exists = self.check_subkey_exists(parent_key, key_name);

        // 如果子键不存在，直接返回成功
        if !subkey_exists {
            log_key_already_deleted();
            return create_already_deleted_result(key_path, None, "键不存在（可能已被删除）");
        }

        log_recursive_deletion_attempt();

        // 执行递归删除操作
        match parent_key.delete_subkey_all(key_name) {
            Ok(_) => self.handle_key_deletion_success(key_path),
            Err(e) => {
                // 检查是否因为键不存在而失败
                if e.raw_os_error() == Some(2) {
                    log_key_already_deleted();
                    return create_already_deleted_result(
                        key_path,
                        None,
                        "键不存在（可能已被删除）",
                    );
                }
                self.handle_key_deletion_failure(key_path, &e)
            }
        }
    }

    /// 删除父GUID目录
    fn delete_guid_parent_directory(
        &self,
        parent_guid_path: &str,
        original_path: &str,
        value_name: Option<&str>,
    ) -> DeleteResult {
        println!("检测到GUID目录,将删除整个父GUID目录: {}", parent_guid_path);
        println!("原始目标: {}", original_path);

        if let Some(name) = value_name {
            println!("值名: {}", name);
        }

        // 解析父GUID路径
        let parse_result = Self::parse_registry_path(parent_guid_path);
        let (root_key, subkey) = match parse_result {
            Ok((root, sub)) => {
                println!("路径解析成功");
                (root, sub)
            }
            Err(e) => {
                println!("路径解析失败: {}", e);
                return create_failure_result(
                    original_path,
                    value_name.map(|s| s.to_string()),
                    format!("无法解析GUID目录路径: {}", e),
                    false,
                    false,
                );
            }
        };

        // 获取父GUID目录的父路径和GUID目录名
        let split_result = Self::split_key_path(&subkey);
        let (parent_path, guid_dir_name) = split_result;

        if guid_dir_name.is_empty() {
            return create_failure_result(
                original_path,
                value_name.map(|s| s.to_string()),
                "无效的GUID目录路径".to_string(),
                false,
                false,
            );
        }

        // 打开父键
        let parent_key_result =
            Self::open_registry_key(root_key, parent_path, KEY_READ | KEY_WRITE);
        match parent_key_result {
            Ok(parent_key) => {
                println!("成功打开父键,准备删除GUID目录: {}", guid_dir_name);

                // 检查GUID目录是否存在
                if !self.check_subkey_exists(&parent_key, guid_dir_name) {
                    println!("GUID目录不存在(可能已被删除)");
                    return create_already_deleted_result(
                        original_path,
                        value_name.map(|s| s.to_string()),
                        "GUID目录不存在(可能已被删除)",
                    );
                }

                // 删除整个GUID目录
                match parent_key.delete_subkey_all(guid_dir_name) {
                    Ok(_) => {
                        println!("GUID目录删除成功");
                        DeleteResult {
                            success: true,
                            key_path: original_path.to_string(),
                            value_name: value_name.map(|s| s.to_string()),
                            message: format!("已删除父GUID目录: {}", parent_guid_path),
                            already_deleted: false,
                            deleted_parent_guid: true,
                        }
                    }
                    Err(e) => {
                        println!("GUID目录删除失败: {}", e);
                        let error_msg = Self::format_error_message(&e);
                        create_failure_result(
                            original_path,
                            value_name.map(|s| s.to_string()),
                            format!("GUID目录删除失败: {}", error_msg),
                            false,
                            false,
                        )
                    }
                }
            }
            Err(e) => {
                if e.raw_os_error() == Some(2) {
                    println!("父键不存在(GUID目录可能已被删除)");
                    return create_already_deleted_result(
                        original_path,
                        value_name.map(|s| s.to_string()),
                        "父键不存在(GUID目录可能已被删除)",
                    );
                }
                println!("无法打开父键: {}", e);
                create_failure_result(
                    original_path,
                    value_name.map(|s| s.to_string()),
                    format!("无法打开GUID目录的父键: {}", e),
                    false,
                    false,
                )
            }
        }
    }

    /// 检查是否应该删除父GUID目录（找到第一个GUID目录）
    fn should_delete_parent_guid(path: &str) -> Option<String> {
        // 查找路径中的第一个GUID目录
        if let Some(start_pos) = Self::find_first_guid_start(path) {
            // 找到GUID的结束位置
            if let Some(end_pos) = Self::find_guid_end(path, start_pos) {
                // 提取从开始到GUID目录结束的部分
                let guid_path = &path[..end_pos];

                // 验证提取的路径
                if Self::is_valid_guid_path(guid_path) {
                    return Some(guid_path.to_string());
                }
            }
        }

        None
    }

    /// 查找第一个GUID开始位置
    fn find_first_guid_start(path: &str) -> Option<usize> {
        // 查找第一个 '{' 字符，确保它前面是 '\' 或位于路径开头
        for i in 0..path.len() {
            if path.chars().nth(i) == Some('{') {
                // 检查 '{' 前面是否是反斜杠
                if i == 0 || path.chars().nth(i - 1) == Some('\\') {
                    // 检查后面是否有足够的位置容纳GUID格式
                    if i + 37 <= path.len() {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    /// 查找GUID结束位置
    fn find_guid_end(path: &str, start_pos: usize) -> Option<usize> {
        let mut i = start_pos + 1;
        let mut char_count = 0;
        let mut hyphen_count = 0;

        // 验证GUID格式并找到结束位置
        while i < path.len() {
            let c = path.chars().nth(i).unwrap();

            if c == '}' {
                // 找到结束的 '}'
                // 验证格式：8-4-4-4-12
                if char_count == 36 && hyphen_count == 4 {
                    return Some(i + 1); // 包含 '}'
                }
                break;
            }

            // 检查字符是否是有效的GUID字符
            if !Self::is_valid_guid_char(c) {
                break;
            }

            if c == '-' {
                hyphen_count += 1;
                // 验证连字符位置
                if !Self::is_valid_hyphen_position(char_count) {
                    break;
                }
            }

            char_count += 1;
            i += 1;
        }

        None
    }

    /// 检查字符是否是有效的GUID字符
    fn is_valid_guid_char(c: char) -> bool {
        c.is_ascii_hexdigit() || c == '-'
    }

    /// 验证连字符位置（8-4-4-4-12格式）
    fn is_valid_hyphen_position(char_count: usize) -> bool {
        match char_count {
            8 | 13 | 18 | 23 => true, // GUID标准位置
            _ => false,
        }
    }

    /// 验证GUID路径是否有效
    fn is_valid_guid_path(path: &str) -> bool {
        // 确保路径不以反斜杠结尾
        !path.ends_with('\\') && !path.is_empty()
    }

    /// 检查值是否存在
    fn check_value_exists(&self, key: &RegKey, value_name: &str) -> bool {
        key.enum_values()
            .find(|result| match result {
                Ok((name, _)) => name == value_name,
                Err(_) => false,
            })
            .is_some()
    }

    /// 检查子键是否存在
    fn check_subkey_exists(&self, parent_key: &RegKey, key_name: &str) -> bool {
        parent_key.open_subkey(key_name).is_ok()
    }

    /// 处理值删除成功
    fn handle_value_deletion_success(&self, key_path: &str, value_name: &str) -> DeleteResult {
        log_value_deletion_success();
        create_success_result(key_path, Some(value_name), "值删除成功", false)
    }

    /// 处理值删除失败
    fn handle_value_deletion_failure(
        &self,
        key_path: &str,
        value_name: &str,
        error: &std::io::Error,
    ) -> DeleteResult {
        let error_msg = Self::format_error_message(error);
        log_value_deletion_failure(&error_msg);
        create_failure_result(
            key_path,
            Some(value_name.to_string()),
            format!("值删除失败: {}", error_msg),
            false,
            false,
        )
    }

    /// 处理键删除成功
    fn handle_key_deletion_success(&self, key_path: &str) -> DeleteResult {
        log_key_deletion_success();
        create_success_result(key_path, None, "键删除成功", false)
    }

    /// 处理键删除失败
    fn handle_key_deletion_failure(&self, key_path: &str, error: &std::io::Error) -> DeleteResult {
        let error_msg = Self::format_error_message(error);
        log_key_deletion_failure(&error_msg);
        create_failure_result(
            key_path,
            None,
            format!("键删除失败: {}", error_msg),
            false,
            false,
        )
    }

    /// 处理单个项目
    fn process_single_item(
        &self,
        index: usize,
        key_path: &str,
        value_name: Option<&str>,
        importance: RegistryImportance,
        total: usize,
    ) -> DeleteResult {
        // 记录项目处理开始
        log_item_processing_start(index, total);

        let result = self.safe_delete(key_path, value_name, importance);

        // 记录项目处理结果
        log_item_processing_result(&result);

        result
    }

    /// 检查删除是否被阻止
    fn is_deletion_blocked(importance: RegistryImportance) -> bool {
        importance == RegistryImportance::SystemCritical
    }

    /// 解析注册表路径
    fn parse_registry_path(path: &str) -> Result<(HKEY, String), String> {
        let trimmed_path = Self::trim_path(path);

        if trimmed_path.is_empty() {
            return Err("路径为空".to_string());
        }

        // 分割根键和子键
        let (root_str, subkey) = Self::split_root_and_subkey(&trimmed_path);

        // 记录解析调试信息
        log_parse_debug(&trimmed_path, &root_str, &subkey);

        // 映射根键字符串到 HKEY
        let root_key = Self::map_root_string_to_hkey(&root_str)?;

        Ok((root_key, subkey))
    }

    /// 修剪路径
    fn trim_path(path: &str) -> &str {
        path.trim_start_matches("\\\\").trim_start_matches("\\")
    }

    /// 分割根键和子键
    fn split_root_and_subkey(path: &str) -> (String, String) {
        match path.find('\\') {
            Some(pos) => {
                let (root, sub) = path.split_at(pos);
                (root.to_uppercase(), sub[1..].to_string())
            }
            None => (path.to_uppercase(), String::new()),
        }
    }

    /// 映射根键字符串到 HKEY
    fn map_root_string_to_hkey(root_str: &str) -> Result<HKEY, String> {
        let root_key = match root_str {
            "HKEY_CLASSES_ROOT" | "HKCR" => HKEY_CLASSES_ROOT,
            "HKEY_CURRENT_USER" | "HKCU" => HKEY_CURRENT_USER,
            "HKEY_LOCAL_MACHINE" | "HKLM" => HKEY_LOCAL_MACHINE,
            "HKEY_USERS" | "HKU" => HKEY_USERS,
            "HKEY_CURRENT_CONFIG" | "HKCC" => HKEY_CURRENT_CONFIG,
            _ => return Err(format!("未知的根键: {}", root_str)),
        };

        Ok(root_key)
    }

    /// 打开注册表键
    fn open_registry_key(
        root_key: HKEY,
        subkey: &str,
        access: u32,
    ) -> Result<RegKey, std::io::Error> {
        // 记录键打开调试信息
        log_key_open_debug(root_key, subkey, access);

        if subkey.is_empty() {
            Ok(RegKey::predef(root_key))
        } else {
            RegKey::predef(root_key).open_subkey_with_flags(subkey, access)
        }
    }

    /// 检查是否是根键
    fn is_root_key(subkey: &str) -> bool {
        subkey.is_empty() || subkey == "\\"
    }

    /// 分割键路径为父路径和键名
    fn split_key_path(path: &str) -> (&str, &str) {
        if let Some(last_slash) = path.rfind('\\') {
            let (parent, child) = path.split_at(last_slash);
            (parent, &child[1..])
        } else {
            ("", path)
        }
    }

    /// 格式化错误信息
    fn format_error_message(error: &std::io::Error) -> String {
        let (error_desc, error_code) = Self::get_error_description(error);
        let full_message = Self::build_error_message(error_desc, error_code, error);

        // 记录错误详情
        log_error_detail(&full_message);

        full_message
    }

    /// 获取错误描述
    fn get_error_description(error: &std::io::Error) -> (&'static str, Option<i32>) {
        let error_code = error.raw_os_error();
        let error_desc = match error_code {
            Some(2) => "键或值不存在 (ERROR_FILE_NOT_FOUND)",
            Some(5) => "访问被拒绝，需要管理员权限 (ERROR_ACCESS_DENIED)",
            Some(6) => "句柄无效 (ERROR_INVALID_HANDLE)",
            Some(32) => "文件正由其他进程使用 (ERROR_SHARING_VIOLATION)",
            Some(87) => "参数错误 (ERROR_INVALID_PARAMETER)",
            Some(1018) => "密钥已标记为删除",
            Some(145) => "目录不为空 (ERROR_DIR_NOT_EMPTY)",
            Some(267) => "目录名称无效 (ERROR_DIRECTORY)",
            Some(183) => "当文件已存在时，无法创建该文件 (ERROR_ALREADY_EXISTS)",
            Some(-2147024891) => "访问被拒绝 (E_ACCESSDENIED)",
            _ => "未知错误",
        };

        (error_desc, error_code)
    }

    /// 构建错误消息
    fn build_error_message(
        error_desc: &str,
        error_code: Option<i32>,
        error: &std::io::Error,
    ) -> String {
        match error_code {
            Some(code) => format!("{} (错误代码: {})", error_desc, code),
            None => format!("{}: {}", error_desc, error),
        }
    }
}

/// 创建成功结果
fn create_success_result(
    key_path: &str,
    value_name: Option<&str>,
    message: &str,
    deleted_parent_guid: bool,
) -> DeleteResult {
    DeleteResult {
        success: true,
        key_path: key_path.to_string(),
        value_name: value_name.map(|s| s.to_string()),
        message: message.to_string(),
        already_deleted: false,
        deleted_parent_guid,
    }
}

/// 创建失败结果
fn create_failure_result(
    key_path: &str,
    value_name: Option<String>,
    message: String,
    already_deleted: bool,
    deleted_parent_guid: bool,
) -> DeleteResult {
    DeleteResult {
        success: false,
        key_path: key_path.to_string(),
        value_name,
        message,
        already_deleted,
        deleted_parent_guid,
    }
}

/// 创建已经删除的结果（键/值不存在的情况）
fn create_already_deleted_result(
    key_path: &str,
    value_name: Option<String>,
    message: &str,
) -> DeleteResult {
    DeleteResult {
        success: true, // 注意这里返回 success: true
        key_path: key_path.to_string(),
        value_name,
        message: message.to_string(),
        already_deleted: true,
        deleted_parent_guid: false,
    }
}

/// 显示批量删除摘要
fn display_batch_delete_summary(
    total: usize,
    success_count: usize,
    fail_count: usize,
    guid_delete_count: usize,
) {
    println!("\n{}", "=".repeat(60));
    println!("批量删除完成");
    println!("{}", "-".repeat(60));
    println!("成功/已删除: {} 个", success_count);
    println!("实际失败: {} 个", fail_count);
    println!("总计: {} 个", total);

    if guid_delete_count > 0 {
        println!("其中删除GUID目录: {} 个", guid_delete_count);
    }

    let success_rate = if total > 0 {
        (success_count as f32 / total as f32) * 100.0
    } else {
        0.0
    };

    println!("成功率: {:.1}%", success_rate);

    if fail_count == 0 && success_count > 0 {
        println!("所有项目都已清理完成");
    } else if fail_count > 0 {
        println!(" |{}| 个项目需要进一步处理", fail_count);
    }

    println!("{}", "=".repeat(60));
}

/// 记录删除开始
fn log_deletion_start(key_path: &str, value_name: Option<&str>) {
    println!("开始删除操作");
    println!("路径: {}", key_path);

    if let Some(name) = value_name {
        println!("值名: {}", name);
    } else {
        println!("操作: 删除整个键");
    }

    println!("{}", "-".repeat(50));
}

/// 记录GUID父目录检测
fn log_guid_parent_detection(parent_guid_path: &str) {
    println!("检测到GUID目录，将删除整个父目录");
    println!("父GUID路径: {}", parent_guid_path);
}

/// 记录解析成功
fn log_parse_success(root_key: &HKEY, subkey: &str) {
    println!("路径解析成功");
    println!("根键: {:?}", root_key);
    println!("子键: {}", subkey);
}

/// 记录解析失败
fn log_parse_failure(error: &str) {
    println!("路径解析失败: {}", error);
}

/// 记录键打开成功
fn log_key_open_success() {
    println!("成功打开注册表键");
}

/// 记录键打开失败
fn log_key_open_failure(error: &std::io::Error) {
    println!("无法打开注册表键: {}", error);
}

/// 记录键未找到
fn log_key_not_found() {
    println!("键不存在（可能已被删除）");
}

/// 记录值已删除
fn log_value_already_deleted() {
    println!("值不存在（可能已被删除）");
}

/// 记录键已删除
fn log_key_already_deleted() {
    println!("键不存在（可能已被删除）");
}

/// 记录根键删除尝试
fn log_root_key_deletion_attempt() {
    println!("尝试删除注册表根键，操作被拒绝");
}

/// 记录无效键路径
fn log_invalid_key_path() {
    println!("无效的键路径");
}

/// 记录父键打开成功
fn log_parent_key_open_success() {
    println!("成功打开父键");
}

/// 记录父键打开失败
fn log_parent_key_open_failure(error: &std::io::Error) {
    println!("无法打开父键: {}", error);
}

/// 记录安全删除开始
fn log_safe_delete_start(key_path: &str, value_name: Option<&str>, importance: RegistryImportance) {
    println!("\n安全删除检查");
    println!("{}", "=".repeat(60));
    println!("目标路径: {}", key_path);

    let value_display = value_name.unwrap_or_else(|| "(删除整个键)");

    println!("值名: {}", value_display);
    println!("重要等级: {:?}", importance);
    println!("{}", "-".repeat(60));
}

/// 记录删除被阻止
fn log_deletion_blocked() {
    println!("此项目被标记为系统关键,禁止删除");
}

/// 记录删除允许
fn log_deletion_allowed() {
    println!("重要等级检查通过,开始删除操作");
}

/// 记录批量删除开始
fn log_batch_delete_start(total: usize) {
    println!("\n开始批量删除");
    println!("{}", "=".repeat(60));
    println!("总项目数: {}", total);
    println!("{}", "-".repeat(60));
}

/// 记录值存在性检查
fn log_value_existence_check() {
    println!("检查值是否存在...");
}

/// 记录值删除尝试
fn log_deletion_attempt() {
    println!("正在删除值...");
}

/// 记录子键存在性检查
fn log_subkey_existence_check() {
    println!("检查子键是否存在...");
}

/// 记录递归删除尝试
fn log_recursive_deletion_attempt() {
    println!("正在递归删除子键...");
}

/// 记录值删除成功
fn log_value_deletion_success() {
    println!("值删除成功");
}

/// 记录值删除失败
fn log_value_deletion_failure(error_msg: &str) {
    println!("值删除失败: {}", error_msg);
}

/// 记录键删除成功
fn log_key_deletion_success() {
    println!("键删除成功");
}

/// 记录键删除失败
fn log_key_deletion_failure(error_msg: &str) {
    println!("键删除失败: {}", error_msg);
}

/// 记录项目处理开始
fn log_item_processing_start(index: usize, total: usize) {
    println!("\n[ITEM {}/{}]", index + 1, total);
    println!("{}", "-".repeat(40));
}

/// 记录项目处理结果
fn log_item_processing_result(result: &DeleteResult) {
    if result.success {
        if result.already_deleted {
            println!("已删除/不存在");
        } else if result.deleted_parent_guid {
            println!("成功(已删除父GUID目录)");
        } else {
            println!("成功");
        }
    } else {
        println!("失败: {}", result.message);
    }
}

/// 记录解析调试信息
fn log_parse_debug(path: &str, root_str: &str, subkey: &str) {
    println!("原始路径: {}", path);
    println!("根键字符串: {}", root_str);
    println!("子键路径: {}", subkey);
}

/// 记录键打开调试信息
fn log_key_open_debug(root_key: HKEY, subkey: &str, access: u32) {
    println!("尝试打开键:");
    println!("根键: {:?}", root_key);
    println!("子键: {}", subkey);
    println!("访问权限: 0x{:X}", access);
}

/// 记录错误详情
fn log_error_detail(message: &str) {
    println!("{}", message);
}
