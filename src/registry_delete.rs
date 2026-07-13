//! 注册表删除模块
//! 提供注册表项删除功能

use std::io::{self, Write};
use winreg::enums::*;
use winreg::{RegKey, HKEY};
use crate::registry_search::format_registry_value;

/// 检查路径中是否包含 GUID 并返回 GUID 路径
fn find_guid_in_path(path: &str) -> Option<String> {
    // GUID 格式: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
    let bytes = path.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        // 查找 '{'
        if bytes[i] == b'{' {
            let start = i;
            // 检查是否是有效的 GUID
            // 格式: {8-4-4-4-12} 共 36 个字符 + 2 个花括号 = 38
            if i + 37 < bytes.len() {
                // 检查位置 9, 14, 19, 24 是否都是 '-'
                if bytes[i + 9] == b'-'
                    && bytes[i + 14] == b'-'
                    && bytes[i + 19] == b'-'
                    && bytes[i + 24] == b'-'
                    && bytes[i + 37] == b'}'
                {
                    // 检查所有十六进制字符
                    let mut valid = true;
                    for j in (i + 1)..(i + 37) {
                        let c = bytes[j];
                        if c != b'-'
                            && !(c >= b'0' && c <= b'9')
                            && !(c >= b'A' && c <= b'F')
                            && !(c >= b'a' && c <= b'f')
                        {
                            valid = false;
                            break;
                        }
                    }
                    if valid {
                        let guid_end = i + 38; // 包括 '}'
                        // 检查 GUID 后面是否是路径分隔符或结束
                        if guid_end == bytes.len() || bytes[guid_end] == b'\\' {
                            let guid_str =
                                String::from_utf8_lossy(&bytes[start..guid_end]).to_string();
                            // 获取包含 GUID 的完整路径前缀
                            let path_str = String::from_utf8_lossy(bytes).to_string();
                            return Some(path_str[..start + guid_str.len()].to_string());
                        }
                    }
                }
            }
            i += 1;
        } else {
            i += 1;
        }
    }
    None
}

/// 删除结果
#[derive(Debug, Clone)]
pub struct DeleteResult {
    pub success: bool,
    #[allow(dead_code)]
    pub key_path: String,
    #[allow(dead_code)]
    pub value_name: Option<String>,
    pub message: String,
    pub already_deleted: bool,
    #[allow(dead_code)]
    pub deleted_parent_guid: bool,
    #[allow(dead_code)]
    pub skipped: bool,
}

impl DeleteResult {
    pub fn success(key_path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            success: true,
            key_path: key_path.into(),
            value_name: None,
            message: message.into(),
            already_deleted: false,
            deleted_parent_guid: false,
            skipped: false,
        }
    }

    pub fn failure(key_path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            success: false,
            key_path: key_path.into(),
            value_name: None,
            message: message.into(),
            already_deleted: false,
            deleted_parent_guid: false,
            skipped: false,
        }
    }

    pub fn already_deleted(key_path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            success: true,
            key_path: key_path.into(),
            value_name: None,
            message: message.into(),
            already_deleted: true,
            deleted_parent_guid: false,
            skipped: false,
        }
    }

    pub fn skipped(key_path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            success: false,
            key_path: key_path.into(),
            value_name: None,
            message: message.into(),
            already_deleted: false,
            deleted_parent_guid: false,
            skipped: true,
        }
    }
}

/// 注册表删除器
pub struct RegistryDeleter {
    delete_guid_parent: bool,
}

impl RegistryDeleter {
    pub fn new() -> Self {
        Self {
            delete_guid_parent: true,
        }
    }

    pub fn delete_value(&self, key_path: &str, value_name: &str) -> DeleteResult {
        if let Some(parent_guid) = self.should_delete_parent_guid(key_path) {
            return self.delete_guid_parent_directory(&parent_guid, key_path, Some(value_name));
        }

        let (root, subkey) = match self.parse_registry_path(key_path) {
            Ok(parsed) => parsed,
            Err(e) => return DeleteResult::failure(key_path, e),
        };

        let key = match RegKey::predef(root).open_subkey_with_flags(&subkey, KEY_READ | KEY_WRITE) {
            Ok(k) => k,
            Err(e) => {
                if e.raw_os_error() == Some(2) {
                    return DeleteResult::already_deleted(key_path, "键不存在");
                }
                return DeleteResult::failure(key_path, format!("无法打开键: {}", e));
            }
        };

        // 检查值是否存在
        let exists = key
            .enum_values()
            .any(|r| r.is_ok_and(|(name, _)| name == value_name));
        if !exists {
            return DeleteResult::already_deleted(key_path, "值不存在");
        }

        match key.delete_value(value_name) {
            Ok(_) => DeleteResult::success(key_path, format!("值 '{}' 删除成功", value_name)),
            Err(e) => {
                if e.raw_os_error() == Some(2) {
                    DeleteResult::already_deleted(key_path, "值不存在")
                } else {
                    DeleteResult::failure(key_path, format!("删除失败: {}", e))
                }
            }
        }
    }

    pub fn delete_key(&self, key_path: &str) -> DeleteResult {
        if let Some(parent_guid) = self.should_delete_parent_guid(key_path) {
            return self.delete_guid_parent_directory(&parent_guid, key_path, None);
        }

        let (root, subkey) = match self.parse_registry_path(key_path) {
            Ok(parsed) => parsed,
            Err(e) => return DeleteResult::failure(key_path, e),
        };

        if subkey.is_empty() {
            return DeleteResult::failure(key_path, "不能删除根键");
        }

        let (parent_path, key_name) = self.split_key_path(&subkey);

        // 如果父路径为空，说明要删除的是根键下的直接子键
        let parent = if parent_path.is_empty() {
            RegKey::predef(root)
        } else {
            match RegKey::predef(root).open_subkey_with_flags(parent_path, KEY_READ | KEY_WRITE) {
                Ok(p) => p,
                Err(e) => {
                    if e.raw_os_error() == Some(2) {
                        return DeleteResult::already_deleted(key_path, "父键不存在");
                    }
                    return DeleteResult::failure(key_path, format!("无法打开父键: {}", e));
                }
            }
        };

        // 检查键是否存在
        if parent.open_subkey(key_name).is_err() {
            return DeleteResult::already_deleted(key_path, "键不存在");
        }

        match parent.delete_subkey_all(key_name) {
            Ok(_) => DeleteResult::success(key_path, "键删除成功"),
            Err(e) => {
                if e.raw_os_error() == Some(2) {
                    DeleteResult::already_deleted(key_path, "键不存在")
                } else {
                    DeleteResult::failure(key_path, format!("删除失败: {}", e))
                }
            }
        }
    }

    /// 批量删除，每个项目都询问用户确认
    pub fn batch_delete(&self, items: &[(&str, Option<&str>)]) -> Vec<DeleteResult> {
        let mut results = Vec::with_capacity(items.len());

        for (index, (path, value_name)) in items.iter().enumerate() {
            // 先检查是否存在
            let exists = match value_name {
                Some(name) => self.check_value_exists(path, name),
                None => self.check_key_exists(path),
            };

            // 显示分隔线和序号
            println!("\n{}", "=".repeat(80));
            println!("项目 [{}/{}]", index + 1, items.len());

            // 显示完整路径
            println!("路径: {}", path);

            match value_name {
                Some(name) => {
                    println!("值名: {}", name);
                    if !exists {
                        println!("状态: ❌ 值不存在");
                        println!("{}", "=".repeat(80));
                        // 自动跳过
                        let result = DeleteResult::already_deleted(
                            *path,
                            format!("值 '{}' 不存在", name)
                        );
                        results.push(result);
                        continue;
                    }
                    // 尝试读取值数据
                    if let Some(data) = self.get_value_data(path, name) {
                        println!("数据: {}", data);
                    } else {
                        println!("数据: <无法读取>");
                    }
                    println!("操作: 删除此值");
                }
                None => {
                    if !exists {
                        println!("状态: ❌ 键不存在");
                        println!("{}", "=".repeat(80));
                        // 自动跳过
                        let result = DeleteResult::already_deleted(
                            *path,
                            "键不存在".to_string()
                        );
                        results.push(result);
                        continue;
                    }
                    println!("操作: 删除此键及其所有子项");
                }
            }
            println!("{}", "=".repeat(80));

            // 询问用户是否删除
            if !self.ask_user_confirmation() {
                let result = DeleteResult::skipped(
                    *path,
                    match value_name {
                        Some(name) => format!("已跳过值 '{}'", name),
                        None => "已跳过".to_string(),
                    },
                );
                results.push(result);
                continue;
            }

            // 执行删除
            let result = match value_name {
                Some(name) => self.delete_value(path, name),
                None => self.delete_key(path),
            };

            if result.success {
                println!("✓ {}", result.message);
            } else {
                println!("✗ {}", result.message);
            }
            results.push(result);
        }

        // 显示总结
        if !results.is_empty() {
            println!("\n{}", "=".repeat(80));
            let success_count = results.iter().filter(|r| r.success && !r.already_deleted).count();
            let already_deleted_count = results.iter().filter(|r| r.already_deleted).count();
            let skipped_count = results.iter().filter(|r| r.skipped).count();
            let failed_count = results.len() - success_count - already_deleted_count - skipped_count;
            println!("删除完成: 成功 {} 项, 已不存在 {} 项, 跳过 {} 项, 失败 {} 项",
                     success_count, already_deleted_count, skipped_count, failed_count);
            println!("{}", "=".repeat(80));
        }

        results
    }

    /// 检查值是否存在
    fn check_value_exists(&self, key_path: &str, value_name: &str) -> bool {
        let (root, subkey) = match self.parse_registry_path(key_path) {
            Ok(parsed) => parsed,
            Err(_) => return false,
        };

        let key = match RegKey::predef(root).open_subkey_with_flags(&subkey, KEY_READ) {
            Ok(k) => k,
            Err(_) => return false,
        };

        // 检查值是否存在
        key.enum_values()
            .any(|r| r.is_ok_and(|(name, _)| name == value_name))
    }

    /// 检查键是否存在
    fn check_key_exists(&self, key_path: &str) -> bool {
        let (root, subkey) = match self.parse_registry_path(key_path) {
            Ok(parsed) => parsed,
            Err(_) => return false,
        };

        if subkey.is_empty() {
            return false;
        }

        let (parent_path, key_name) = self.split_key_path(&subkey);

        let parent = if parent_path.is_empty() {
            RegKey::predef(root)
        } else {
            match RegKey::predef(root).open_subkey_with_flags(parent_path, KEY_READ) {
                Ok(p) => p,
                Err(_) => return false,
            }
        };

        parent.open_subkey(key_name).is_ok()
    }

    /// 获取值数据（用于显示）
    fn get_value_data(&self, key_path: &str, value_name: &str) -> Option<String> {
        let (root, subkey) = match self.parse_registry_path(key_path) {
            Ok(parsed) => parsed,
            Err(_) => return None,
        };

        let key = match RegKey::predef(root).open_subkey_with_flags(&subkey, KEY_READ) {
            Ok(k) => k,
            Err(_) => return None,
        };

        // 查找值数据
        for value_result in key.enum_values() {
            if let Ok((name, value)) = value_result {
                if name == value_name {
                    return Some(format_registry_value(&value));
                }
            }
        }
        None
    }

    /// 询问用户是否删除当前项
    fn ask_user_confirmation(&self) -> bool {
        loop {
            print!("是否删除? [y | n | q]: ");
            io::stdout().flush().unwrap();

            let mut input = String::new();
            io::stdin().read_line(&mut input).unwrap();
            let input = input.trim().to_lowercase();

            match input.as_str() {
                "y" | "yes" => return true,
                "n" | "no" => return false,
                "q" | "quit" | "exit" => {
                    println!("退出删除操作");
                    std::process::exit(0);
                }
                _ => {
                    println!("无效输入，请输入 y | n | q");
                    continue;
                }
            }
        }
    }

    fn should_delete_parent_guid(&self, path: &str) -> Option<String> {
        if !self.delete_guid_parent {
            return None;
        }
        find_guid_in_path(path)
    }

    fn delete_guid_parent_directory(
        &self,
        parent_guid_path: &str,
        original_path: &str,
        value_name: Option<&str>,
    ) -> DeleteResult {
        eprintln!("删除GUID父目录: {}", parent_guid_path);

        let (root, subkey) = match self.parse_registry_path(parent_guid_path) {
            Ok(parsed) => parsed,
            Err(e) => {
                return DeleteResult::failure(original_path, format!("解析GUID路径失败: {}", e))
            }
        };

        let (parent_path, guid_name) = self.split_key_path(&subkey);
        if guid_name.is_empty() {
            return DeleteResult::failure(original_path, "无效的GUID路径");
        }

        let parent = if parent_path.is_empty() {
            RegKey::predef(root)
        } else {
            match RegKey::predef(root).open_subkey_with_flags(parent_path, KEY_READ | KEY_WRITE) {
                Ok(p) => p,
                Err(e) => {
                    if e.raw_os_error() == Some(2) {
                        return DeleteResult::already_deleted(original_path, "父键不存在");
                    }
                    return DeleteResult::failure(original_path, format!("无法打开父键: {}", e));
                }
            }
        };

        if parent.open_subkey(guid_name).is_err() {
            return DeleteResult::already_deleted(original_path, "GUID目录不存在");
        }

        match parent.delete_subkey_all(guid_name) {
            Ok(_) => DeleteResult {
                success: true,
                key_path: original_path.to_string(),
                value_name: value_name.map(String::from),
                message: format!("已删除GUID父目录: {}", parent_guid_path),
                already_deleted: false,
                deleted_parent_guid: true,
                skipped: false,
            },
            Err(e) => DeleteResult::failure(original_path, format!("删除GUID目录失败: {}", e)),
        }
    }

    fn parse_registry_path(&self, path: &str) -> Result<(HKEY, String), String> {
        let trimmed = path.trim_start_matches("\\\\").trim_start_matches('\\');
        if trimmed.is_empty() {
            return Err("路径为空".to_string());
        }

        let (root_str, subkey) = match trimmed.find('\\') {
            Some(pos) => {
                let (root, sub) = trimmed.split_at(pos);
                (root.to_uppercase(), sub[1..].to_string())
            }
            None => (trimmed.to_uppercase(), String::new()),
        };

        let root_key = match root_str.as_str() {
            "HKEY_CLASSES_ROOT" | "HKCR" => HKEY_CLASSES_ROOT,
            "HKEY_CURRENT_USER" | "HKCU" => HKEY_CURRENT_USER,
            "HKEY_LOCAL_MACHINE" | "HKLM" => HKEY_LOCAL_MACHINE,
            "HKEY_USERS" | "HKU" => HKEY_USERS,
            "HKEY_CURRENT_CONFIG" | "HKCC" => HKEY_CURRENT_CONFIG,
            _ => return Err(format!("未知根键: {}", root_str)),
        };

        Ok((root_key, subkey))
    }

    fn split_key_path<'a>(&self, path: &'a str) -> (&'a str, &'a str) {
        path.rfind('\\')
            .map(|pos| {
                let (parent, child) = path.split_at(pos);
                (parent, &child[1..])
            })
            .unwrap_or(("", path))
    }
}

impl Default for RegistryDeleter {
    fn default() -> Self {
        Self::new()
    }
}