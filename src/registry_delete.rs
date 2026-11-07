//! 注册表删除模块
//!
//! 提供单个键/值的删除能力，并针对路径中的 GUID 子键做了特殊处理：
//! 一旦路径中出现形如 `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}` 的 GUID 段，
//! 会直接删除该 GUID 所在的父键（含其下所有子项），而不是只删 GUID 下面的某一层。

use winreg::enums::*;
use winreg::{RegKey, HKEY};

/// 在路径中查找第一个完整 GUID 段，并返回"包含该 GUID 的路径前缀"。
///
/// GUID 段格式：`{8-4-4-4-12}`，共 36 个字符 + 2 个花括号 = 38 字符。
/// 要求 GUID 后面要么是路径分隔符 `\`，要么已经是路径结尾，避免误匹配
/// `{...}abc` 这类把 GUID 当名字一部分的场景。
///
/// 返回示例：
/// - 输入 `HKLM\Software\Classes\CLSID\{ABCD...}\InprocServer32`
/// - 返回 `HKLM\Software\Classes\CLSID\{ABCD...}`
fn find_guid_in_path(path: &str) -> Option<String> {
    let bytes = path.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'{' {
            let start = i;
            // 固定位置校验：8-4-4-4-12 之间必须有 '-'，末尾必须有 '}'
            if i + 37 < bytes.len()
                && bytes[i + 9] == b'-'
                && bytes[i + 14] == b'-'
                && bytes[i + 19] == b'-'
                && bytes[i + 24] == b'-'
                && bytes[i + 37] == b'}'
            {
                // 花括号内部只允许十六进制字符和 '-'
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
                    let guid_end = i + 38; // 含结尾的 '}'
                                           // GUID 之后必须是 '\' 或字符串结束
                    if guid_end == bytes.len() || bytes[guid_end] == b'\\' {
                        let guid_str = String::from_utf8_lossy(&bytes[start..guid_end]).to_string();
                        let path_str = String::from_utf8_lossy(bytes).to_string();
                        return Some(path_str[..start + guid_str.len()].to_string());
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

/// 单条删除的结果。
///
/// 字段含义：
/// - `success`：操作是否成功（`already_deleted` 的条目 `success` 也为 true）。
/// - `key_path`：发起删除时使用的原始路径（便于 UI 展示）。
/// - `value_name`：删除的是"值"时记录值名，删除"键"时为 `None`。
/// - `message`：给用户看的说明文字（失败时即失败原因）。
/// - `already_deleted`：目标本来就不存在（不算失败，但也不计成功）。
/// - `skipped`：用户主动跳过；当前 GUI 流程不会产生该状态，保留用于兼容未来。
#[derive(Debug, Clone)]
pub struct DeleteResult {
    pub success: bool,
    pub key_path: String,
    pub value_name: Option<String>,
    pub message: String,
    pub already_deleted: bool,
    pub skipped: bool,
}

impl DeleteResult {
    /// 构造"删除成功"的结果。
    pub fn success(key_path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            success: true,
            key_path: key_path.into(),
            value_name: None,
            message: message.into(),
            already_deleted: false,
            skipped: false,
        }
    }

    /// 构造"删除失败"的结果（例如权限不足、路径无法解析等）。
    pub fn failure(key_path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            success: false,
            key_path: key_path.into(),
            value_name: None,
            message: message.into(),
            already_deleted: false,
            skipped: false,
        }
    }

    /// 构造"目标本来就不存在"的结果。
    /// 注意 `success` 仍为 true，UI 侧应优先根据 `already_deleted` 分类展示。
    pub fn already_deleted(key_path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            success: true,
            key_path: key_path.into(),
            value_name: None,
            message: message.into(),
            already_deleted: true,
            skipped: false,
        }
    }
}

/// 注册表删除器。
///
/// 目前只暴露一个可配置项 `delete_guid_parent`：是否把"删除 GUID 下的子项"
/// 升级为"直接删除整个 GUID 父键"。默认开启，与工具的设计意图一致。
pub struct RegistryDeleter {
    delete_guid_parent: bool,
}

impl RegistryDeleter {
    /// 创建删除器；默认开启 GUID 父键级联删除。
    pub fn new() -> Self {
        Self {
            delete_guid_parent: true,
        }
    }

    // ---------------- 单个删除 ----------------

    /// 删除指定键下的某个值。
    ///
    /// 流程：
    /// 1. 若路径中含 GUID 且启用了 GUID 父键删除，则转交 `delete_guid_parent_directory`；
    /// 2. 否则解析根键并打开子键（需要 READ | WRITE）；
    /// 3. 枚举值确认目标确实存在（不存在按 "already_deleted" 返回）；
    /// 4. 调用 `delete_value` 执行删除，`ERROR_FILE_NOT_FOUND` 视为已不存在。
    pub fn delete_value(&self, key_path: &str, value_name: &str) -> DeleteResult {
        // GUID 路径优先走父键级联删除，避免留下空壳
        if let Some(parent_guid) = self.should_delete_parent_guid(key_path) {
            return self.delete_guid_parent_directory(&parent_guid, key_path, Some(value_name));
        }

        let (root, subkey) = match self.parse_registry_path(key_path) {
            Ok(parsed) => parsed,
            Err(e) => return DeleteResult::failure(key_path, e),
        };

        // 打开目标键（读 + 写），失败时按 OS 错误码区分"不存在"与"其他失败"
        let key = match RegKey::predef(root).open_subkey_with_flags(&subkey, KEY_READ | KEY_WRITE) {
            Ok(k) => k,
            Err(e) => {
                if e.raw_os_error() == Some(2) {
                    return DeleteResult::already_deleted(key_path, "键不存在");
                }
                return DeleteResult::failure(key_path, format!("无法打开键: {}", e));
            }
        };

        // 枚举检查值是否存在；不存在就直接返回，不必调用 DeleteValue
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

    /// 删除一个注册表键（连同其全部子键、值）。
    ///
    /// 流程：
    /// 1. 若路径中含 GUID 且启用了 GUID 父键删除，则转交 `delete_guid_parent_directory`；
    /// 2. 拆分父键路径与键名，打开父键；
    /// 3. 探测目标键是否存在；
    /// 4. 调用 `delete_subkey_all` 递归删除。
    pub fn delete_key(&self, key_path: &str) -> DeleteResult {
        if let Some(parent_guid) = self.should_delete_parent_guid(key_path) {
            return self.delete_guid_parent_directory(&parent_guid, key_path, None);
        }

        let (root, subkey) = match self.parse_registry_path(key_path) {
            Ok(parsed) => parsed,
            Err(e) => return DeleteResult::failure(key_path, e),
        };

        // 不允许删除根键本身
        if subkey.is_empty() {
            return DeleteResult::failure(key_path, "不能删除根键");
        }

        let (parent_path, key_name) = self.split_key_path(&subkey);

        // 父路径为空说明目标是根键的直接子键，直接用根句柄
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

        // 先探测目标键是否存在，避免 delete_subkey_all 对不存在键产生歧义错误
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

    // ---------------- GUID 父目录处理 ----------------

    /// 判断路径里是否有 GUID 段，并返回含 GUID 的前缀路径。
    /// 若未启用该特性则直接返回 `None`。
    fn should_delete_parent_guid(&self, path: &str) -> Option<String> {
        if !self.delete_guid_parent {
            return None;
        }
        find_guid_in_path(path)
    }

    /// 删除 `parent_guid_path` 指向的 GUID 父键（递归删除其全部内容）。
    ///
    /// 参数：
    /// - `parent_guid_path`：含 GUID 的前缀路径（已由 `find_guid_in_path` 截出）。
    /// - `original_path`：用户最初请求删除的路径，仅用于结果里的展示。
    /// - `value_name`：原请求若为"删除值"，则记录下来；"删除键"时为 `None`。
    fn delete_guid_parent_directory(
        &self,
        parent_guid_path: &str,
        original_path: &str,
        value_name: Option<&str>,
    ) -> DeleteResult {
        let (root, subkey) = match self.parse_registry_path(parent_guid_path) {
            Ok(parsed) => parsed,
            Err(e) => {
                return DeleteResult::failure(original_path, format!("解析 GUID 路径失败: {}", e))
            }
        };

        let (parent_path, guid_name) = self.split_key_path(&subkey);
        if guid_name.is_empty() {
            return DeleteResult::failure(original_path, "无效的 GUID 路径");
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
            return DeleteResult::already_deleted(original_path, "GUID 目录不存在");
        }

        match parent.delete_subkey_all(guid_name) {
            Ok(_) => DeleteResult {
                success: true,
                key_path: original_path.to_string(),
                value_name: value_name.map(String::from),
                message: format!("已删除 GUID 父目录: {}", parent_guid_path),
                already_deleted: false,
                skipped: false,
            },
            Err(e) => DeleteResult::failure(original_path, format!("删除 GUID 目录失败: {}", e)),
        }
    }

    // ---------------- 路径解析 ----------------

    /// 把 "根键 + 子路径" 形式的字符串拆成 `(HKEY, 子路径)`。
    ///
    /// - 支持长短两种根键写法（HKEY_LOCAL_MACHINE / HKLM 等）。
    /// - 允许前导 `\` 或 `\\`，方便直接粘贴注册表编辑器里的路径。
    /// - 找不到根键时返回错误字符串，由调用方封装为 `DeleteResult::failure`。
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

    /// 把子路径拆成 `(父路径, 末段键名)`。
    /// 没有分隔符时返回 `("", 原路径)`，表示目标挂在根键下。
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
