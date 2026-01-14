//! 注册表备份模块
use std::fs::{self};
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

/// 备份结果
#[derive(Debug)]
pub struct BackupResult {
    pub success: bool,
    pub backup_path: String,
    pub message: String,
    #[allow(dead_code)]
    pub timestamp: String,
}

/// 注册表备份器
pub struct RegistryBackup {
    backup_dir: String,
}

impl RegistryBackup {
    /// 创建新的备份器 - 使用根目录的backup文件夹
    pub fn new() -> Self {
        // 直接使用根目录的backup文件夹
        let backup_dir = "backup".to_string();

        // 清理旧的备份（覆盖）
        Self::cleanup_backup_dir(&backup_dir);

        RegistryBackup { backup_dir }
    }

    /// 清理备份目录（如果存在则删除所有内容）
    fn cleanup_backup_dir(dir: &str) {
        let path = Path::new(dir);
        if path.exists() {
            println!("清理旧的备份目录: {}", dir);
            let _ = fs::remove_dir_all(dir);
        }
    }

    /// 获取格式化的日期时间字符串
    fn get_formatted_datetime() -> String {
        let now = SystemTime::now();
        let duration = now.duration_since(UNIX_EPOCH).unwrap_or_default();

        let seconds = duration.as_secs();
        let minutes = seconds / 60;
        let hours = minutes / 60;
        let days = hours / 24;

        // 从1970-01-01开始计算
        let year = 1970 + (days / 365) as u32;
        let month = ((days % 365) / 30) as u32 + 1;
        let day = (days % 30) as u32 + 1;
        let hour = (hours % 24) as u32;
        let minute = (minutes % 60) as u32;
        let second = (seconds % 60) as u32;

        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            year, month, day, hour, minute, second
        )
    }

    /// 创建备份目录
    fn create_backup_directory(&self) -> bool {
        let path = Path::new(&self.backup_dir);

        // 如果目录存在，先删除
        if path.exists() {
            if let Err(e) = fs::remove_dir_all(&self.backup_dir) {
                println!("清理旧备份失败: {}", e);
                return false;
            }
        }

        // 创建新目录
        match fs::create_dir_all(&self.backup_dir) {
            Ok(_) => {
                println!("创建备份目录: {}", self.backup_dir);
                true
            }
            Err(e) => {
                println!("创建备份目录失败: {}", e);
                false
            }
        }
    }

    /// 备份整个注册表（一次性备份）
    pub fn backup_full_registry(&self) -> BackupResult {
        println!();
        println!("{}", "═".repeat(60));
        println!("开始备份注册表");
        println!("备份目录: {}", self.backup_dir);
        println!("{}", "─".repeat(60));

        // 创建备份目录（会清理旧的）
        if !self.create_backup_directory() {
            return BackupResult {
                success: false,
                backup_path: self.backup_dir.clone(),
                message: "创建备份目录失败".to_string(),
                timestamp: Self::get_formatted_datetime(),
            };
        }

        let backup_file = format!("{}/registry_backup.reg", self.backup_dir);

        println!("正在备份整个注册表...");

        // 备份整个注册表（需要管理员权限）
        // 注意：reg save 命令不接受带引号的路径
        let result = Command::new("cmd")
            .args(&["/C", "reg", "save", "hklm", &backup_file, "/y"])
            .output();

        let backup_result = match result {
            Ok(output) => {
                if output.status.success() {
                    println!("  ✓ 注册表备份成功");
                    BackupResult {
                        success: true,
                        backup_path: backup_file.clone(),
                        message: format!("注册表备份成功，文件: {}", backup_file),
                        timestamp: Self::get_formatted_datetime(),
                    }
                } else {
                    // 如果备份整个注册表失败，尝试备份当前用户
                    let error_msg = String::from_utf8_lossy(&output.stderr);
                    println!("  ⚠ 备份整个注册表失败: {}", error_msg);
                    println!("  ⚠ 正在尝试备份当前用户注册表...");

                    // 备份当前用户注册表
                    self.backup_current_user(&backup_file)
                }
            }
            Err(e) => {
                println!("  ⚠ 执行备份命令失败: {}", e);
                println!("  ⚠ 正在尝试备份当前用户注册表...");

                // 备份当前用户注册表
                self.backup_current_user(&backup_file)
            }
        };

        println!("{}", "─".repeat(60));
        println!(
            "备份完成: {}",
            if backup_result.success {
                "成功"
            } else {
                "失败"
            }
        );
        println!("{}", "═".repeat(60));

        backup_result
    }

    /// 备份当前用户注册表（不需要管理员权限）
    fn backup_current_user(&self, backup_file: &str) -> BackupResult {
        let result = Command::new("reg")
            .args(&["export", "HKCU", backup_file, "/y"])
            .output();

        match result {
            Ok(output) => {
                if output.status.success() {
                    println!("  ✓ 当前用户注册表备份成功");
                    BackupResult {
                        success: true,
                        backup_path: backup_file.to_string(),
                        message: "当前用户注册表备份成功".to_string(),
                        timestamp: Self::get_formatted_datetime(),
                    }
                } else {
                    let error_msg = String::from_utf8_lossy(&output.stderr);
                    println!("  ✗ 备份失败: {}", error_msg);
                    BackupResult {
                        success: false,
                        backup_path: backup_file.to_string(),
                        message: format!("备份失败: {}", error_msg),
                        timestamp: Self::get_formatted_datetime(),
                    }
                }
            }
            Err(e) => {
                println!("  ✗ 备份失败: {}", e);
                BackupResult {
                    success: false,
                    backup_path: backup_file.to_string(),
                    message: format!("备份失败: {}", e),
                    timestamp: Self::get_formatted_datetime(),
                }
            }
        }
    }
}
