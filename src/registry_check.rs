// registry_check.rs
use std::fs;

// 添加 Serde 依赖
use serde::{Deserialize, Serialize};

/// 注册表重要等级分类
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegistryImportance {
    /// 系统关键 - Windows内核和核心组件，绝对不能删除
    SystemCritical,
    /// 高度危险 - 可能包含恶意软件或系统威胁
    HighRisk,
    /// 未知区域 - 不在特征库中的路径，需要人工审核（比安全部分等级更高）
    Unknown,
    /// 安全部分 - 用户应用程序和自定义设置
    Safe,
}

/// 实现显示特性
impl std::fmt::Display for RegistryImportance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegistryImportance::SystemCritical => write!(f, "系统关键"),
            RegistryImportance::HighRisk => write!(f, "高度危险"),
            RegistryImportance::Unknown => write!(f, "未知区域"),
            RegistryImportance::Safe => write!(f, "安全部分"),
        }
    }
}

/// 实现排序特性（从危险到安全）
impl PartialOrd for RegistryImportance {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RegistryImportance {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // 定义优先级：系统关键 > 高度危险 > 未知区域 > 安全部分
        let self_priority = match self {
            RegistryImportance::SystemCritical => 4,
            RegistryImportance::HighRisk => 3,
            RegistryImportance::Unknown => 2,
            RegistryImportance::Safe => 1,
        };

        let other_priority = match other {
            RegistryImportance::SystemCritical => 4,
            RegistryImportance::HighRisk => 3,
            RegistryImportance::Unknown => 2,
            RegistryImportance::Safe => 1,
        };

        self_priority.cmp(&other_priority)
    }
}

/// 匹配类型枚举
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchType {
    /// 键路径匹配
    Item,
    /// 值名匹配
    Key,
    /// 值数据匹配
    Value,
}

/// 搜索结果结构体
#[derive(Debug, Clone)]
pub struct SearchResult {
    /// 注册表键路径
    pub key_path: String,
    /// 值名称（可选）
    pub value_name: Option<String>,
    /// 值数据（可选）
    pub value_data: Option<String>,
    /// 匹配类型
    pub match_type: MatchType,
}

/// 特征库数据结构
#[derive(Debug, Deserialize, Serialize)]
pub struct FeatureDatabase {
    /// 系统关键路径列表
    pub system_critical: Vec<String>,
    /// 高度危险路径列表
    pub high_risk: Vec<String>,
    /// 安全部分路径列表
    pub safe: Vec<String>,
}

/// 注册表检查器主结构体
pub struct RegistryChecker {
    /// 特征数据库
    pub features: FeatureDatabase,
}

impl RegistryChecker {
    /// 从YAML文件加载特征库
    pub fn load_from_file(file_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        // 记录开始加载特征库
        log_loading_start(file_path);

        match fs::read_to_string(file_path) {
            Ok(content) => Self::create_from_yaml(&content),
            Err(e) => {
                // 记录加载失败，使用默认特征库
                log_loading_failure(e);
                Ok(Self::create_default())
            }
        }
    }

    /// 创建默认特征库（当文件加载失败时使用）
    pub fn create_default() -> Self {
        // 记录默认特征库创建
        log_default_creation();

        Self {
            features: FeatureDatabase {
                system_critical: create_system_critical_patterns(),
                high_risk: create_high_risk_patterns(),
                safe: create_safe_patterns(),
            },
        }
    }

    /// 评估注册表路径的重要等级
    pub fn assess_registry_path(&self, path: &str) -> RegistryImportance {
        let path_upper = path.to_uppercase();

        // 按优先级检查：系统关键 -> 高度危险 -> 安全部分
        if self.is_system_critical(&path_upper) {
            log_assessment_result(path, "系统关键");
            return RegistryImportance::SystemCritical;
        }

        if self.is_high_risk(&path_upper) {
            log_assessment_result(path, "高度危险");
            return RegistryImportance::HighRisk;
        }

        if self.is_safe(&path_upper) {
            log_assessment_result(path, "安全部分");
            return RegistryImportance::Safe;
        }

        // 不在任何特征库中，标记为未知（比安全部分等级更高）
        log_assessment_result(path, "未知区域");
        RegistryImportance::Unknown
    }

    /// 获取操作建议
    pub fn get_operation_advice(&self, importance: RegistryImportance) -> &'static str {
        match importance {
            RegistryImportance::SystemCritical => "绝对不能删除：Windows内核和核心组件",
            RegistryImportance::HighRisk => "建议删除：可能包含恶意软件或系统威胁",
            RegistryImportance::Unknown => "需要人工审核：不在特征库中的未知区域",
            RegistryImportance::Safe => "可以删除：用户应用程序和自定义设置",
        }
    }

    /// 批量评估搜索结果
    pub fn assess_search_results(
        &self,
        results: &[SearchResult],
    ) -> Vec<(SearchResult, RegistryImportance)> {
        // 记录批量评估开始
        log_batch_assessment_start(results.len());

        let assessed = results
            .iter()
            .map(|result| {
                let importance = self.assess_registry_path(&result.key_path);
                (result.clone(), importance)
            })
            .collect();

        // 记录批量评估完成
        log_batch_assessment_complete();
        assessed
    }

    /// 获取特征库摘要信息
    pub fn get_features_summary(&self) -> String {
        format!(
            "特征库统计：系统关键({}) 高度危险({}) 安全部分({})",
            self.features.system_critical.len(),
            self.features.high_risk.len(),
            self.features.safe.len()
        )
    }

    /// 从YAML内容创建检查器
    fn create_from_yaml(yaml_content: &str) -> Result<Self, Box<dyn std::error::Error>> {
        // 记录YAML加载成功
        log_yaml_loading_success(yaml_content);

        // 使用 serde_yaml 解析 YAML
        let features: FeatureDatabase = serde_yaml::from_str(yaml_content)?;

        // 记录YAML解析成功
        log_yaml_parsing_success();

        // 记录特征提取完成
        log_feature_extraction_complete(&features);

        Ok(Self { features })
    }

    /// 检查是否为系统关键路径
    fn is_system_critical(&self, path_upper: &str) -> bool {
        self.features
            .system_critical
            .iter()
            .any(|pattern| Self::path_matches_pattern(path_upper, pattern))
    }

    /// 检查是否为高度危险路径
    fn is_high_risk(&self, path_upper: &str) -> bool {
        self.features
            .high_risk
            .iter()
            .any(|pattern| Self::path_matches_pattern(path_upper, pattern))
    }

    /// 检查是否为安全部分路径
    fn is_safe(&self, path_upper: &str) -> bool {
        self.features
            .safe
            .iter()
            .any(|pattern| Self::path_matches_pattern(path_upper, pattern))
    }

    /// 检查路径是否匹配模式
    fn path_matches_pattern(path: &str, pattern: &str) -> bool {
        let pattern_upper = pattern.to_uppercase();

        // 处理以反斜杠结尾的模式（目录匹配）
        if pattern.ends_with('\\') {
            return Self::match_directory_pattern(path, &pattern_upper);
        }

        // 普通包含匹配
        path.contains(&pattern_upper)
    }

    /// 匹配目录模式
    fn match_directory_pattern(path: &str, pattern: &str) -> bool {
        // 检查路径是否以模式开头
        if path.starts_with(pattern) {
            return true;
        }

        // 检查路径是否包含模式作为目录
        let dir_pattern = pattern.trim_end_matches('\\');
        path.contains(&format!("{}\\", dir_pattern))
    }
}

/// 创建系统关键模式列表
fn create_system_critical_patterns() -> Vec<String> {
    vec![
        "HKEY_LOCAL_MACHINE\\SYSTEM".to_string(),
        "HKEY_LOCAL_MACHINE\\HARDWARE".to_string(),
        "HKEY_LOCAL_MACHINE\\SAM".to_string(),
        "HKEY_LOCAL_MACHINE\\SECURITY".to_string(),
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion".to_string(),
        "HKEY_CLASSES_ROOT\\CLSID".to_string(),
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths".to_string(),
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall".to_string(),
    ]
}

/// 创建高度危险模式列表
fn create_high_risk_patterns() -> Vec<String> {
    vec![
        "Run\\".to_string(),
        "RunOnce\\".to_string(),
        "RunServices".to_string(),
        "Policies\\Explorer\\Run".to_string(),
        "Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
        "\\Shell\\Open\\Command".to_string(),
        "\\command\\".to_string(),
        "\\ShellEx\\".to_string(),
        "Browser Helper Objects".to_string(),
        "Winlogon\\".to_string(),
    ]
}

/// 创建安全部分模式列表
fn create_safe_patterns() -> Vec<String> {
    vec![
        "Software\\".to_string(),
        "Control Panel".to_string(),
        "AppEvents".to_string(),
        "Keyboard Layout".to_string(),
        "Microsoft\\Windows\\CurrentVersion\\Explorer".to_string(),
        "Microsoft\\Windows\\CurrentVersion\\Internet Settings".to_string(),
        "Microsoft\\Office".to_string(),
        "Policies\\Microsoft".to_string(),
    ]
}

/// 记录开始加载特征库
fn log_loading_start(file_path: &str) {
    println!("正在加载特征库文件: {}", file_path);
}

/// 记录YAML加载成功
fn log_yaml_loading_success(yaml_content: &str) {
    println!(
        "YAML文件读取成功,大小: {} 字节",
        yaml_content.len()
    );
}

/// 记录加载失败
fn log_loading_failure(error: std::io::Error) {
    println!("文件加载失败: {}，使用默认特征库", error);
}

/// 记录YAML解析成功
fn log_yaml_parsing_success() {
    println!("YAML解析成功");
}

/// 记录特征提取完成
fn log_feature_extraction_complete(features: &FeatureDatabase) {
    println!("特征库加载完成:");
    println!("系统关键路径: {} 个", features.system_critical.len());
    println!("高度危险路径: {} 个", features.high_risk.len());
    println!("安全部分路径: {} 个", features.safe.len());
}

/// 记录默认特征库创建
fn log_default_creation() {
    println!("创建默认特征库");
}

/// 记录评估结果
fn log_assessment_result(path: &str, result: &str) {
    println!("{} -> {}", path, result);
}

/// 记录批量评估开始
fn log_batch_assessment_start(count: usize) {
    println!("开始批量评估 {} 个搜索结果", count);
}

/// 记录批量评估完成
fn log_batch_assessment_complete() {
    println!("批量评估完成");
}
