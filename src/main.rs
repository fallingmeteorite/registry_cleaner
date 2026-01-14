//! fallingmeteorite
// main.rs
mod registry_backup;
mod registry_check;
mod registry_delete;
mod registry_search;

use registry_backup::*;
use registry_check::*;
use registry_delete::*;
use registry_search::*;
use std::io::{self, Write};
use winreg::HKEY;
use winreg::enums::*;

// Windows API相关导入
use std::ptr;
use winapi::um::securitybaseapi::CheckTokenMembership;
use winapi::um::securitybaseapi::FreeSid;
use winapi::um::winnt::{
    DOMAIN_ALIAS_RID_ADMINS, PSID, SECURITY_BUILTIN_DOMAIN_RID, SID_IDENTIFIER_AUTHORITY,
};

// 从 registry_check 模块导入所有需要的类型
use registry_check::{MatchType, RegistryImportance, SearchResult};
// 将 registry_search::SearchResult 转换为当前 crate 的 SearchResult
impl From<registry_search::SearchResult> for SearchResult {
    fn from(result: registry_search::SearchResult) -> Self {
        // 根据字符串匹配类型转换为枚举
        let match_type = match result.match_type.as_str() {
            "项" => MatchType::Item,
            "键" => MatchType::Key,
            "值" => MatchType::Value,
            _ => MatchType::Value, // 默认值
        };

        // 将空字符串转换为 None，非空字符串转换为 Some
        let value_name = if result.value_name.is_empty() {
            None
        } else {
            Some(result.value_name)
        };

        let value_data = if result.value_data.is_empty() {
            None
        } else {
            Some(result.value_data)
        };

        // 构建 SearchResult 结构体
        SearchResult {
            key_path: result.key_path,
            value_name,
            value_data,
            match_type,
        }
    }
}

// 安全评估结果结构体
#[derive(Debug)]
pub struct AssessedResult {
    pub result: SearchResult,
    pub importance: RegistryImportance,
}

// 从元组转换为 AssessedResult
impl From<(SearchResult, RegistryImportance)> for AssessedResult {
    fn from((result, importance): (SearchResult, RegistryImportance)) -> Self {
        AssessedResult { result, importance }
    }
}

/// 注册表根键统计信息
#[derive(Debug)]
pub struct RootStats {
    pub name: String,
    pub total_keys: usize,
}

/// 检查是否以管理员权限运行（Windows系统）
fn is_running_as_admin() -> bool {
    unsafe {
        let mut sia = SID_IDENTIFIER_AUTHORITY {
            Value: [0, 0, 0, 0, 0, 5], // SECURITY_NT_AUTHORITY
        };
        let mut administrators_sid: PSID = ptr::null_mut();
        let mut is_member = 0;

        // 创建Administrators组的SID
        if winapi::um::securitybaseapi::AllocateAndInitializeSid(
            &mut sia,
            2, // 子权限数量
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0,
            0,
            0,
            0,
            0,
            0,
            &mut administrators_sid,
        ) == 0
        {
            return false;
        }

        // 检查当前进程是否是管理员组的成员
        let result = CheckTokenMembership(ptr::null_mut(), administrators_sid, &mut is_member);

        // 释放SID内存
        FreeSid(administrators_sid);

        result != 0 && is_member != 0
    }
}

/// 显示程序标题和版本信息
fn show_program_title() {
    println!("注册表清理工具 v1.0");
    println!();
}

/// 执行注册表备份（直接进行完整备份）
fn perform_registry_backup() -> Result<bool, Box<dyn std::error::Error>> {
    println!("注册表备份");
    println!("{}", "─".repeat(60));

    // 直接进行完整备份
    println!("开始完整备份注册表...");
    let backup = RegistryBackup::new();
    let result = backup.backup_full_registry();

    println!();
    if result.success {
        println!("✓ 备份成功！");
        println!("备份路径: {}", result.backup_path);
        println!("{}", "═".repeat(60));
        Ok(true)
    } else {
        println!("✗ 备份失败！");
        println!("错误信息: {}", result.message);
        print!("是否继续？(y/N): ");
        io::stdout().flush()?;

        let mut continue_answer = String::new();
        io::stdin().read_line(&mut continue_answer)?;

        Ok(continue_answer.trim().to_lowercase() == "y")
    }
}

/// 加载特征库文件
fn load_features_library() -> RegistryChecker {
    println!("加载特征库");
    println!("{}", "─".repeat(60));

    match RegistryChecker::load_from_file("features.yaml") {
        Ok(checker) => {
            println!("特征库加载成功");
            println!("{}", checker.get_features_summary());
            checker
        }
        Err(e) => {
            // 如果文件加载失败，使用默认特征库
            println!("无法加载特征库文件: {}", e);
            println!("使用内置默认特征库...");
            let default_checker = RegistryChecker::create_default();
            println!("{}", default_checker.get_features_summary());
            default_checker
        }
    }
}

/// 获取用户输入的搜索关键字
fn get_search_keyword() -> Result<String, Box<dyn std::error::Error>> {
    println!("输入搜索参数");
    println!("{}", "─".repeat(60));

    print!("请输入搜索关键字: ");
    io::stdout().flush()?;

    let mut keyword = String::new();
    io::stdin().read_line(&mut keyword)?;
    let keyword = keyword.trim();

    if keyword.is_empty() {
        println!("关键字不能为空！");
        return Err("关键字为空".into());
    }

    println!("搜索关键字: '{}'", keyword);
    println!("{}", "─".repeat(60));
    println!();

    Ok(keyword.to_string())
}

/// 在整个注册表中搜索关键字
fn search_in_registry(keyword: &str) -> Vec<registry_search::SearchResult> {
    println!("搜索注册表");
    println!("{}", "─".repeat(60));
    println!("开始搜索 '{}'...", keyword);

    let roots = get_registry_roots();
    let mut all_results = Vec::new();

    // 统计注册表大小
    println!("正在统计注册表大小...");
    println!();

    let root_stats_list = collect_root_statistics(&roots);

    println!();
    println!("{}", "═".repeat(60));
    println!();

    // 在每个根键中搜索
    for (root_index, (root_key, root_name)) in roots.iter().enumerate() {
        let root_stats = &root_stats_list[root_index];

        println!("搜索 |{}| 共 |{}| 个键", root_name, root_stats.total_keys);

        match search_registry(
            *root_key,
            root_name,
            keyword,
            root_stats.total_keys,
            Some(&mut |processed: usize, total: usize, found: usize| {
                display_progress_bar(processed, total, found, root_name);
            }),
        ) {
            Ok(results) => {
                if !results.is_empty() {
                    println!("\n找到 {} 个匹配项", results.len());
                    all_results.extend(results);
                } else {
                    println!("\n未找到匹配项");
                }
            }
            Err(e) => println!("\n无法访问 {}: {}", root_name, e),
        }

        if root_index < roots.len() - 1 {
            println!();
        }
    }

    all_results
}

/// 收集注册表根键的统计信息
fn collect_root_statistics(roots: &[(HKEY, &'static str)]) -> Vec<RootStats> {
    let mut stats = Vec::new();

    for (root_key, root_name) in roots {
        match count_keys(*root_key) {
            Ok(total_keys) => {
                stats.push(RootStats {
                    name: root_name.to_string(),
                    total_keys,
                });
                println!("{}: {:>12} 个键", root_name, total_keys);
            }
            Err(e) => println!("无法访问 {}: {}", root_name, e),
        }
    }

    stats
}

/// 显示未找到结果的提示信息
fn show_no_results_message() {
    println!();
    println!("{}", "═".repeat(60));
    println!("未找到任何匹配项");
    println!("{}", "─".repeat(60));
    println!("程序结束");
}

/// 对搜索结果进行安全检查
fn perform_safety_check(
    all_results: &[registry_search::SearchResult],
    checker: &RegistryChecker,
) -> Vec<(SearchResult, RegistryImportance)> {
    println!("安全检查");
    println!("{}", "─".repeat(60));
    println!("正在进行安全检查...");

    // 转换结果类型
    let converted_results: Vec<SearchResult> = all_results
        .iter()
        .map(|result| result.clone().into())
        .collect();

    // 评估结果
    let assessed_results = checker.assess_search_results(&converted_results);

    // 统计各风险等级数量
    let (system_critical, high_risk, unknown, safe) = count_risk_levels(&assessed_results);

    // 显示统计结果
    show_safety_check_summary(
        system_critical,
        high_risk,
        unknown,
        safe,
        assessed_results.len(),
    );

    assessed_results
}

/// 统计风险等级数量
fn count_risk_levels(
    results: &[(SearchResult, RegistryImportance)],
) -> (usize, usize, usize, usize) {
    let mut system_critical = 0;
    let mut high_risk = 0;
    let mut unknown = 0;
    let mut safe = 0;

    for (_, importance) in results {
        match importance {
            RegistryImportance::SystemCritical => system_critical += 1,
            RegistryImportance::HighRisk => high_risk += 1,
            RegistryImportance::Unknown => unknown += 1,
            RegistryImportance::Safe => safe += 1,
        }
    }

    (system_critical, high_risk, unknown, safe)
}

/// 显示安全检查摘要
fn show_safety_check_summary(
    system_critical: usize,
    high_risk: usize,
    unknown: usize,
    safe: usize,
    total: usize,
) {
    println!("安全检查完成:");
    println!("{}", "─".repeat(60));
    println!("系统关键: {} 个", system_critical);
    println!("高度危险: {} 个", high_risk);
    println!("未知区域: {} 个", unknown);
    println!("安全部分: {} 个", safe);
    println!("{}", "─".repeat(60));
    println!("总计: {} 个匹配项", total);
    println!();
}

/// 显示详细的搜索结果
fn show_detailed_results(
    assessed_results: &[(SearchResult, RegistryImportance)],
    checker: &RegistryChecker,
) {
    println!("显示详细结果");
    println!("{}", "─".repeat(60));
    println!("详细结果和安全评估:");
    println!("{}", "═".repeat(80));

    for (i, (result, importance)) in assessed_results.iter().enumerate() {
        display_single_result(i, result, importance, checker, assessed_results.len());

        if i < assessed_results.len() - 1 {
            println!();
        }
    }
}

/// 显示单个结果
fn display_single_result(
    index: usize,
    result: &SearchResult,
    importance: &RegistryImportance,
    checker: &RegistryChecker,
    total: usize,
) {
    // 确定状态颜色标识
    let status_color = match importance {
        RegistryImportance::SystemCritical => "[系统关键]",
        RegistryImportance::HighRisk => "[高度危险]",
        RegistryImportance::Unknown => "[未知区域]",
        RegistryImportance::Safe => "[安全部分]",
    };

    println!("结果 {}/{} {}", index + 1, total, status_color);
    println!("{}", "─".repeat(80));

    // 显示基本信息
    println!("路径: {}", result.key_path);

    if let Some(ref value_name) = result.value_name {
        if !value_name.is_empty() {
            println!("值名: {}", value_name);
        }
    }

    println!("匹配类型: {:?}", result.match_type);
    println!("重要等级: {}", importance);
    println!("操作建议: {}", checker.get_operation_advice(*importance));

    // 显示值数据（截断显示）
    if let Some(ref value_data) = result.value_data {
        if !value_data.is_empty() {
            let display_data = if value_data.len() > 100 {
                format!("{}...", &value_data[..100])
            } else {
                value_data.clone()
            };
            println!("数据: {}", display_data);
        }
    }

    println!("{}", "─".repeat(80));
}

/// 处理删除操作
fn handle_deletion_process(
    assessed_results: &[(SearchResult, RegistryImportance)],
) -> Result<(), Box<dyn std::error::Error>> {
    // 统计可删除项目
    let (deletable_count, system_critical_count) = count_deletable_items(assessed_results);

    println!();
    println!("删除确认");
    println!("{}", "─".repeat(60));

    // 如果有可删除项目，询问用户
    if deletable_count > 0 {
        show_deletion_summary(deletable_count, system_critical_count);

        if ask_user_for_deletion()? {
            perform_deletion_operation(assessed_results)?;
        } else {
            println!("取消删除操作。");
        }
    } else {
        println!("没有可以安全删除的项目。");
    }

    Ok(())
}

/// 统计可删除和不可删除的项目
fn count_deletable_items(
    assessed_results: &[(SearchResult, RegistryImportance)],
) -> (usize, usize) {
    let mut deletable = 0;
    let mut system_critical = 0;

    for (_, importance) in assessed_results {
        match importance {
            RegistryImportance::SystemCritical => system_critical += 1,
            RegistryImportance::HighRisk => deletable += 1,
            RegistryImportance::Unknown => deletable += 1,
            RegistryImportance::Safe => deletable += 1,
        }
    }

    (deletable, system_critical)
}

/// 显示删除摘要
fn show_deletion_summary(deletable: usize, system_critical: usize) {
    println!("可以删除的项目: {} 个", deletable);
    println!("不可删除的项目: {} 个", system_critical);
    println!();
}

/// 询问用户是否删除
fn ask_user_for_deletion() -> Result<bool, Box<dyn std::error::Error>> {
    print!("是否删除所有可删除的项目？(y/N): ");
    io::stdout().flush()?;

    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;

    let answer = answer.trim().to_lowercase();
    Ok(answer == "y" || answer == "yes")
}

/// 执行删除操作
fn perform_deletion_operation(
    assessed_results: &[(SearchResult, RegistryImportance)],
) -> Result<(), Box<dyn std::error::Error>> {
    println!();
    println!("执行删除操作");
    println!("{}", "─".repeat(60));
    println!("开始删除操作...");

    // 收集需要删除的项目
    let items_to_delete = collect_items_for_deletion(assessed_results);

    // 执行批量删除
    let deleter = RegistryDeleter::new();
    let delete_results = deleter.batch_delete(&items_to_delete);

    // 显示删除结果
    display_delete_summary(&delete_results);

    // 询问是否查看详细结果
    if ask_user_for_details()? {
        display_detailed_delete_results(&delete_results);
    }

    Ok(())
}

/// 收集需要删除的项目
fn collect_items_for_deletion(
    assessed_results: &[(SearchResult, RegistryImportance)],
) -> Vec<(&str, Option<&str>, RegistryImportance)> {
    let mut items = Vec::new();

    for (result, importance) in assessed_results {
        // 只收集非系统关键的项目
        if *importance != RegistryImportance::SystemCritical {
            let value_name = result.value_name.as_deref();
            items.push((result.key_path.as_str(), value_name, *importance));
        }
    }

    items
}

/// 询问用户是否查看详细删除结果
fn ask_user_for_details() -> Result<bool, Box<dyn std::error::Error>> {
    println!();
    print!("是否查看详细删除结果? (y/N): ");
    io::stdout().flush()?;

    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;

    let answer = answer.trim().to_lowercase();
    Ok(answer == "y" || answer == "yes")
}

/// 显示删除操作摘要
fn display_delete_summary(results: &[DeleteResult]) {
    let success_count = results.iter().filter(|r| r.success).count();
    let fail_count = results.len() - success_count;
    let success_rate = if !results.is_empty() {
        (success_count as f32 / results.len() as f32) * 100.0
    } else {
        0.0
    };

    println!();
    println!("{}", "═".repeat(60));
    println!("删除操作摘要:");
    println!("{}", "─".repeat(60));
    println!("总项目数: {}", results.len());
    println!("成功删除: {}", success_count);
    println!("删除失败: {}", fail_count);
    println!("成功率: {:.1}%", success_rate);
    println!("{}", "─".repeat(60));
}

/// 显示详细的删除结果
fn display_detailed_delete_results(results: &[DeleteResult]) {
    println!();
    println!("{}", "═".repeat(80));
    println!("详细删除结果:");
    println!("{}", "═".repeat(80));

    for (i, result) in results.iter().enumerate() {
        let status = if result.success {
            "[成功]"
        } else {
            "[失败]"
        };

        println!("{}/{} {}", i + 1, results.len(), status);
        println!("{}", "─".repeat(80));
        println!("路径: {}", result.key_path);

        if let Some(value_name) = &result.value_name {
            println!("值名: {}", value_name);
        }

        println!("状态: {}", result.message);
        println!("{}", "─".repeat(80));

        if i < results.len() - 1 {
            println!();
        }
    }
}

/// 显示程序完成信息
fn show_program_completion() {
    println!();
    println!("{}", "═".repeat(60));
    println!("程序执行完成！");
    println!("{}", "═".repeat(60));

    // 等待用户按键退出
    println!();
    print!("按任意键退出...");
    io::stdout().flush().unwrap();
    let _ = io::stdin().read_line(&mut String::new());
}

/// 显示进度条
fn display_progress_bar(processed: usize, total: usize, found: usize, root_name: &str) {
    // 使用终端转义序列清除整行（如果终端支持）
    if cfg!(windows) {
        // Windows 简单方法
        let bar_length = 30;
        let filled_length = if total > 0 {
            (processed * bar_length) / total
        } else {
            0
        };

        let percent = if total > 0 {
            (processed as f64 * 100.0) / total as f64
        } else {
            0.0
        };

        let progress_bar = format!(
            "{}{}",
            "█".repeat(filled_length),
            "░".repeat(bar_length - filled_length)
        );

        // 使用固定格式确保长度一致
        let line = format!(
            "\r{} | {:5.1}% | {} | 已处理: {}/{} | 找到: {}",
            progress_bar, percent, root_name, processed, total, found
        );

        print!("{}", line);
    } else {
        // Unix/Linux 可以使用更复杂的转义序列
        print!("\x1B[2K\r"); // 清除整行
        // ... 然后输出进度条
    }

    io::stdout().flush().unwrap();
}

/// 获取注册表根键列表
fn get_registry_roots() -> Vec<(HKEY, &'static str)> {
    vec![
        (HKEY_CLASSES_ROOT, "HKEY_CLASSES_ROOT"),
        (HKEY_CURRENT_USER, "HKEY_CURRENT_USER"),
        (HKEY_LOCAL_MACHINE, "HKEY_LOCAL_MACHINE"),
        (HKEY_USERS, "HKEY_USERS"),
        (HKEY_CURRENT_CONFIG, "HKEY_CURRENT_CONFIG"),
    ]
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 检查是否以管理员权限运行
    if !is_running_as_admin() {
        println!("{}", "═".repeat(60));
        println!("警告：权限不足！");
        println!("{}", "─".repeat(60));
        println!("注册表操作需要管理员权限。");
        println!("请以管理员身份重新运行此程序。");
        println!("{}", "═".repeat(60));

        // 等待用户按键
        println!();
        print!("按任意键退出...");
        io::stdout().flush()?;
        let _ = io::stdin().read_line(&mut String::new());

        return Ok(());
    }

    // 显示程序标题
    show_program_title();

    // 步骤1: 询问是否备份
    println!("{}", "═".repeat(60));
    println!("注册表清理工具 v1.1");
    println!("{}", "═".repeat(60));

    print!("是否在执行清理前备份注册表？(Y/n): ");
    io::stdout().flush()?;

    let mut backup_choice = String::new();
    io::stdin().read_line(&mut backup_choice)?;
    let backup_choice = backup_choice.trim().to_lowercase();

    // 默认为是，除非用户明确输入n或no
    let should_backup = backup_choice.is_empty() || backup_choice == "y" || backup_choice == "yes";

    if should_backup {
        println!();
        println!("{}", "═".repeat(60));
        println!("步骤 1: 注册表备份");
        println!("{}", "═".repeat(60));

        let backup_successful = perform_registry_backup()?;
        if !backup_successful {
            print!("是否继续执行搜索和清理？(y/N): ");
            io::stdout().flush()?;

            let mut continue_choice = String::new();
            io::stdin().read_line(&mut continue_choice)?;
            let continue_choice = continue_choice.trim().to_lowercase();

            if continue_choice != "y" && continue_choice != "yes" {
                println!("程序已终止。");
                show_program_completion();
                return Ok(());
            }
        }
    } else {
        println!("跳过备份步骤。");
    }

    println!();
    println!("{}", "═".repeat(60));
    println!("步骤 2: 特征库加载");
    println!("{}", "═".repeat(60));

    // 步骤2: 加载特征库
    let checker = load_features_library();

    // 步骤3: 获取用户输入的关键字
    let keyword = get_search_keyword()?;

    // 步骤4: 在注册表中搜索关键字
    let all_results = search_in_registry(&keyword);

    // 如果没有找到结果，提前结束
    if all_results.is_empty() {
        show_no_results_message();
        return Ok(());
    }

    // 步骤5: 进行安全检查
    let assessed_results = perform_safety_check(&all_results, &checker);

    // 步骤6: 显示详细结果
    show_detailed_results(&assessed_results, &checker);

    // 步骤7: 询问是否进行删除操作
    if !assessed_results.is_empty() {
        println!();
        println!("{}", "═".repeat(60));
        println!("步骤 7: 删除操作");
        println!("{}", "═".repeat(60));

        print!("是否要对搜索结果进行处理？(Y/n): ");
        io::stdout().flush()?;

        let mut process_choice = String::new();
        io::stdin().read_line(&mut process_choice)?;
        let process_choice = process_choice.trim().to_lowercase();

        // 默认为是，除非用户明确输入n或no
        let should_process =
            process_choice.is_empty() || process_choice == "y" || process_choice == "yes";

        if should_process {
            handle_deletion_process(&assessed_results)?;
        } else {
            println!("跳过删除操作。");
        }
    }

    // 程序结束
    show_program_completion();

    Ok(())
}