//! 注册表清理工具主程序

mod registry_delete;
mod registry_search;

use crate::registry_delete::{DeleteResult, RegistryDeleter};
use crate::registry_search::{RegistrySearcher, SearchResult};
use std::io::{self, BufRead, Write};

#[cfg(windows)]
use winapi::um::securitybaseapi::{AllocateAndInitializeSid, CheckTokenMembership, FreeSid};
#[cfg(windows)]
use winapi::um::winnt::{
    DOMAIN_ALIAS_RID_ADMINS, PSID, SECURITY_BUILTIN_DOMAIN_RID, SID_IDENTIFIER_AUTHORITY,
};

/// 检查是否以管理员权限运行（Windows）
#[cfg(windows)]
fn is_running_as_admin() -> bool {
    unsafe {
        let mut sia = SID_IDENTIFIER_AUTHORITY {
            Value: [0, 0, 0, 0, 0, 5],
        };
        let mut administrators_sid: PSID = std::ptr::null_mut();
        let mut is_member = 0;

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
            &mut administrators_sid,
        ) == 0
        {
            return false;
        }

        let result = CheckTokenMembership(std::ptr::null_mut(), administrators_sid, &mut is_member);
        FreeSid(administrators_sid);

        result != 0 && is_member != 0
    }
}

/// 非 Windows 平台默认返回 false
#[cfg(not(windows))]
fn is_running_as_admin() -> bool {
    false
}

/// 读取用户输入（带提示）
fn read_input(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    let stdin = io::stdin();
    let mut line = String::new();
    stdin.lock().read_line(&mut line).unwrap();
    line.trim().to_string()
}

/// 读取用户确认（Y/N）
fn confirm(prompt: &str, default: bool) -> bool {
    let default_str = if default { "Y/n" } else { "y/N" };
    loop {
        let input = read_input(&format!("{} [{}]: ", prompt, default_str));
        let input = input.to_lowercase();

        if input.is_empty() {
            return default;
        }
        match input.as_str() {
            "y" | "yes" => return true,
            "n" | "no" => return false,
            _ => println!("请输入 Y 或 N"),
        }
    }
}

/// 读取非空字符串输入
fn read_non_empty_input(prompt: &str) -> String {
    loop {
        let input = read_input(prompt);
        if input.trim().is_empty() {
            println!("输入不能为空,请重新输入!");
        } else {
            return input;
        }
    }
}

/// 主程序
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 检查管理员权限
    if !is_running_as_admin() {
        println!();
        println!(" ⚠️ 警告:权限不足!");
        println!("注册表操作需要管理员权限.");
        println!("请以管理员身份重新运行此程序.");
        println!();
        press_any_key_to_continue();
        return Ok(());
    }

    // 显示标题
    show_title();

    // 步骤1: 获取搜索关键字
    println!();
    let keyword = read_non_empty_input("请输入搜索关键字(不分大小写):");
    let keyword = keyword.trim();

    // 步骤2: 搜索注册表
    println!("\n正在搜索符合要求的项目 '{}'...", keyword);
    let searcher = RegistrySearcher::new();
    let results = searcher.search_all(keyword)?;

    if results.is_empty() {
        println!("未找到任何匹配项");
        press_any_key_to_continue();
        return Ok(());
    }

    println!("一共找到 {} 个匹配项", results.len());

    // 步骤3: 显示详细结果
    if confirm("是否查看详细查找结果?", true) {
        display_detailed_results(&results);
    }

    // 步骤4: 删除操作
    if confirm(&format!("是否开始删除这 {} 个项目?", results.len()), false) {
        let deleter = RegistryDeleter::new();

        // 准备删除项目列表
        let delete_items: Vec<_> = results
            .iter()
            .map(|r| {
                let value_name = r.value_name.as_deref();
                (r.key_path.as_str(), value_name)
            })
            .collect();

        let delete_results = deleter.batch_delete(&delete_items);
        display_delete_summary(&delete_results)
    }

    press_any_key_to_continue();
    Ok(())
}

/// 显示程序标题
fn show_title() {
    println!();
    println!("{}", "=".repeat(60));
    println!("简易注册表清理工具 v2026-7-12");
    println!("{}", "=".repeat(60));
    println!();
}

/// 显示详细结果 - 使用和删除时一样的格式
fn display_detailed_results(results: &[SearchResult]) {
    if results.is_empty() {
        return;
    }

    println!();
    println!("{}", "=".repeat(80));
    println!("详细搜索结果 (共 {} 项)", results.len());
    println!("{}", "=".repeat(80));

    for (i, r) in results.iter().enumerate() {
        println!("\n项目 [{}/{}]", i + 1, results.len());
        println!("{}", "=".repeat(80));
        println!("路径: {}", r.key_path);

        if let Some(name) = &r.value_name {
            println!("值名: {}", name);
        }

        if let Some(data) = &r.value_data {
            let display_data = if data.len() > 100 {
                format!("{}...", &data[..100])
            } else {
                data.clone()
            };
            println!("数据: {}", display_data);
        }

        println!("匹配类型: {}", r.match_type);
        println!("{}", "=".repeat(80));
    }

    println!();
}

/// 显示删除摘要
fn display_delete_summary(results: &[DeleteResult]) {
    let success = results.iter().filter(|r| r.success).count();
    let failed = results.len() - success;

    println!();
    println!("删除操作完成");
    println!("{}", "-".repeat(60));
    println!("  成功: {} 个", success);
    println!("  失败: {} 个", failed);
    if !results.is_empty() {
        println!(
            "  成功率: {:.1}%",
            (success as f32 / results.len() as f32) * 100.0
        );
    }
}

/// 等待用户按键
fn press_any_key_to_continue() {
    println!();
    print!("按任意键退出...");
    io::stdout().flush().unwrap();
    let _ = io::stdin().read_line(&mut String::new());
}
