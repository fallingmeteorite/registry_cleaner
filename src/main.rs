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

// ============================================================
// 权限检查
// ============================================================

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

// ============================================================
// 输入辅助
// ============================================================

/// 读取用户输入（带提示）。
/// `read_line` 失败（EOF / 管道关闭 / IO 错误）时返回空串，而不是 panic。
fn read_input(prompt: &str) -> String {
    print!("{}", prompt);
    let _ = io::stdout().flush();
    let stdin = io::stdin();
    let mut line = String::new();
    if stdin.lock().read_line(&mut line).is_err() {
        return String::new();
    }
    line.trim().to_string()
}

/// 读取用户确认（Y/N）。EOF 时返回 default，避免死循环。
fn confirm(prompt: &str, default: bool) -> bool {
    let default_str = if default { "Y/n" } else { "y/N" };
    loop {
        let input = read_input(&format!("  ❓ {} [{}]: ", prompt, default_str));
        let input = input.to_lowercase();

        if input.is_empty() {
            return default;
        }
        match input.as_str() {
            "y" | "yes" => return true,
            "n" | "no" => return false,
            _ => println!("  ⚠️  请输入 Y 或 N"),
        }
    }
}

/// 读取非空字符串输入。
/// 连续两次读到空（视为 EOF / stdin 关闭）时返回空串，由调用方决定退出。
fn read_non_empty_input(prompt: &str) -> String {
    let mut eof_guard = 0u32;
    loop {
        let input = read_input(prompt);
        if input.trim().is_empty() {
            eof_guard += 1;
            if eof_guard >= 2 {
                return String::new();
            }
            println!("  ⚠️  输入不能为空，请重新输入!");
        } else {
            return input;
        }
    }
}

// ============================================================
// 主程序
// ============================================================

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ---------- 权限检查 ----------
    if !is_running_as_admin() {
        println!();
        println!("  ⚠️  权限不足");
        println!("  ─────────────────────────────────────────────");
        println!("  注册表操作需要管理员权限。");
        println!("  请以管理员身份重新运行此程序。");
        println!();
        press_any_key_to_continue();
        return Ok(());
    }

    // ---------- 标题 ----------
    show_title();

    // ---------- 步骤 1: 获取搜索关键字 ----------
    println!();
    let keyword = read_non_empty_input("  🔎 请输入搜索关键字（不分大小写）: ");
    let keyword = keyword.trim();
    if keyword.is_empty() {
        println!();
        println!("  ℹ️  未输入关键字，程序退出。");
        press_any_key_to_continue();
        return Ok(());
    }

    // ---------- 步骤 2: 搜索注册表 ----------
    println!();
    println!("  🔍 正在搜索符合要求的项目 '{}' …", keyword);
    let searcher = RegistrySearcher::new();
    let results = searcher.search_all(keyword)?;

    if results.is_empty() {
        println!();
        println!("  ℹ️  未找到任何匹配项");
        press_any_key_to_continue();
        return Ok(());
    }

    println!();
    println!("  ✅ 一共找到 {} 个匹配项", results.len());

    // ---------- 步骤 3: 显示详细结果 ----------
    if confirm("是否查看详细查找结果?", true) {
        display_detailed_results(&results);
    }

    // ---------- 步骤 4: 删除操作 ----------
    // 删除前统计"不同的注册表键数量"，用于提示用户避免误删。
    let unique_path_count = {
        let mut v: Vec<&str> = results.iter().map(|r| r.key_path.as_str()).collect();
        v.sort_unstable();
        v.dedup();
        v.len()
    };
    println!();
    println!(
        "  ⚠️  本次将影响 {} 个不同的注册表键（共 {} 条匹配）",
        unique_path_count,
        results.len()
    );

    if confirm(&format!("是否开始删除这 {} 个项目?", results.len()), false) {
        let deleter = RegistryDeleter::new();

        // 按 (key_path, value_name) 排序：相邻项共享父路径，
        // 若删除器内部有父键句柄缓存即可命中，减少重复打开。
        let mut delete_items: Vec<(&str, Option<&str>)> = results
            .iter()
            .map(|r| (r.key_path.as_str(), r.value_name.as_deref()))
            .collect();
        delete_items.sort_unstable_by(|a, b| a.0.cmp(b.0).then_with(|| a.1.cmp(&b.1)));

        let delete_results = deleter.batch_delete(&delete_items);
        display_delete_summary(&delete_results);
    }

    press_any_key_to_continue();
    Ok(())
}

// ============================================================
// 显示
// ============================================================

/// 显示程序标题
fn show_title() {
    println!();
    println!("  ─────────────────────────────────────────────────────");
    println!("              简易注册表清理工具");
    println!("              v2026-7-12");
    println!("  ─────────────────────────────────────────────────────");
    println!();
}

/// 显示详细结果
fn display_detailed_results(results: &[SearchResult]) {
    if results.is_empty() {
        return;
    }

    println!();
    println!("  ─────────────────────────────────────────────────────");
    println!("              详细搜索结果（共 {} 项）", results.len());
    println!("  ─────────────────────────────────────────────────────");

    for (i, r) in results.iter().enumerate() {
        println!();
        println!(
            "  ── 项目 [{}/{}] ──────────────────────────────",
            i + 1,
            results.len()
        );
        println!("     路径      : {}", r.key_path);

        if let Some(name) = &r.value_name {
            println!("     值名      : {}", name);
        }

        if let Some(data) = &r.value_data {
            println!("     数据      : {}", data);
        }

        println!("     匹配类型  : {}", r.match_type);
    }

    println!();
}

/// 显示删除摘要
fn display_delete_summary(results: &[DeleteResult]) {
    let success = results.iter().filter(|r| r.success).count();
    let failed = results.len() - success;
    let rate = if results.is_empty() {
        0.0
    } else {
        (success as f32 / results.len() as f32) * 100.0
    };

    println!();
    println!("  ─────────────────────────────────────────────────────");
    println!("              删除操作完成");
    println!("  ─────────────────────────────────────────────────────");
    println!("     成功      : {}", success);
    println!("     失败      : {}", failed);
    println!("     成功率    : {:.1}%", rate);
    println!("  ─────────────────────────────────────────────────────");
    println!();
}

/// 等待用户按键
fn press_any_key_to_continue() {
    println!();
    print!("  按任意键退出…");
    let _ = io::stdout().flush();
    let _ = io::stdin().read_line(&mut String::new());
}
