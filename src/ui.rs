//! 注册表清理工具 - 渲染层
//!
//! 所有 egui 相关代码集中于此：调色板、字体、样式、`eframe::App` 实现、
//! 各个面板/弹窗/列表的绘制。
//!
//! 该模块对外只暴露：
//!   - `setup_fonts` / `setup_style`（由 main 在启动时调用）
//!   - `render(app, ctx)`（由 `eframe::App::update` 调用）

use crate::app::{fmt_elapsed, AppMode, CleanerApp};
use crate::registry_delete::DeleteResult;
use crate::registry_search::MatchType;

use eframe::egui;
use egui::{Color32, Frame, Margin, RichText, Rounding, ScrollArea, Stroke, Ui};

use std::time::{Duration, Instant};

// ---------------- 颜色常量（浅色主题） ----------------

mod pal {
    use egui::Color32;

    pub const BG_DEEP: Color32 = Color32::from_rgb(245, 246, 248);
    pub const BG_PANEL: Color32 = Color32::from_rgb(250, 250, 252);
    pub const BG_CARD: Color32 = Color32::from_rgb(255, 255, 255);
    pub const BG_CARD_SEL: Color32 = Color32::from_rgb(232, 241, 252);
    pub const BG_CARD_FOCUS: Color32 = Color32::from_rgb(215, 231, 251);
    pub const BG_WIDGET: Color32 = Color32::from_rgb(240, 241, 244);
    pub const BG_HOVER: Color32 = Color32::from_rgb(226, 230, 236);
    pub const BG_ACTIVE: Color32 = Color32::from_rgb(210, 215, 222);

    pub const BORDER_DIM: Color32 = Color32::from_rgb(221, 224, 229);
    pub const BORDER_SEL: Color32 = Color32::from_rgb(120, 170, 230);
    pub const BORDER_FOCUS: Color32 = Color32::from_rgb(60, 130, 220);

    pub const ACCENT: Color32 = Color32::from_rgb(50, 130, 220);
    pub const ON_ACCENT: Color32 = Color32::from_rgb(255, 255, 255);

    pub const TEXT: Color32 = Color32::from_rgb(50, 55, 65);
    pub const TEXT_DIM: Color32 = Color32::from_rgb(110, 118, 132);
    pub const TEXT_FAINT: Color32 = Color32::from_rgb(160, 168, 180);
    pub const TEXT_BRIGHT: Color32 = Color32::from_rgb(18, 22, 30);

    pub const GREEN: Color32 = Color32::from_rgb(30, 150, 70);
    pub const GREEN_DIM: Color32 = Color32::from_rgb(219, 245, 226);
    pub const RED: Color32 = Color32::from_rgb(200, 50, 60);
    pub const RED_DIM: Color32 = Color32::from_rgb(255, 228, 230);
    pub const RED_BTN: Color32 = Color32::from_rgb(200, 55, 60);
    pub const YELLOW: Color32 = Color32::from_rgb(170, 120, 0);
    pub const YELLOW_DARK: Color32 = Color32::from_rgb(255, 246, 216);
    pub const PURPLE: Color32 = Color32::from_rgb(130, 70, 200);
    pub const PURPLE_DARK: Color32 = Color32::from_rgb(240, 231, 255);
    pub const GREEN_DARK: Color32 = Color32::from_rgb(219, 245, 226);
}

// ---------------- eframe::App 桥接 ----------------

impl eframe::App for CleanerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        render(self, ctx);
    }
}

// ---------------- 渲染入口 ----------------

pub(crate) fn render(app: &mut CleanerApp, ctx: &egui::Context) {
    app.poll_background();

    render_top(app, ctx);
    render_bottom(app, ctx);
    render_central(app, ctx);
    render_confirm_dialog(app, ctx);
    render_info_dialog(app, ctx);
    render_toast(app, ctx);

    if matches!(app.mode, AppMode::Searching | AppMode::Deleting) {
        ctx.request_repaint_after(Duration::from_millis(80));
    }
}

// ---------------- 顶部面板 ----------------

fn render_top(app: &mut CleanerApp, ctx: &egui::Context) {
    egui::TopBottomPanel::top("top")
        .frame(
            Frame::none()
                .fill(pal::BG_DEEP)
                .stroke(Stroke::new(1.0_f32, pal::BORDER_DIM))
                .inner_margin(Margin::symmetric(16.0, 12.0)),
        )
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("▍").size(22.0).color(pal::ACCENT));
                ui.label(
                    RichText::new("注册表清理工具")
                        .size(19.0)
                        .strong()
                        .color(pal::TEXT_BRIGHT),
                );
                ui.add_space(6.0);
                ui.label(RichText::new("v2026-7-12").size(11.0).color(pal::TEXT_FAINT));

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let (bg, fg, txt) = if app.whitelist_loaded {
                        (pal::GREEN_DIM, pal::GREEN, "✓ 白名单已加载")
                    } else {
                        (pal::YELLOW_DARK, pal::YELLOW, "! 白名单未加载")
                    };
                    Frame::none()
                        .fill(bg)
                        .rounding(Rounding::same(12.0))
                        .inner_margin(Margin::symmetric(10.0, 4.0))
                        .show(ui, |ui| {
                            ui.label(RichText::new(txt).size(12.0).color(fg).strong());
                        })
                        .response
                        .on_hover_text(if app.whitelist_loaded {
                            "已成功从 whitelist.yaml 加载 system_critical 白名单"
                        } else {
                            "未找到或解析失败 whitelist.yaml，本次搜索不会跳过任何路径"
                        });

                    ui.add_space(6.0);

                    let (bg, fg, txt) = if app.is_admin {
                        (pal::GREEN_DIM, pal::GREEN, "✓ 管理员")
                    } else {
                        (pal::RED_DIM, pal::RED, "! 非管理员")
                    };
                    Frame::none()
                        .fill(bg)
                        .rounding(Rounding::same(12.0))
                        .inner_margin(Margin::symmetric(10.0, 4.0))
                        .show(ui, |ui| {
                            ui.label(RichText::new(txt).size(12.0).color(fg).strong());
                        });
                });
            });

            ui.add_space(10.0);

            ui.horizontal(|ui| {
                let enabled = matches!(
                    app.mode,
                    AppMode::Idle | AppMode::Results | AppMode::Done
                );

                let search_resp = ui.add_enabled(
                    enabled,
                    egui::TextEdit::singleline(&mut app.keyword)
                        .hint_text("输入要搜索的注册表关键字…")
                        .desired_width(340.0)
                        .margin(Margin::symmetric(10.0, 8.0)),
                );

                let enter = enabled
                    && search_resp.lost_focus()
                    && ui.input(|i| i.key_pressed(egui::Key::Enter));

                if enabled {
                    let btn = egui::Button::new(
                        RichText::new("🔍 搜索").strong().color(pal::ON_ACCENT),
                    )
                        .fill(pal::ACCENT)
                        .min_size(egui::vec2(140.0, 32.0));
                    if ui.add(btn).clicked() || enter {
                        app.start_search();
                    }
                }

                if app.mode == AppMode::Results && !app.results.is_empty() {
                    ui.add_space(8.0);
                    let item_keys = app.selected_item_keys();

                    let all_effective = app.results.iter().enumerate().all(|(i, r)| {
                        app.selected[i]
                            || (r.match_type != MatchType::Item
                            && item_keys.contains(&r.key_path))
                    });

                    let delete_count = app
                        .results
                        .iter()
                        .enumerate()
                        .filter(|(i, r)| {
                            if !app.selected[*i] {
                                return false;
                            }
                            match r.match_type {
                                MatchType::Item => true,
                                _ => !item_keys.contains(&r.key_path),
                            }
                        })
                        .count();

                    if ui
                        .add(
                            egui::Button::new("☰ 全选 / 反选")
                                .min_size(egui::vec2(140.0, 32.0))
                        )
                        .clicked()
                    {
                        for s in app.selected.iter_mut() {
                            *s = !all_effective;
                        }
                    }

                    let txt_color = if delete_count > 0 {
                        Color32::WHITE
                    } else {
                        pal::TEXT_FAINT
                    };
                    let mut btn = egui::Button::new(
                        RichText::new(format!("🗑 删除选中 ({})", delete_count))
                            .strong()
                            .color(txt_color),
                    )
                        .min_size(egui::vec2(140.0, 32.0));
                    if delete_count > 0 {
                        btn = btn.fill(pal::RED_BTN);
                    }

                    if ui.add_enabled(delete_count > 0, btn).clicked() {
                        app.show_confirm = true;
                    }
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if enabled {
                        let refresh_btn =
                            egui::Button::new(RichText::new("⟳ 刷新").color(pal::TEXT))
                                .min_size(egui::vec2(90.0, 32.0));
                        if ui
                            .add(refresh_btn)
                            .on_hover_text("清空当前状态，重新开始")
                            .clicked()
                        {
                            app.reset_ui();
                        }
                    }
                });
            });
        });
}

// ---------------- 底部状态栏 ----------------

fn render_bottom(app: &CleanerApp, ctx: &egui::Context) {
    egui::TopBottomPanel::bottom("bottom")
        .frame(
            Frame::none()
                .fill(pal::BG_DEEP)
                .stroke(Stroke::new(1.0_f32, pal::BORDER_DIM))
                .inner_margin(Margin::symmetric(16.0, 10.0)),
        )
        .show(ctx, |ui| {
            if app.mode == AppMode::Done {
                ui.label(
                    RichText::new("删除操作已完成 · 中央区域为逐条处理结果")
                        .size(12.0)
                        .color(pal::TEXT_DIM),
                );
            } else if let Some(i) = app.focused {
                if let Some(r) = app.results.get(i) {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("▸").size(14.0).color(pal::ACCENT));
                        ui.label(
                            RichText::new(&r.key_path)
                                .monospace()
                                .size(12.5)
                                .color(pal::TEXT),
                        );
                    });
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        if let Some(v) = &r.value_name {
                            ui.label(RichText::new("值名").size(11.0).color(pal::TEXT_DIM));
                            ui.label(RichText::new(v).monospace().size(12.0).color(pal::YELLOW));
                            ui.add_space(16.0);
                        }
                        ui.label(RichText::new("类型").size(11.0).color(pal::TEXT_DIM));
                        badge_pill(ui, r.match_type.clone());
                        if let Some(d) = &r.value_data {
                            ui.add_space(16.0);
                            ui.label(RichText::new("数据").size(11.0).color(pal::TEXT_DIM));
                            ui.label(RichText::new(d).monospace().size(12.0).color(pal::TEXT));
                        }
                    });
                }
            } else {
                ui.label(
                    RichText::new("点击结果行查看详情")
                        .size(12.0)
                        .color(pal::TEXT_FAINT),
                );
            }

            ui.add_space(6.0);
            ui.separator();
            ui.add_space(6.0);

            ui.horizontal(|ui| match app.mode {
                AppMode::Idle => {
                    ui.label(RichText::new("●").color(pal::GREEN));
                    ui.label(RichText::new("就绪").size(12.0).color(pal::TEXT_DIM));
                    if let Some(d) = app.search_elapsed {
                        ui.label(
                            RichText::new(format!("· 上次搜索用时 {}", fmt_elapsed(d)))
                                .size(12.0)
                                .color(pal::TEXT_FAINT),
                        );
                    }
                }
                AppMode::Searching => {
                    ui.spinner();
                    let elapsed = app.search_start.map(|t| t.elapsed()).unwrap_or_default();
                    ui.label(
                        RichText::new(format!(
                            "正在搜索…  已处理 {}  ·  命中 {}  ·  {}",
                            app.processed,
                            app.found,
                            fmt_elapsed(elapsed)
                        ))
                            .color(pal::YELLOW)
                            .size(12.0),
                    );
                }
                AppMode::Results => {
                    let item_keys = app.selected_item_keys();
                    let sel = app
                        .results
                        .iter()
                        .enumerate()
                        .filter(|(i, r)| {
                            app.selected[*i]
                                || (r.match_type != MatchType::Item
                                && item_keys.contains(&r.key_path))
                        })
                        .count();

                    let elapsed = app.search_elapsed.unwrap_or_default();
                    ui.label(RichText::new("●").color(pal::ACCENT));
                    ui.label(
                        RichText::new(format!(
                            "共 {} 项，已选 {} · 已处理 {} · 用时 {}",
                            app.results.len(),
                            sel,
                            app.processed,
                            fmt_elapsed(elapsed),
                        ))
                            .size(12.0)
                            .color(pal::TEXT),
                    );
                }
                AppMode::Deleting => {
                    let frac = if app.delete_total == 0 {
                        0.0
                    } else {
                        app.delete_current as f32 / app.delete_total as f32
                    };
                    ui.add(
                        egui::ProgressBar::new(frac)
                            .desired_width(220.0)
                            .text(format!("{}/{}", app.delete_current, app.delete_total)),
                    );
                    ui.label(RichText::new("正在删除…").color(pal::YELLOW).size(12.0));
                }
                AppMode::Done => {
                    let color = if app.delete_failed > 0 {
                        pal::YELLOW
                    } else {
                        pal::GREEN
                    };
                    ui.label(RichText::new("✓").size(14.0).color(color));
                    ui.label(
                        RichText::new(format!(
                            "完成 · 成功 {} · 已不存在 {} · 跳过 {} · 失败 {}",
                            app.delete_success,
                            app.delete_already,
                            app.delete_skipped,
                            app.delete_failed
                        ))
                            .color(color)
                            .size(12.0),
                    );
                }
            });
        });
}

// ---------------- 中央区域 ----------------

fn render_central(app: &mut CleanerApp, ctx: &egui::Context) {
    egui::CentralPanel::default()
        .frame(
            Frame::none()
                .fill(pal::BG_PANEL)
                .inner_margin(Margin::symmetric(12.0, 8.0)),
        )
        .show(ctx, |ui| {
            if app.mode == AppMode::Done && !app.delete_results.is_empty() {
                render_delete_results(app, ui);
                return;
            }

            if app.results.is_empty() {
                ui.centered_and_justified(|ui| {
                    let msg = if app.mode == AppMode::Searching {
                        "正在搜索…"
                    } else {
                        "输入关键字开始搜索"
                    };
                    ui.label(RichText::new(msg).size(15.0).color(pal::TEXT_FAINT));
                });
                return;
            }

            render_results_list(app, ui);
        });
}

fn render_results_list(app: &mut CleanerApp, ui: &mut Ui) {
    let item_keys = app.selected_item_keys();
    let display_order = app.build_display_order();
    let mut prev_i: Option<usize> = None;

    ScrollArea::vertical()
        .auto_shrink([false; 2])
        .show(ui, |ui| {
            for &i in &display_order {
                if let Some(pi) = prev_i {
                    if app.results[pi].key_path != app.results[i].key_path {
                        ui.add_space(6.0);
                    }
                }
                prev_i = Some(i);

                let r = &app.results[i];
                let is_focused = app.focused == Some(i);
                let is_forced =
                    r.match_type != MatchType::Item && item_keys.contains(&r.key_path);
                let is_selected = app.selected[i] || is_forced;

                let (bg, border) = if is_focused {
                    (pal::BG_CARD_FOCUS, pal::BORDER_FOCUS)
                } else if is_selected {
                    (pal::BG_CARD_SEL, pal::BORDER_SEL)
                } else {
                    (pal::BG_CARD, pal::BORDER_DIM)
                };

                let frame = Frame::none()
                    .fill(bg)
                    .stroke(Stroke::new(1.0_f32, border))
                    .rounding(Rounding::same(6.0))
                    .inner_margin(Margin::symmetric(10.0, 8.0))
                    .outer_margin(Margin::symmetric(0.0, 1.0));

                frame.show(ui, |ui| {
                    ui.horizontal(|ui| {
                        let cb_bg = if is_forced {
                            pal::BORDER_SEL
                        } else if is_selected {
                            pal::ACCENT
                        } else {
                            Color32::WHITE
                        };
                        let cb_border = if is_selected || is_forced {
                            cb_bg
                        } else {
                            pal::BORDER_DIM
                        };

                        let (cb_rect, cb_resp) = ui.allocate_exact_size(
                            egui::vec2(18.0, 18.0),
                            egui::Sense::click(),
                        );
                        let painter = ui.painter();
                        painter.rect_filled(cb_rect, Rounding::same(3.0), cb_bg);
                        painter.rect_stroke(
                            cb_rect,
                            Rounding::same(3.0),
                            Stroke::new(1.0_f32, cb_border),
                        );
                        if is_selected {
                            let inner = cb_rect.shrink(4.0);
                            let p1 = egui::pos2(inner.left(), inner.center().y);
                            let p2 = egui::pos2(inner.center().x - 0.5, inner.bottom() - 1.0);
                            let p3 = egui::pos2(inner.right(), inner.top() + 1.5);
                            let check_stroke = Stroke::new(2.0_f32, Color32::WHITE);
                            painter.line_segment([p1, p2], check_stroke);
                            painter.line_segment([p2, p3], check_stroke);
                        }

                        if cb_resp.clicked() {
                            if is_forced {
                                app.toast = Some((
                                    "所属键已被选中，该值会随键一起删除".to_string(),
                                    Instant::now(),
                                ));
                            } else {
                                app.selected[i] = !app.selected[i];
                            }
                        }
                        if cb_resp.hovered() {
                            let icon = if is_forced {
                                egui::CursorIcon::NotAllowed
                            } else {
                                egui::CursorIcon::PointingHand
                            };
                            ui.ctx().set_cursor_icon(icon);
                        }
                        if is_forced {
                            cb_resp.on_hover_text("随所属键一起删除，无法单独取消");
                        }

                        ui.add_space(4.0);
                        badge_pill(ui, r.match_type.clone());
                        ui.add_space(6.0);

                        if is_forced {
                            ui.label(
                                RichText::new("随键删除")
                                    .size(10.5)
                                    .color(pal::ACCENT)
                                    .italics(),
                            );
                            ui.add_space(4.0);
                        }

                        let path = if let Some(v) = &r.value_name {
                            format!("{}  →  {}", r.key_path, v)
                        } else {
                            r.key_path.clone()
                        };
                        let text_color = if is_focused {
                            pal::TEXT_BRIGHT
                        } else {
                            pal::TEXT
                        };

                        let path_resp = ui.add(
                            egui::Label::new(
                                RichText::new(path)
                                    .monospace()
                                    .size(12.5)
                                    .color(text_color),
                            )
                                .truncate()
                                .sense(egui::Sense::click()),
                        );

                        if path_resp.clicked() {
                            app.focused = Some(i);
                        }
                        if path_resp.double_clicked() {
                            if is_forced {
                                app.toast = Some((
                                    "所属键已被选中，该值会随键一起删除".to_string(),
                                    Instant::now(),
                                ));
                            } else {
                                app.selected[i] = !app.selected[i];
                            }
                        }
                        if path_resp.hovered() {
                            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                        }
                    });
                });
            }
        });
}

fn render_delete_results(app: &CleanerApp, ui: &mut Ui) {
    ui.horizontal(|ui| {
        ui.label(
            RichText::new("删除结果")
                .size(15.0)
                .strong()
                .color(pal::TEXT_BRIGHT),
        );
        ui.add_space(10.0);
        stat_pill(ui, "✓ 成功", app.delete_success, pal::GREEN, pal::GREEN_DARK);
        stat_pill(
            ui,
            "ℹ 已不存在",
            app.delete_already,
            pal::TEXT_DIM,
            pal::BG_WIDGET,
        );
        stat_pill(
            ui,
            "⏭ 已跳过",
            app.delete_skipped,
            pal::YELLOW,
            pal::YELLOW_DARK,
        );
        stat_pill(ui, "✕ 失败", app.delete_failed, pal::RED, pal::RED_DIM);
    });
    ui.add_space(8.0);

    ScrollArea::vertical()
        .auto_shrink([false; 2])
        .show(ui, |ui| {
            for r in &app.delete_results {
                let (icon, label, fg, bg) = classify_delete(r);

                let frame = Frame::none()
                    .fill(pal::BG_CARD)
                    .stroke(Stroke::new(1.0_f32, pal::BORDER_DIM))
                    .rounding(Rounding::same(6.0))
                    .inner_margin(Margin::symmetric(10.0, 8.0))
                    .outer_margin(Margin::symmetric(0.0, 2.0));

                frame.show(ui, |ui| {
                    ui.horizontal(|ui| {
                        Frame::none()
                            .fill(bg)
                            .rounding(Rounding::same(4.0))
                            .inner_margin(Margin::symmetric(6.0, 2.0))
                            .show(ui, |ui| {
                                ui.label(
                                    RichText::new(format!("{} {}", icon, label))
                                        .size(11.0)
                                        .color(fg)
                                        .strong(),
                                );
                            });

                        ui.add_space(6.0);

                        let path = if let Some(v) = &r.value_name {
                            format!("{}  →  {}", r.key_path, v)
                        } else {
                            r.key_path.clone()
                        };
                        ui.add(
                            egui::Label::new(
                                RichText::new(path).monospace().size(12.5).color(pal::TEXT),
                            )
                                .truncate(),
                        );
                    });

                    if !r.message.is_empty() {
                        ui.add_space(2.0);
                        let msg_color = if r.success || r.skipped {
                            pal::TEXT_DIM
                        } else {
                            pal::RED
                        };
                        ui.horizontal(|ui| {
                            ui.add_space(4.0);
                            ui.label(RichText::new(&r.message).size(11.5).color(msg_color));
                        });
                    }
                });
            }
        });
}

// ---------------- 弹窗 ----------------

fn render_confirm_dialog(app: &mut CleanerApp, ctx: &egui::Context) {
    if !app.show_confirm {
        return;
    }

    let item_keys = app.selected_item_keys();
    let sel = app
        .results
        .iter()
        .enumerate()
        .filter(|(i, r)| {
            if !app.selected[*i] {
                return false;
            }
            match r.match_type {
                MatchType::Item => true,
                _ => !item_keys.contains(&r.key_path),
            }
        })
        .count();

    let frame = Frame::none()
        .fill(pal::BG_CARD)
        .stroke(Stroke::new(1.5_f32, pal::RED_BTN))
        .rounding(Rounding::same(10.0))
        .inner_margin(Margin::symmetric(20.0, 16.0));

    egui::Window::new("confirm")
        .title_bar(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .frame(frame)
        .show(ctx, |ui| {
            ui.label(
                RichText::new("!  确认删除")
                    .size(16.0)
                    .strong()
                    .color(pal::RED),
            );
            ui.add_space(8.0);
            ui.label(
                RichText::new(format!("即将删除选中的 {} 个项目", sel))
                    .size(14.0)
                    .color(pal::TEXT),
            );
            ui.add_space(4.0);
            ui.label(
                RichText::new("此操作不可撤销")
                    .size(11.5)
                    .color(pal::TEXT_FAINT),
            );
            ui.add_space(16.0);

            ui.horizontal(|ui| {
                let confirm_btn =
                    egui::Button::new(RichText::new("⚠ 确认删除").strong().color(Color32::WHITE))
                        .fill(pal::RED_BTN)
                        .min_size(egui::vec2(120.0, 32.0));
                if ui.add(confirm_btn).clicked() {
                    app.start_delete();
                }
                ui.add_space(10.0);
                let cancel_btn =
                    egui::Button::new(RichText::new("✕ 取消")).min_size(egui::vec2(100.0, 32.0));
                if ui.add(cancel_btn).clicked() {
                    app.show_confirm = false;
                }
            });
        });
}

fn render_info_dialog(app: &mut CleanerApp, ctx: &egui::Context) {
    let Some(msg) = app.info_dialog.clone() else {
        return;
    };

    let frame = Frame::none()
        .fill(pal::BG_CARD)
        .stroke(Stroke::new(1.5_f32, pal::BORDER_FOCUS))
        .rounding(Rounding::same(10.0))
        .inner_margin(Margin::symmetric(24.0, 18.0));

    egui::Window::new("info")
        .title_bar(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .frame(frame)
        .show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.label(
                    RichText::new("提示")
                        .size(16.0)
                        .strong()
                        .color(pal::ACCENT),
                );
                ui.add_space(8.0);
                ui.label(RichText::new(&msg).size(14.0).color(pal::TEXT));
                ui.add_space(18.0);

                let ok_btn = egui::Button::new(
                    RichText::new("✓ 确定").strong().color(pal::ON_ACCENT),
                )
                    .fill(pal::ACCENT)
                    .min_size(egui::vec2(140.0, 32.0));

                if ui.add(ok_btn).clicked()
                    || ui.input(|i| i.key_pressed(egui::Key::Enter))
                    || ui.input(|i| i.key_pressed(egui::Key::Escape))
                {
                    app.info_dialog = None;
                }
            });
        });
}

fn render_toast(app: &mut CleanerApp, ctx: &egui::Context) {
    let Some((msg, t)) = &app.toast else {
        return;
    };
    if t.elapsed() < Duration::from_millis(1800) {
        let frame = Frame::none()
            .fill(Color32::from_rgb(255, 249, 226))
            .stroke(Stroke::new(1.0_f32, pal::YELLOW))
            .rounding(Rounding::same(8.0))
            .inner_margin(Margin::symmetric(16.0, 10.0));

        egui::Window::new("toast")
            .title_bar(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_BOTTOM, [0.0, -80.0])
            .frame(frame)
            .show(ctx, |ui| {
                ui.label(RichText::new(msg).size(13.0).color(pal::YELLOW));
            });
        ctx.request_repaint_after(Duration::from_millis(100));
    } else {
        app.toast = None;
    }
}

// ---------------- UI 小组件 ----------------

fn badge_pill(ui: &mut Ui, mt: MatchType) {
    let (text, bg, fg) = match mt {
        MatchType::Item => ("键名", pal::YELLOW_DARK, pal::YELLOW),
        MatchType::Key => ("值名", pal::GREEN_DARK, pal::GREEN),
        MatchType::Value => ("数据", pal::PURPLE_DARK, pal::PURPLE),
    };
    Frame::none()
        .fill(bg)
        .rounding(Rounding::same(4.0))
        .inner_margin(Margin::symmetric(6.0, 2.0))
        .show(ui, |ui| {
            ui.label(RichText::new(text).size(11.0).color(fg).strong());
        });
}

fn stat_pill(ui: &mut Ui, label: &str, count: usize, fg: Color32, bg: Color32) {
    Frame::none()
        .fill(bg)
        .rounding(Rounding::same(4.0))
        .inner_margin(Margin::symmetric(6.0, 2.0))
        .show(ui, |ui| {
            ui.label(
                RichText::new(format!("{} {}", label, count))
                    .size(11.5)
                    .color(fg)
                    .strong(),
            );
        });
}

fn classify_delete(r: &DeleteResult) -> (&'static str, &'static str, Color32, Color32) {
    if r.skipped {
        ("⏭", "已跳过", pal::YELLOW, pal::YELLOW_DARK)
    } else if r.already_deleted {
        ("ℹ", "已不存在", pal::TEXT_DIM, pal::BG_WIDGET)
    } else if r.success {
        ("✓", "成功", pal::GREEN, pal::GREEN_DARK)
    } else {
        ("✕", "失败", pal::RED, pal::RED_DIM)
    }
}

// ---------------- 样式 / 字体 ----------------

pub(crate) fn setup_style(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();

    let mut v = egui::Visuals::light();
    v.panel_fill = pal::BG_PANEL;
    v.window_fill = pal::BG_CARD;
    v.extreme_bg_color = pal::BG_WIDGET;
    v.faint_bg_color = pal::BG_DEEP;
    v.override_text_color = Some(pal::TEXT);

    v.widgets.noninteractive.bg_fill = pal::BG_WIDGET;
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, pal::BORDER_DIM);
    v.widgets.noninteractive.fg_stroke = Stroke::new(1.0_f32, pal::TEXT_DIM);
    v.widgets.inactive.bg_fill = pal::BG_WIDGET;
    v.widgets.inactive.weak_bg_fill = pal::BG_WIDGET;
    v.widgets.inactive.fg_stroke = Stroke::new(1.0_f32, pal::TEXT);
    v.widgets.hovered.bg_fill = pal::BG_HOVER;
    v.widgets.hovered.weak_bg_fill = pal::BG_HOVER;
    v.widgets.hovered.fg_stroke = Stroke::new(1.0_f32, pal::TEXT_BRIGHT);
    v.widgets.active.bg_fill = pal::BG_ACTIVE;
    v.widgets.active.weak_bg_fill = pal::BG_ACTIVE;
    v.widgets.active.fg_stroke = Stroke::new(1.5_f32, pal::TEXT_BRIGHT);

    v.selection.bg_fill = Color32::from_rgb(200, 225, 250);
    v.selection.stroke = Stroke::new(1.0_f32, pal::ACCENT);
    v.hyperlink_color = pal::ACCENT;

    let shadow = egui::epaint::Shadow {
        offset: egui::vec2(0.0, 4.0),
        blur: 16.0,
        spread: 0.0,
        color: Color32::from_black_alpha(28),
    };
    v.window_shadow = shadow;
    v.popup_shadow = shadow;

    v.widgets.noninteractive.rounding = Rounding::same(6.0);
    v.widgets.inactive.rounding = Rounding::same(6.0);
    v.widgets.hovered.rounding = Rounding::same(6.0);
    v.widgets.active.rounding = Rounding::same(6.0);
    v.window_rounding = Rounding::same(10.0);
    v.menu_rounding = Rounding::same(8.0);

    style.visuals = v;
    style.spacing.item_spacing = egui::vec2(8.0, 6.0);
    style.spacing.button_padding = egui::vec2(12.0, 6.0);
    style.spacing.interact_size.y = 28.0;
    style.spacing.scroll.bar_width = 10.0;
    style.spacing.scroll.bar_inner_margin = 4.0;

    ctx.set_style(style);
}

pub(crate) fn setup_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();

    for path in [
        "C:\\Windows\\Fonts\\msyh.ttc",
        "C:\\Windows\\Fonts\\simhei.ttf",
        "C:\\Windows\\Fonts\\simsun.ttc",
    ] {
        if let Ok(data) = std::fs::read(path) {
            fonts
                .font_data
                .insert("cjk".to_owned(), egui::FontData::from_owned(data));
            fonts
                .families
                .get_mut(&egui::FontFamily::Proportional)
                .unwrap()
                .push("cjk".to_owned());
            fonts
                .families
                .get_mut(&egui::FontFamily::Monospace)
                .unwrap()
                .push("cjk".to_owned());
            break;
        }
    }

    if let Ok(data) = std::fs::read("C:\\Windows\\Fonts\\seguisym.ttf") {
        fonts
            .font_data
            .insert("sym".to_owned(), egui::FontData::from_owned(data));
        fonts
            .families
            .get_mut(&egui::FontFamily::Proportional)
            .unwrap()
            .push("sym".to_owned());
        fonts
            .families
            .get_mut(&egui::FontFamily::Monospace)
            .unwrap()
            .push("sym".to_owned());
    }

    ctx.set_fonts(fonts);
}