use egui::{Color32, Context, Stroke, Visuals};

pub fn apply_theme(ctx: &Context, dark_mode: bool) {
    let mut style = (*ctx.style()).clone();

    if dark_mode {
        let mut visuals = Visuals::dark();
        visuals.panel_fill = Color32::from_rgb(15, 20, 28);
        visuals.window_fill = Color32::from_rgb(22, 31, 44);
        visuals.extreme_bg_color = Color32::from_rgb(11, 15, 22);

        visuals.widgets.noninteractive.bg_fill = Color32::from_rgb(22, 31, 44);
        visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0f32, Color32::from_rgb(34, 49, 69));
        visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0f32, Color32::from_rgb(226, 232, 240));

        visuals.widgets.inactive.bg_fill = Color32::from_rgb(26, 36, 51);
        visuals.widgets.inactive.bg_stroke = Stroke::new(1.0f32, Color32::from_rgb(42, 60, 84));
        visuals.widgets.inactive.fg_stroke = Stroke::new(1.0f32, Color32::from_rgb(203, 213, 225));

        visuals.widgets.hovered.bg_fill = Color32::from_rgb(35, 49, 70);
        visuals.widgets.hovered.bg_stroke = Stroke::new(1.0f32, Color32::from_rgb(56, 189, 248));
        visuals.widgets.hovered.fg_stroke = Stroke::new(1.0f32, Color32::WHITE);

        visuals.widgets.active.bg_fill = Color32::from_rgb(30, 58, 95);
        visuals.widgets.active.bg_stroke = Stroke::new(1.0f32, Color32::from_rgb(56, 189, 248));
        visuals.widgets.active.fg_stroke = Stroke::new(1.0f32, Color32::WHITE);

        visuals.selection.bg_fill = Color32::from_rgb(30, 58, 95);
        visuals.selection.stroke = Stroke::new(1.0f32, Color32::from_rgb(56, 189, 248));

        style.visuals = visuals;
    } else {
        let mut visuals = Visuals::light();
        visuals.panel_fill = Color32::from_rgb(248, 250, 252);
        visuals.window_fill = Color32::from_rgb(255, 255, 255);
        visuals.extreme_bg_color = Color32::from_rgb(241, 245, 249);

        visuals.widgets.noninteractive.bg_fill = Color32::from_rgb(255, 255, 255);
        visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0f32, Color32::from_rgb(203, 213, 225));
        visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0f32, Color32::from_rgb(15, 23, 42));

        visuals.widgets.inactive.bg_fill = Color32::from_rgb(241, 245, 249);
        visuals.widgets.inactive.bg_stroke = Stroke::new(1.0f32, Color32::from_rgb(203, 213, 225));
        visuals.widgets.inactive.fg_stroke = Stroke::new(1.0f32, Color32::from_rgb(51, 65, 85));

        visuals.widgets.hovered.bg_fill = Color32::from_rgb(226, 232, 240);
        visuals.widgets.hovered.bg_stroke = Stroke::new(1.0f32, Color32::from_rgb(2, 132, 199));
        visuals.widgets.hovered.fg_stroke = Stroke::new(1.0f32, Color32::BLACK);

        visuals.widgets.active.bg_fill = Color32::from_rgb(219, 234, 254);
        visuals.widgets.active.bg_stroke = Stroke::new(1.0f32, Color32::from_rgb(2, 132, 199));
        visuals.widgets.active.fg_stroke = Stroke::new(1.0f32, Color32::BLACK);

        visuals.selection.bg_fill = Color32::from_rgb(219, 234, 254);
        visuals.selection.stroke = Stroke::new(1.0f32, Color32::from_rgb(2, 132, 199));

        style.visuals = visuals;
    }

    ctx.set_style(style);
}
