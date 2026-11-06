use bevy::{
    camera::RenderTarget, core_pipeline::tonemapping::Tonemapping, prelude::*,
    render::RenderPlugin, winit::WinitPlugin,
};
use bevy_capture::{
    encoder::{Encoder, Result},
    Capture, CaptureBundle, CapturePlugin, RenderTargetHeadless,
};
use std::sync::{Arc, Mutex};

// 320 * 4 = 1280 bytes per row is a multiple of 256, so the copy needs no row padding,
// while the 320 pixel count is not a multiple of 256.
const WIDTH: u32 = 320;
const HEIGHT: u32 = 2;
const ROW_BYTES: usize = WIDTH as usize * 4;
const ROWS: [[u8; 4]; HEIGHT as usize] = [[255, 0, 0, 255], [0, 0, 255, 255]];
const UPDATES: usize = 5;

#[derive(Clone, Default)]
struct Collector(Arc<Mutex<Vec<Vec<u8>>>>);

impl Encoder for Collector {
    fn encode(&mut self, image: &Image) -> Result<()> {
        self.0
            .lock()
            .unwrap()
            .push(image.data.clone().expect("captured image has data"));
        Ok(())
    }
}

fn setup(mut commands: Commands, mut images: ResMut<Assets<Image>>) {
    commands.spawn((
        Camera2d,
        Tonemapping::None,
        Msaa::Off,
        RenderTarget::target_headless(WIDTH, HEIGHT, &mut images),
        CaptureBundle::default(),
    ));
    for (y, color) in [0.5, -0.5].into_iter().zip(ROWS) {
        commands.spawn((
            Sprite::from_color(
                Color::srgba_u8(color[0], color[1], color[2], color[3]),
                Vec2::new(WIDTH as f32, 1.0),
            ),
            Transform::from_xyz(0.0, y, 0.0),
        ));
    }
}

#[test]
fn captured_frame_keeps_every_row_of_the_source() {
    let collector = Collector::default();

    let mut app = App::new();
    app.add_plugins((
        DefaultPlugins
            .build()
            .disable::<WinitPlugin>()
            .set(RenderPlugin {
                synchronous_pipeline_compilation: true,
                ..default()
            }),
        CapturePlugin,
    ))
    .add_systems(Startup, setup);
    app.finish();
    app.cleanup();

    for _ in 0..UPDATES {
        app.update();
    }
    app.world_mut()
        .query::<&mut Capture>()
        .single_mut(app.world_mut())
        .unwrap()
        .start(collector.clone());
    for _ in 0..UPDATES {
        app.update();
    }

    let frames = collector.0.lock().unwrap();
    assert!(!frames.is_empty(), "no frame reached the encoder");
    for frame in frames.iter() {
        assert_eq!(
            frame.len(),
            ROW_BYTES * HEIGHT as usize,
            "frame byte length"
        );
        for (row, color) in frame.chunks(ROW_BYTES).zip(ROWS) {
            assert!(
                row.chunks(4).all(|pixel| pixel == color),
                "row differs from its source pattern"
            );
        }
    }
}
