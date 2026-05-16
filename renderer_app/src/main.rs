#![windows_subsystem = "windows"]

use std::sync::Arc;
use winit::{
    application::ApplicationHandler,
    event::WindowEvent,
    event_loop::{ActiveEventLoop, ControlFlow, EventLoop},
    window::{Window, WindowId},
};
use glyphon::{
    fontdb, Attrs, Buffer, Color, Family, FontSystem, Metrics, Resolution, Shaping, SwashCache,
    TextArea, TextAtlas, TextBounds, TextRenderer,
};

#[derive(PartialEq, Clone, Copy)]
enum AppMode {
    Home,
    Editing,
}

struct AppState {
    window: Arc<Window>,
    surface: wgpu::Surface<'static>,
    device: wgpu::Device,
    queue: wgpu::Queue,
    config: wgpu::SurfaceConfiguration,

    font_system: FontSystem,
    swash_cache: SwashCache,
    viewport: glyphon::Viewport,
    text_atlas: TextAtlas,
    text_renderer: TextRenderer,
    text_buffer: Buffer,

    bg_pipeline: wgpu::RenderPipeline,
    bg_bind_group: wgpu::BindGroup,
    bg_uniform_buf: wgpu::Buffer,
    start_time: std::time::Instant,
    mode: AppMode,
    cursor_pos: winit::dpi::PhysicalPosition<f64>,
    edit_text: String,
    ime_preedit: String,
    modifiers: winit::keyboard::ModifiersState,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, bytemuck::Pod, bytemuck::Zeroable)]
struct BgUniforms {
    resolution: [f32; 2],
    time: f32,
    mode: f32,
}

#[derive(Default)]
struct App {
    state: Option<AppState>,
}

impl ApplicationHandler for App {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        if self.state.is_some() {
            return;
        }

        let window = Arc::new(
            event_loop
                .create_window(
                    Window::default_attributes()
                        .with_title("Rust Wgpu Font Rendering")
                        .with_inner_size(winit::dpi::PhysicalSize::new(1920, 1080))
                )
                .unwrap(),
        );

        let size = window.inner_size();

        let instance = wgpu::Instance::default();
        let surface = instance.create_surface(window.clone()).unwrap();

        let adapter = pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions {
            power_preference: wgpu::PowerPreference::HighPerformance,
            compatible_surface: Some(&surface),
            force_fallback_adapter: false,
        }))
        .unwrap();

        let (device, queue) = pollster::block_on(adapter.request_device(
            &wgpu::DeviceDescriptor {
                label: None,
                required_features: wgpu::Features::empty(),
                required_limits: wgpu::Limits::default(),
                ..Default::default()
            },
        ))
        .unwrap();

        let surface_caps = surface.get_capabilities(&adapter);
        let surface_format = surface_caps
            .formats
            .iter()
            .copied()
            .find(|f| f.is_srgb())
            .unwrap_or(surface_caps.formats[0]);

        let config = wgpu::SurfaceConfiguration {
            usage: wgpu::TextureUsages::RENDER_ATTACHMENT,
            format: surface_format,
            width: size.width.max(1),
            height: size.height.max(1),
            present_mode: surface_caps.present_modes[0],
            alpha_mode: surface_caps.alpha_modes[0],
            view_formats: vec![],
            desired_maximum_frame_latency: 2,
        };
        surface.configure(&device, &config);

        let mut font_system = FontSystem::new();
        let font_dir = std::path::Path::new(r"C:\Users\Administrator\Desktop\锚点\Font");
        
        let _ = font_system.db_mut().load_font_file(font_dir.join(r"HarmonyOS_Sans\HarmonyOS_Sans_Regular.ttf"));
        let _ = font_system.db_mut().load_font_file(font_dir.join(r"HarmonyOS_Sans_SC\HarmonyOS_Sans_SC_Regular.ttf"));
        let _ = font_system.db_mut().load_font_file(font_dir.join(r"HarmonyOS_Sans_Naskh_Arabic\HarmonyOS_Sans_Naskh_Arabic_Regular.ttf"));

        font_system.db_mut().set_sans_serif_family("HarmonyOS Sans");

        let swash_cache = SwashCache::new();
        let cache = glyphon::Cache::new(&device);
        let mut viewport = glyphon::Viewport::new(&device, &cache);
        viewport.update(&queue, Resolution { width: size.width.max(1), height: size.height.max(1) });

        let mut text_atlas = TextAtlas::new(&device, &queue, &cache, surface_format);
        let text_renderer =
            TextRenderer::new(&mut text_atlas, &device, wgpu::MultisampleState::default(), None);

        let mut text_buffer = Buffer::new(&mut font_system, Metrics::new(32.0, 52.0));
        text_buffer.set_size(&mut font_system, Some(size.width as f32), Some(size.height as f32));
        text_buffer.set_text(
            &mut font_system,
            "锚点笔记 (Anchor Notes)\n\n点击右下角 + 号新建笔记",
            &Attrs::new().family(Family::SansSerif),
            Shaping::Advanced,
            None,
        );
        text_buffer.shape_until_scroll(&mut font_system, false);

        let bg_shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("bg_shader"),
            source: wgpu::ShaderSource::Wgsl(std::borrow::Cow::Borrowed(r#"
struct BgUniforms {
    resolution: vec2<f32>,
    time: f32,
    mode: f32,
};
@group(0) @binding(0) var<uniform> uniforms: BgUniforms;

struct VertexOutput {
    @builtin(position) clip_position: vec4<f32>,
};

fn mod289(x: vec3<f32>) -> vec3<f32> { return x - floor(x * (1.0 / 289.0)) * 289.0; }
fn mod289_2(x: vec2<f32>) -> vec2<f32> { return x - floor(x * (1.0 / 289.0)) * 289.0; }
fn permute(x: vec3<f32>) -> vec3<f32> { return mod289(((x * 34.0) + 1.0) * x); }
fn snoise(v: vec2<f32>) -> f32 {
    let C = vec4<f32>(0.211324865405187, 0.366025403784439, -0.577350269189626, 0.024390243902439);
    var i  = floor(v + dot(v, C.yy));
    let x0 = v -   i + dot(i, C.xx);
    var i1 = vec2<f32>(0.0);
    if (x0.x > x0.y) { i1 = vec2<f32>(1.0, 0.0); } else { i1 = vec2<f32>(0.0, 1.0); }
    let x1 = x0.xy + C.xx - i1;
    let x2 = x0.xy + C.zz;
    i = mod289_2(i);
    let p = permute(permute(i.y + vec3<f32>(0.0, i1.y, 1.0)) + i.x + vec3<f32>(0.0, i1.x, 1.0));
    var m = max(0.5 - vec3<f32>(dot(x0, x0), dot(x1, x1), dot(x2, x2)), vec3<f32>(0.0));
    m = m * m; m = m * m;
    let x = 2.0 * fract(p * C.www) - 1.0;
    let h = abs(x) - 0.5;
    let ox = floor(x + 0.5);
    let a0 = x - ox;
    m = m * (1.79284291400159 - 0.85373472095314 * (a0 * a0 + h * h));
    let g = vec3<f32>(a0.x * x0.x + h.x * x0.y, a0.y * x1.x + h.y * x1.y, a0.z * x2.x + h.z * x2.y);
    return 130.0 * dot(m, g);
}
fn noise(p: vec2<f32>) -> f32 { return snoise(p) * 0.5 + 0.5; }

fn fbm(p: vec2<f32>) -> f32 {
    var v = 0.0; var a = 0.5; var shift = vec2<f32>(100.0); var p2 = p;
    let rot = mat2x2<f32>(cos(0.5), sin(0.5), -sin(0.5), cos(0.5));
    for (var i = 0; i < 4; i++) {
        v += a * noise(p2);
        p2 = rot * p2 * 2.0 + shift; 
        a *= 0.5;
    }
    return v;
}

fn srgb_to_linear(c: vec3<f32>) -> vec3<f32> {
    return pow(c, vec3<f32>(2.2));
}

fn get_fluid(uv: vec2<f32>, t: f32) -> f32 {
    let q = vec2<f32>(fbm(uv + vec2<f32>(0.0, 0.0) + t), fbm(uv + vec2<f32>(5.2, 1.3) - t));
    let r = vec2<f32>(fbm(uv + 4.0*q + vec2<f32>(1.7, 9.2) + t*0.5), fbm(uv + 4.0*q + vec2<f32>(8.3, 2.8) - t*0.7));
    return fbm(uv + 4.0*r);
}

fn sd_segment(p: vec2<f32>, a: vec2<f32>, b: vec2<f32>) -> f32 {
    let pa = p - a;
    let ba = b - a;
    let h = clamp(dot(pa, ba) / dot(ba, ba), 0.0, 1.0);
    return length(pa - ba * h);
}

@vertex
fn vs_main(@builtin(vertex_index) in_vertex_index: u32) -> VertexOutput {
    var pos = array<vec2<f32>, 3>(vec2<f32>(-1.0, -3.0), vec2<f32>(3.0, 1.0), vec2<f32>(-1.0, 1.0));
    var out: VertexOutput; out.clip_position = vec4<f32>(pos[in_vertex_index], 0.0, 1.0); return out;
}

@fragment
fn fs_main(in: VertexOutput) -> @location(0) vec4<f32> {
    let p = in.clip_position.xy;
    let y = p.y;
    
    var bg_color = vec3<f32>(0.0);
    let bar_color = srgb_to_linear(vec3<f32>(0.0862745)); // #161616
    
    if (y <= 60.0) { 
        bg_color = bar_color; 
    } else if (y >= uniforms.resolution.y - 40.0) { 
        bg_color = bar_color; 
    } else {
        let base_dark = srgb_to_linear(vec3<f32>(0.06666)); // #111111
        let bright_white = srgb_to_linear(vec3<f32>(0.95)); 
        
        let uv = p / uniforms.resolution.y * 2.5; 
        let t = uniforms.time * 0.03; 
        
        var f_blurred = 0.0;
        let blur_radius = 0.15; 
        
        for(var i=0; i<12; i++) {
            let r_blur = sqrt(f32(i) / 12.0);
            let theta = 2.39996323 * f32(i);
            let offset = vec2<f32>(cos(theta), sin(theta)) * r_blur * blur_radius;
            f_blurred += get_fluid(uv + offset, t);
        }
        f_blurred /= 12.0; 
        
        let halo = smoothstep(0.55, 0.85, f_blurred);
        let final_halo = pow(halo, 1.5); 
        
        bg_color = mix(base_dark, bright_white, final_halo);
    }
    
    // --- FAB (Floating Action Button) & Back Button ---
    var final_color = bg_color;

    if (uniforms.mode < 0.5) {
        // Home 模式：渲染右下角 + 号按钮
        let fab_center = vec2<f32>(uniforms.resolution.x - 80.0, uniforms.resolution.y - 80.0);
        
        let d_circle = length(p - fab_center) - 30.0;
        let circle_color = srgb_to_linear(vec3<f32>(0.07843)); 
        
        let d_line1 = sd_segment(p, fab_center + vec2<f32>(-18.0, 0.0), fab_center + vec2<f32>(18.0, 0.0)) - 2.0;
        let d_line2 = sd_segment(p, fab_center + vec2<f32>(0.0, -18.0), fab_center + vec2<f32>(0.0, 18.0)) - 2.0;
        let d_plus = min(d_line1, d_line2);
        let plus_color = srgb_to_linear(vec3<f32>(0.50196)); 
        
        let aa = 1.5;
        let alpha_circle = 1.0 - smoothstep(0.0, aa, d_circle);
        let alpha_plus = 1.0 - smoothstep(0.0, aa, d_plus);
        
        final_color = mix(final_color, circle_color, alpha_circle);
        final_color = mix(final_color, plus_color, alpha_plus);
    } else {
        // Editing 模式：渲染左上角返回按钮
        let back_center = vec2<f32>(30.0, 30.0);
        
        let d_back_circle = length(p - back_center) - 15.0;
        let back_color = srgb_to_linear(vec3<f32>(0.2)); 
        
        let d_arrow1 = sd_segment(p, back_center + vec2<f32>(4.0, 0.0), back_center + vec2<f32>(-4.0, 0.0)) - 1.5;
        let d_arrow2 = sd_segment(p, back_center + vec2<f32>(-4.0, 0.0), back_center + vec2<f32>(0.0, -4.0)) - 1.5;
        let d_arrow3 = sd_segment(p, back_center + vec2<f32>(-4.0, 0.0), back_center + vec2<f32>(0.0, 4.0)) - 1.5;
        let d_arrow = min(d_arrow1, min(d_arrow2, d_arrow3));
        let arrow_color = srgb_to_linear(vec3<f32>(0.8)); 
        
        let aa = 1.5;
        let alpha_back = 1.0 - smoothstep(0.0, aa, d_back_circle);
        let alpha_arrow = 1.0 - smoothstep(0.0, aa, d_arrow);
        
        final_color = mix(final_color, back_color, alpha_back);
        final_color = mix(final_color, arrow_color, alpha_arrow);
    }

    return vec4<f32>(final_color, 1.0);
}
            "#)),
        });

        use wgpu::util::DeviceExt;
        let bg_uniform_buf = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("bg_uniform_buf"),
            contents: bytemuck::cast_slice(&[BgUniforms {
                resolution: [size.width as f32, size.height as f32],
                time: 0.0,
                mode: 0.0,
            }]),
            usage: wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST,
        });

        let bg_bind_group_layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("bg_bind_group_layout"),
            entries: &[
                wgpu::BindGroupLayoutEntry {
                    binding: 0,
                    visibility: wgpu::ShaderStages::FRAGMENT,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Uniform,
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
            ],
        });

        let bg_bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("bg_bind_group"),
            layout: &bg_bind_group_layout,
            entries: &[
                wgpu::BindGroupEntry {
                    binding: 0,
                    resource: bg_uniform_buf.as_entire_binding(),
                },
            ],
        });

        let bg_pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("bg_pipeline_layout"),
            bind_group_layouts: &[Some(&bg_bind_group_layout)],
            immediate_size: 0,
        });

        let bg_pipeline = device.create_render_pipeline(&wgpu::RenderPipelineDescriptor {
            label: Some("bg_pipeline"),
            layout: Some(&bg_pipeline_layout),
            vertex: wgpu::VertexState {
                module: &bg_shader,
                entry_point: Some("vs_main"),
                compilation_options: Default::default(),
                buffers: &[],
            },
            fragment: Some(wgpu::FragmentState {
                module: &bg_shader,
                entry_point: Some("fs_main"),
                compilation_options: Default::default(),
                targets: &[Some(wgpu::ColorTargetState {
                    format: surface_format,
                    blend: Some(wgpu::BlendState::REPLACE),
                    write_mask: wgpu::ColorWrites::ALL,
                })],
            }),
            primitive: wgpu::PrimitiveState {
                topology: wgpu::PrimitiveTopology::TriangleList,
                strip_index_format: None,
                front_face: wgpu::FrontFace::Ccw,
                cull_mode: Some(wgpu::Face::Back),
                polygon_mode: wgpu::PolygonMode::Fill,
                unclipped_depth: false,
                conservative: false,
            },
            depth_stencil: None,
            multisample: wgpu::MultisampleState::default(),
            multiview_mask: None,
            cache: None,
        });

        self.state = Some(AppState {
            window,
            surface,
            device,
            queue,
            config,
            font_system,
            swash_cache,
            viewport,
            text_atlas,
            text_renderer,
            text_buffer,
            bg_pipeline,
            bg_bind_group,
            bg_uniform_buf,
            start_time: std::time::Instant::now(),
            mode: AppMode::Home,
            cursor_pos: winit::dpi::PhysicalPosition::new(0.0, 0.0),
            edit_text: String::new(),
            ime_preedit: String::new(),
            modifiers: winit::keyboard::ModifiersState::default(),
        });
    }

    fn window_event(
        &mut self,
        event_loop: &ActiveEventLoop,
        window_id: WindowId,
        event: WindowEvent,
    ) {
        let state = match self.state.as_mut() {
            Some(state) => state,
            None => return,
        };

        if window_id != state.window.id() {
            return;
        }

        match event {
            WindowEvent::CloseRequested => {
                event_loop.exit();
            }
            WindowEvent::Resized(physical_size) => {
                state.config.width = physical_size.width.max(1);
                state.config.height = physical_size.height.max(1);
                state.surface.configure(&state.device, &state.config);
                state.viewport.update(&state.queue, Resolution {
                    width: state.config.width,
                    height: state.config.height,
                });
                
                let elapsed = state.start_time.elapsed().as_secs_f32();
                
                state.queue.write_buffer(
                    &state.bg_uniform_buf,
                    0,
                    bytemuck::cast_slice(&[BgUniforms {
                        resolution: [state.config.width as f32, state.config.height as f32],
                        time: elapsed,
                        mode: if state.mode == AppMode::Home { 0.0 } else { 1.0 },
                    }]),
                );
                
                state.text_buffer.set_size(
                    &mut state.font_system,
                    Some(state.config.width as f32),
                    Some(state.config.height as f32),
                );
                state.window.request_redraw();
            }
            WindowEvent::RedrawRequested => {
                let frame = match state.surface.get_current_texture() {
                    wgpu::CurrentSurfaceTexture::Success(frame) | wgpu::CurrentSurfaceTexture::Suboptimal(frame) => frame,
                    _ => return,
                };
                
                let elapsed = state.start_time.elapsed().as_secs_f32();
                
                state.queue.write_buffer(
                    &state.bg_uniform_buf,
                    0,
                    bytemuck::cast_slice(&[BgUniforms {
                        resolution: [state.config.width as f32, state.config.height as f32],
                        time: elapsed,
                        mode: if state.mode == AppMode::Home { 0.0 } else { 1.0 },
                    }]),
                );
                
                let view = frame
                    .texture
                    .create_view(&wgpu::TextureViewDescriptor::default());

                if state.mode == AppMode::Editing {
                    let show_cursor = (elapsed * 2.0).fract() < 0.5;
                    let cursor = if show_cursor { "|" } else { " " };
                    let display_text = format!("{}{}{}", state.edit_text, state.ime_preedit, cursor);
                    state.text_buffer.set_text(
                        &mut state.font_system,
                        &display_text,
                        &Attrs::new().family(Family::SansSerif),
                        Shaping::Advanced,
                        None,
                    );
                    state.text_buffer.shape_until_scroll(&mut state.font_system, false);
                }

                state
                    .text_renderer
                    .prepare(
                        &state.device,
                        &state.queue,
                        &mut state.font_system,
                        &mut state.text_atlas,
                        &state.viewport,
                        [TextArea {
                            buffer: &state.text_buffer,
                            left: 50.0,
                            top: 60.0,
                            scale: 1.0,
                            bounds: TextBounds {
                                left: 0,
                                top: 0,
                                right: state.config.width as i32,
                                bottom: state.config.height as i32,
                            },
                            default_color: Color::rgb(240, 240, 240),
                            custom_glyphs: &[],
                        }],
                        &mut state.swash_cache,
                    )
                    .unwrap();

                let mut encoder =
                    state
                        .device
                        .create_command_encoder(&wgpu::CommandEncoderDescriptor { label: None });
                {
                    let mut pass = encoder.begin_render_pass(&wgpu::RenderPassDescriptor {
                        label: None,
                        color_attachments: &[Some(wgpu::RenderPassColorAttachment {
                            view: &view,
                            resolve_target: None,
                            ops: wgpu::Operations {
                                load: wgpu::LoadOp::Clear(wgpu::Color::BLACK),
                                store: wgpu::StoreOp::Store,
                            },
                            depth_slice: None,
                        })],
                        depth_stencil_attachment: None,
                        timestamp_writes: None,
                        occlusion_query_set: None,
                        multiview_mask: None,
                    });
                    
                    pass.set_pipeline(&state.bg_pipeline);
                    pass.set_bind_group(0, &state.bg_bind_group, &[]);
                    pass.draw(0..3, 0..1);
                    
                    state.text_renderer.render(&state.text_atlas, &state.viewport, &mut pass).unwrap();
                }

                state.queue.submit(Some(encoder.finish()));
                frame.present();
                
                state.window.request_redraw();
            }
            WindowEvent::CursorMoved { position, .. } => {
                state.cursor_pos = position;
            }
            WindowEvent::MouseInput { state: element_state, button, .. } => {
                if element_state == winit::event::ElementState::Pressed && button == winit::event::MouseButton::Left {
                    if state.mode == AppMode::Home {
                        let fab_x = state.config.width as f64 - 80.0;
                        let fab_y = state.config.height as f64 - 80.0;
                        let dx = state.cursor_pos.x - fab_x;
                        let dy = state.cursor_pos.y - fab_y;
                        if dx*dx + dy*dy <= 30.0*30.0 {
                            state.mode = AppMode::Editing;
                            state.window.set_ime_allowed(true);
                            state.window.request_redraw();
                        }
                    } else if state.mode == AppMode::Editing {
                        let back_x = 30.0;
                        let back_y = 30.0;
                        let dx = state.cursor_pos.x - back_x;
                        let dy = state.cursor_pos.y - back_y;
                        if dx*dx + dy*dy <= 15.0*15.0 {
                            state.mode = AppMode::Home;
                            state.window.set_ime_allowed(false);
                            state.text_buffer.set_text(
                                &mut state.font_system,
                                "锚点笔记 (Anchor Notes)\n\n点击右下角 + 号新建笔记",
                                &Attrs::new().family(Family::SansSerif),
                                Shaping::Advanced,
                                None,
                            );
                            state.text_buffer.shape_until_scroll(&mut state.font_system, false);
                            state.window.request_redraw();
                        }
                    }
                }
            }
            WindowEvent::ModifiersChanged(modifiers) => {
                state.modifiers = modifiers.state();
            }
            WindowEvent::KeyboardInput { event, .. } => {
                if event.state == winit::event::ElementState::Pressed && state.mode == AppMode::Editing {
                    use winit::keyboard::{Key, NamedKey};
                    let ctrl_pressed = state.modifiers.control_key();
                    
                    match &event.logical_key {
                        Key::Character(c) if ctrl_pressed => {
                            if c == "c" || c == "C" {
                                if let Ok(mut clipboard) = arboard::Clipboard::new() {
                                    let _ = clipboard.set_text(state.edit_text.clone());
                                }
                            } else if c == "v" || c == "V" {
                                if let Ok(mut clipboard) = arboard::Clipboard::new() {
                                    if let Ok(text) = clipboard.get_text() {
                                        state.edit_text.push_str(&text);
                                        state.window.request_redraw();
                                    }
                                }
                            } else if c == "x" || c == "X" {
                                if let Ok(mut clipboard) = arboard::Clipboard::new() {
                                    let _ = clipboard.set_text(state.edit_text.clone());
                                    state.edit_text.clear();
                                    state.window.request_redraw();
                                }
                            } else if c == "a" || c == "A" {
                                // 暂未实现完整的视觉选中，这里只做预留
                            }
                        }
                        Key::Named(NamedKey::Backspace) => {
                            let mut chars = state.edit_text.chars();
                            chars.next_back();
                            state.edit_text = chars.as_str().to_string();
                            state.window.request_redraw();
                        }
                        Key::Named(NamedKey::Enter) => {
                            state.edit_text.push('\n');
                            state.window.request_redraw();
                        }
                        _ => {
                            if !ctrl_pressed {
                                if let Some(text) = &event.text {
                                    if text != "\x08" && text != "\r" && text != "\n" {
                                        state.edit_text.push_str(text);
                                        state.window.request_redraw();
                                    }
                                }
                            }
                        }
                    }
                }
            }
            WindowEvent::Ime(ime) => {
                if state.mode == AppMode::Editing {
                    match ime {
                        winit::event::Ime::Commit(text) => {
                            state.edit_text.push_str(&text);
                            state.ime_preedit.clear();
                            state.window.request_redraw();
                        }
                        winit::event::Ime::Preedit(text, _) => {
                            state.ime_preedit = text;
                            state.window.request_redraw();
                        }
                        winit::event::Ime::Enabled | winit::event::Ime::Disabled => {}
                    }
                }
            }
            _ => {}
        }
    }
}

fn main() {
    env_logger::init();
    let event_loop = EventLoop::new().unwrap();
    event_loop.set_control_flow(ControlFlow::Poll);

    let mut app = App::default();
    event_loop.run_app(&mut app).unwrap();
}
