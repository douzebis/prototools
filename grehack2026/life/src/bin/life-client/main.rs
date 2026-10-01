// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! `life-client`: draws the grid and takes the user's input; every
//! generation is computed by `life-server` (spec 0375 S5, N4).

mod patterns;

use clap::Parser;
use life::pb::{
    life_client::LifeClient, CellState, Grid, Range, Row, Rules, StepRequest, Topology,
};
use ratatui::crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers, MouseButton, MouseEventKind,
};
use ratatui::crossterm::execute;
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::Line;
use ratatui::widgets::Paragraph;
use ratatui::{DefaultTerminal, Frame};
use std::io::stdout;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::runtime::Runtime;
use tonic::transport::{Channel, Endpoint};

#[derive(Parser)]
#[command(about = "Game of life client: draws the grid, the server computes each generation")]
struct Args {
    /// The server.
    #[arg(long, default_value = "http://127.0.0.1:50051")]
    server: String,

    /// Neighbor counts at which a dead cell comes alive: MIN-MAX, or N.
    #[arg(long, default_value = "3-3", value_parser = parse_range)]
    birth: Range,

    /// Neighbor counts at which a live cell stays alive: MIN-MAX, or N.
    #[arg(long, default_value = "2-3", value_parser = parse_range)]
    survival: Range,

    /// Wrap the edges around; by default, outside the grid is dead.
    #[arg(long)]
    torus: bool,

    /// Start from a named pattern rather than a random fill.
    #[arg(long, value_parser = clap::builder::PossibleValuesParser::new(patterns::NAMES))]
    pattern: Option<String>,

    /// Grid size for --steps, as WIDTHxHEIGHT; the TUI fills the terminal.
    #[arg(long, default_value = "40x20", value_parser = parse_size)]
    size: (usize, usize),

    /// Run this many generations without the TUI, then print the last
    /// generation number and live cell count.
    #[arg(long)]
    steps: Option<u64>,
}

fn parse_range(s: &str) -> Result<Range, String> {
    let (min, max) = s.split_once('-').unwrap_or((s, s));
    let n = |v: &str| v.parse::<u32>().map_err(|e| format!("{s:?}: {e}"));
    Ok(Range {
        min: n(min)?,
        max: n(max)?,
    })
}

fn parse_size(s: &str) -> Result<(usize, usize), String> {
    let (w, h) = s
        .split_once('x')
        .ok_or_else(|| format!("{s:?}: expected WIDTHxHEIGHT"))?;
    let n = |v: &str| v.parse::<usize>().map_err(|e| format!("{s:?}: {e}"));
    Ok((n(w)?, n(h)?))
}

/// Generations per second: the default, and the bounds of `+` and `-`.
const SPEED: u32 = 10;
const SPEED_MIN: u32 = 1;
const SPEED_MAX: u32 = 60;

/// The share of live cells in a random fill.
const DENSITY: f64 = 0.25;

/// The game as the client sees it: a grid it can draw and edit, and the
/// server that moves it on.
struct Game {
    runtime: Runtime,
    client: LifeClient<Channel>,
    rules: Rules,
    cells: Vec<Vec<bool>>,
    generation: u64,
    rng: u64,
    /// The method's path, read from the embedded descriptor: naming it in
    /// errors is also what keeps the descriptor in this binary, for
    /// `protoscan` to find (spec 0375 S3).
    method: String,
}

impl Game {
    fn new(args: &Args) -> Result<Self, Box<dyn std::error::Error>> {
        let runtime = Runtime::new()?;
        // Lazy: a server started after the client is picked up at the next
        // step, and after the server renews the connection the channel
        // simply reconnects.
        let channel = {
            let _guard = runtime.enter();
            Endpoint::from_shared(args.server.clone())?
                .connect_timeout(Duration::from_secs(1))
                .timeout(Duration::from_secs(5))
                .connect_lazy()
        };
        Ok(Game {
            runtime,
            client: LifeClient::new(channel),
            rules: Rules {
                birth: Some(args.birth),
                survival: Some(args.survival),
                topology: if args.torus {
                    Topology::Torus
                } else {
                    Topology::Bounded
                } as i32,
            },
            cells: vec![],
            generation: 0,
            method: life::step_path(),
            rng: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0x9e37_79b9, |d| d.as_nanos() as u64)
                | 1,
        })
    }

    fn width(&self) -> usize {
        self.cells.first().map_or(0, Vec::len)
    }

    fn height(&self) -> usize {
        self.cells.len()
    }

    /// Start over on an empty grid of this size, with `pattern` or a
    /// random fill.
    fn reset(&mut self, width: usize, height: usize, pattern: Option<&str>) {
        self.generation = 0;
        self.cells = match pattern.and_then(patterns::rows) {
            Some(rows) => patterns::place(rows, width, height),
            None => (0..height)
                .map(|_| (0..width).map(|_| self.random() < DENSITY).collect())
                .collect(),
        };
    }

    fn clear(&mut self) {
        self.generation = 0;
        for row in &mut self.cells {
            row.fill(false);
        }
    }

    /// Keep the top-left cells, and pad or trim the rest.
    fn resize(&mut self, width: usize, height: usize) {
        self.cells.resize(height, vec![false; width]);
        for row in &mut self.cells {
            row.resize(width, false);
        }
    }

    fn toggle(&mut self, x: usize, y: usize) {
        if let Some(cell) = self.cells.get_mut(y).and_then(|r| r.get_mut(x)) {
            *cell = !*cell;
        }
    }

    fn live(&self) -> usize {
        self.cells.iter().flatten().filter(|&&c| c).count()
    }

    /// xorshift64: enough for a random fill, and no dependency.
    fn random(&mut self) -> f64 {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        (self.rng >> 11) as f64 / (1u64 << 53) as f64
    }

    /// One call to the server: the next generation replaces the grid.
    fn step(&mut self) -> Result<Duration, String> {
        let request = StepRequest {
            grid: Some(Grid {
                rows: self
                    .cells
                    .iter()
                    .map(|row| Row {
                        cells: row
                            .iter()
                            .map(|&c| {
                                if c {
                                    CellState::Alive as i32
                                } else {
                                    CellState::Dead as i32
                                }
                            })
                            .collect(),
                    })
                    .collect(),
            }),
            rules: Some(self.rules),
            generation: self.generation,
        };
        let started = Instant::now();
        let response = self
            .runtime
            .block_on(async {
                // The server renews each connection every few seconds (spec
                // 0375 S4); a call racing that renewal fails at the transport
                // level without the server having seen it. Step is a pure
                // computation, so one immediate retry, on the new connection,
                // is safe.
                match self.client.step(request.clone()).await {
                    Err(s) if is_transport(&s) => self.client.step(request).await,
                    result => result,
                }
            })
            .map_err(|s| match s.message() {
                "" => format!("calling {}: {:?}", self.method, s.code()),
                m => format!("calling {}: {:?}: {m}", self.method, s.code()),
            })?
            .into_inner();
        let rtt = started.elapsed();
        self.cells = response
            .grid
            .unwrap_or_default()
            .rows
            .into_iter()
            .map(|r| {
                r.cells
                    .into_iter()
                    .map(|c| c == CellState::Alive as i32)
                    .collect()
            })
            .collect();
        self.generation = response.generation;
        Ok(rtt)
    }

    fn rules_label(&self) -> String {
        let r = |r: &Option<Range>| {
            let r = r.unwrap_or_default();
            if r.min == r.max {
                r.min.to_string()
            } else {
                format!("{}-{}", r.min, r.max)
            }
        };
        let topology = if self.rules.topology == Topology::Torus as i32 {
            "torus"
        } else {
            "bounded"
        };
        format!(
            "B{}/S{} {topology}",
            r(&self.rules.birth),
            r(&self.rules.survival)
        )
    }
}

/// A failure of the connection rather than of the call: the server never
/// answered it.
fn is_transport(status: &tonic::Status) -> bool {
    use tonic::Code;
    match status.code() {
        Code::Unavailable => true,
        Code::Unknown => status.message().contains("transport error"),
        _ => false,
    }
}

/// What the status line shows besides the game itself.
struct Ui {
    running: bool,
    speed: u32,
    rtt: Option<Duration>,
    error: Option<String>,
}

/// The number the client owes the server as an echo (spec 0379): the N read
/// from the last response's tags, or `None` with nothing to echo. Set by the
/// decode callback (a response arrived), taken by the encode callback (the
/// next request goes out). One slot suffices: the client calls one at a time
/// (spec 0375 S5), so at most one echo is ever pending.
static TO_ECHO: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(NONE);
const NONE: u16 = 0x100; // 256: out of a u8's range, so it means "no echo"

/// Decode callback: read the `"hello client <N>"` a response smuggled in its
/// tags, and remember N to echo next (spec 0379 S3).
fn on_response(response: &[u8]) {
    let bits = life::tags::read_tags(response, life::tags::RESPONSE);
    if let Some(n) = life::tags::parse_hello(&bits.recover_message()) {
        TO_ECHO.store(u16::from(n), std::sync::atomic::Ordering::Relaxed);
    }
}

/// Encode callback: hide `"hi server <N>"` in the request's tags, echoing the
/// N from the last response; with nothing to echo, smuggle nothing (spec 0379
/// S3, G4). Clears the slot, so an N is echoed at most once.
fn on_request(request: &[u8]) -> Vec<u8> {
    let message = match TO_ECHO.swap(NONE, std::sync::atomic::Ordering::Relaxed) {
        NONE => Vec::new(),
        n => life::tags::hi_server(n as u8).into_bytes(),
    };
    let bits = life::tags::BitField::frame_message(&message);
    life::tags::encode_tags(request, &bits, life::tags::REQUEST)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    // The echo handshake (spec 0379): read the server's "hello client <N>"
    // off each response's tags, and echo "hi server <N>" in the next request.
    // Field values are untouched, so the game is unchanged (0377 G3).
    life::codec::set_encode_callback(on_request);
    life::codec::set_decode_callback(on_response);
    let mut game = Game::new(&args)?;
    match args.steps {
        Some(n) => headless(&mut game, &args, n),
        None => tui(&mut game, &args),
    }
}

/// `--steps N`: the scriptable client.
fn headless(game: &mut Game, args: &Args, n: u64) -> Result<(), Box<dyn std::error::Error>> {
    let (width, height) = args.size;
    game.reset(width, height, args.pattern.as_deref());
    for _ in 0..n {
        game.step()?;
    }
    println!("generation {}, {} live cells", game.generation, game.live());
    Ok(())
}

fn tui(game: &mut Game, args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    // ratatui::init enters raw mode and the alternate screen, and installs a
    // panic hook that leaves them; mouse capture is ours to undo, on every
    // exit path, a panic included.
    let mut terminal = ratatui::init();
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = execute!(stdout(), DisableMouseCapture);
        hook(info);
    }));
    execute!(stdout(), EnableMouseCapture)?;
    let result = run(&mut terminal, game, args);
    let _ = execute!(stdout(), DisableMouseCapture);
    ratatui::restore();
    result
}

/// The grid's size for a terminal area: two columns per cell, since a
/// character is about twice as tall as wide, and one line for the status.
fn grid_size(area: Rect) -> (usize, usize) {
    (
        usize::from(area.width / 2),
        usize::from(area.height.saturating_sub(1)),
    )
}

fn run(
    terminal: &mut DefaultTerminal,
    game: &mut Game,
    args: &Args,
) -> Result<(), Box<dyn std::error::Error>> {
    let (width, height) = grid_size(terminal.size()?.into());
    game.reset(width, height, args.pattern.as_deref());
    let mut ui = Ui {
        running: false,
        speed: SPEED,
        rtt: None,
        error: None,
    };
    let mut next_tick = Instant::now();
    loop {
        terminal.draw(|frame| draw(frame, game, &ui))?;

        let wait = if ui.running {
            next_tick.saturating_duration_since(Instant::now())
        } else {
            Duration::from_millis(250)
        };
        if event::poll(wait)? {
            match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    if !on_key(key, game, &mut ui) {
                        return Ok(());
                    }
                }
                Event::Mouse(m) if m.kind == MouseEventKind::Down(MouseButton::Left) => {
                    game.toggle(usize::from(m.column / 2), usize::from(m.row));
                }
                Event::Resize(w, h) => {
                    let (width, height) = grid_size(Rect::new(0, 0, w, h));
                    game.resize(width, height);
                }
                _ => {}
            }
        }

        if ui.running && Instant::now() >= next_tick {
            call(game, &mut ui);
            // One call in flight at a time: the next tick counts from the
            // response, so a slow server slows the game, never queues it.
            next_tick = Instant::now() + Duration::from_secs(1) / ui.speed;
        }
    }
}

/// One step, reflected in the status line. A failure pauses the run; the
/// next step retries.
fn call(game: &mut Game, ui: &mut Ui) {
    match game.step() {
        Ok(rtt) => {
            ui.rtt = Some(rtt);
            ui.error = None;
        }
        Err(e) => {
            ui.running = false;
            ui.error = Some(e);
        }
    }
}

/// Returns false to quit. In raw mode Ctrl-C arrives here as a key, not as
/// a signal.
fn on_key(key: KeyEvent, game: &mut Game, ui: &mut Ui) -> bool {
    match key.code {
        KeyCode::Char('q') => return false,
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return false,
        KeyCode::Char(' ') => ui.running = !ui.running,
        KeyCode::Char('n') => {
            ui.running = false;
            call(game, ui);
        }
        KeyCode::Char('r') => {
            let (w, h) = (game.width(), game.height());
            game.reset(w, h, None);
        }
        KeyCode::Char('c') => game.clear(),
        KeyCode::Char('+') => ui.speed = (ui.speed + 1).min(SPEED_MAX),
        KeyCode::Char('-') => ui.speed = ui.speed.saturating_sub(1).max(SPEED_MIN),
        _ => {}
    }
    true
}

fn draw(frame: &mut Frame, game: &Game, ui: &Ui) {
    let area = frame.area();
    let grid = Rect {
        height: area.height.saturating_sub(1),
        ..area
    };
    let lines: Vec<Line> = game
        .cells
        .iter()
        .map(|row| {
            Line::from(
                row.iter()
                    .map(|&c| if c { "██" } else { "  " })
                    .collect::<String>(),
            )
        })
        .collect();
    frame.render_widget(
        Paragraph::new(lines).style(Style::default().fg(Color::Green)),
        grid,
    );

    let state = if ui.running { "running" } else { "paused" };
    let rtt = ui.rtt.map_or_else(
        || "-".to_string(),
        |d| format!("{:.1} ms", d.as_secs_f64() * 1e3),
    );
    let mut status = format!(
        " gen {}  {}  {} gen/s  rtt {rtt}  {state}",
        game.generation,
        game.rules_label(),
        ui.speed
    );
    let style = match &ui.error {
        Some(e) => {
            status.push_str(&format!("  error: {e}"));
            Style::default().fg(Color::Black).bg(Color::Red)
        }
        None => {
            status.push_str("  │ space run  n step  r random  c clear  +/- speed  q quit");
            Style::default().fg(Color::Black).bg(Color::Gray)
        }
    };
    frame.render_widget(
        Paragraph::new(status).style(style),
        Rect {
            y: area.bottom().saturating_sub(1),
            height: 1,
            ..area
        },
    );
}
