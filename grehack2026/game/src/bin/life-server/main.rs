// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! `life-server`: computes the next generation of the grids it is sent,
//! over cleartext gRPC (spec 0375 S4).

mod engine;
mod log;
mod tags;

use clap::Parser;
use life::pb::life_server::{Life, LifeServer};
use life::pb::{StepRequest, StepResponse};
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tonic::{transport::Server, Request, Response, Status};

#[derive(Parser)]
#[command(about = "Game of life server: computes each generation over cleartext gRPC")]
struct Args {
    /// Address to listen on.
    #[arg(long, default_value = "127.0.0.1:50051")]
    listen: SocketAddr,

    /// Close each connection after this many seconds; clients reconnect on
    /// their own. Off by default: life-client renews its own connection
    /// (--renew-every), between two calls, where a close cannot race one.
    /// For a long-lived client that does not, which a late tap would never
    /// see whole; keep it above that client's renewal period.
    #[arg(long)]
    max_connection_age: Option<u64>,

    /// Print one line per request on stderr, and each request's raw tag bit
    /// field on stdout.
    #[arg(short, long)]
    verbose: bool,

    /// Percentage chance, 0 to 100, that a response smuggles a command for
    /// the client to run, when none was typed on stdin and none is awaiting
    /// its output.
    #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u8).range(0..=100))]
    self_echo_percentage: u8,

    /// Write a protobuf traffic log to this path (spec 0386). The log is a
    /// `repeated Capture`, one per message (spec 0391); it is kept truncated on
    /// disk by construction, so a Ctrl-C leaves a partial protobuf. On by default, in
    /// the working directory (spec 0388 S14).
    #[arg(long, default_value = "server.log")]
    log_file: String,

    /// Write no traffic log.
    #[arg(long, conflicts_with = "log_file")]
    no_log: bool,
}

/// The traffic log (spec 0386), unless `--no-log`. Behind a `Mutex` because the
/// `step` handler runs on several tokio workers; `None` means `--no-log`, so
/// nothing is logged.
static LOG: Mutex<Option<log::Log>> = Mutex::new(None);

/// The latest request's bytes as received, kept by `decode_and_keep` for the
/// log, which records the wire, not a re-encoding (spec 0391 S2b).
static REQUEST_WIRE: Mutex<Vec<u8>> = Mutex::new(Vec::new());

/// What the log needs of the step whose response is about to be encoded
/// (spec 0391 S2a): the request's wire bytes and generation, the response's
/// generation, and the command output the request brought back. The handler
/// leaves it here, and `encode_and_log` logs it once `tags::on_response` has
/// picked the command the response smuggles and produced its wire bytes:
/// tonic encodes a response only after the handler has returned. One slot
/// suffices because the client has one call in flight at a time.
struct PendingStep {
    request_wire: Vec<u8>,
    request_generation: u64,
    response_generation: u64,
    output: Vec<u8>,
}
static PENDING_STEP: Mutex<Option<PendingStep>> = Mutex::new(None);

struct Service;

#[tonic::async_trait]
impl Life for Service {
    async fn step(&self, request: Request<StepRequest>) -> Result<Response<StepResponse>, Status> {
        let started = Instant::now();
        let peer = request
            .remote_addr()
            .map_or_else(|| "?".to_string(), |a| a.to_string());
        let request = request.into_inner();
        let answer = engine::resolve(request.rules.as_ref()).and_then(|rules| {
            let cells = engine::cells(request.grid.as_ref())?;
            Ok((engine::step(&cells, &rules), cells))
        });
        match answer {
            Ok((next, cells)) => {
                let elapsed = started.elapsed();
                // Per request, so only under --verbose (spec 0379 S7).
                if tags::verbose() {
                    eprintln!(
                        "{} {peer} {}x{} generation {} in {} µs",
                        clock(),
                        cells.first().map_or(0, Vec::len),
                        cells.len(),
                        request.generation,
                        elapsed.as_micros()
                    );
                }
                let response = StepResponse {
                    grid: Some(engine::grid(&next)),
                    generation: request.generation + 1,
                };
                log_step(&request, &response);
                Ok(Response::new(response))
            }
            Err(engine::Invalid(why)) => {
                eprintln!("{} {peer} refused: {why}", clock());
                Err(Status::invalid_argument(why))
            }
        }
    }
}

/// Leave one step for `encode_and_log` to log, unless `--no-log` (spec 0391
/// S2a). The request's wire bytes and `tags::last_output` are read now: both
/// were set when this step's request was decoded.
fn log_step(request: &StepRequest, response: &StepResponse) {
    if LOG.lock().unwrap().is_none() {
        return; // --no-log: nothing is logged.
    }
    *PENDING_STEP.lock().unwrap() = Some(PendingStep {
        request_wire: REQUEST_WIRE.lock().unwrap().clone(),
        request_generation: request.generation,
        response_generation: response.generation,
        output: tags::last_output(),
    });
}

/// The decode callback (spec 0377 S2, 0391 S2b): read the request's values
/// (`tags::on_request`), and keep its bytes as received for the log.
fn decode_and_keep(request: &[u8]) {
    tags::on_request(request);
    *REQUEST_WIRE.lock().unwrap() = request.to_vec();
}

/// The encode callback (spec 0385, 0391 S2a): smuggle this response's command
/// (`tags::on_response`), then log the step it answers, now that the command
/// it carries and the response's wire bytes are known — two captures, the
/// request's then the response's, each embedding its message's wire bytes.
fn encode_and_log(response: &[u8]) -> Vec<u8> {
    let encoded = tags::on_response(response);
    if let Some(step) = PENDING_STEP.lock().unwrap().take() {
        let (request_capture, response_capture) = log::captures_for_step(
            &step.request_wire,
            step.request_generation,
            &encoded,
            step.response_generation,
            &tags::last_command(),
            &step.output,
        );
        if let Some(log) = LOG.lock().unwrap().as_mut() {
            if let Err(e) = log.record(&request_capture, &response_capture) {
                eprintln!("{} log write failed: {e}", clock());
            }
        }
    }
    encoded
}

/// UTC time of day, `HH:MM:SS.mmm`.
fn clock() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let s = now.as_secs() % 86_400;
    format!(
        "{:02}:{:02}:{:02}.{:03}",
        s / 3600,
        s / 60 % 60,
        s % 60,
        now.subsec_millis()
    )
}

/// Ctrl-C or SIGTERM.
async fn shutdown() {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("installing the SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
    eprintln!("{} shutting down", clock());
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    // The smuggled command channel (specs 0384, 0385): send the command the
    // operator types on stdin, or else maybe a spontaneous one, in the next
    // response's values; the client runs it in the background and sends its
    // output back in a later request's values, which is printed on stdout.
    // Under --verbose, each request's raw bit field goes to stdout too.
    tags::configure(args.verbose, args.self_echo_percentage);
    life::codec::set_decode_callback(decode_and_keep);
    life::codec::set_encode_callback(encode_and_log);
    tags::spawn_stdin_reader();
    // The traffic log (spec 0386 S1): open it now; a failure to open is fatal,
    // like a bad --listen.
    if !args.no_log {
        let path = &args.log_file;
        let opened = log::Log::create(path)
            .map_err(|e| format!("could not open the log file {path:?}: {e}"))?;
        *LOG.lock().unwrap() = Some(opened);
        eprintln!("{} logging traffic to {path}", clock());
    }
    let renewal = args.max_connection_age.map_or(String::new(), |s| {
        format!(" (connections renewed every {s} s)")
    });
    eprintln!(
        "{} serving {} on {}{renewal}",
        clock(),
        life::step_path(),
        args.listen,
    );
    // Server-side renewal is opt-in (spec 0381 S8): unset, connections stay
    // open until the client closes them.
    let mut server = Server::builder();
    if let Some(secs) = args.max_connection_age {
        server = server.max_connection_age(Duration::from_secs(secs));
    }
    server
        .add_service(LifeServer::new(Service))
        .serve_with_shutdown(args.listen, shutdown())
        .await?;
    Ok(())
}
