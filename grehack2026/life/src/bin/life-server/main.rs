// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! `life-server`: computes the next generation of the grids it is sent,
//! over cleartext gRPC (spec 0375 S4).

mod engine;
mod tags;

use clap::Parser;
use life::pb::life_server::{Life, LifeServer};
use life::pb::{StepRequest, StepResponse};
use std::net::SocketAddr;
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
    /// For a long-lived client that does not, which a late spy would never
    /// see whole; keep it above that client's renewal period.
    #[arg(long)]
    max_connection_age: Option<u64>,

    /// Print one line per request on stderr, and each request's raw tag bit
    /// field on stdout.
    #[arg(short, long)]
    verbose: bool,

    /// Percentage chance, 0 to 100, that a response carries a random number
    /// for the client to factor, when none was typed on stdin and none is
    /// awaiting its factors.
    #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u8).range(0..=100))]
    self_echo_percentage: u8,
}

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
                // Per request, so only under --verbose (spec 0379 S7).
                if tags::verbose() {
                    eprintln!(
                        "{} {peer} {}x{} generation {} in {} µs",
                        clock(),
                        cells.first().map_or(0, Vec::len),
                        cells.len(),
                        request.generation,
                        started.elapsed().as_micros()
                    );
                }
                Ok(Response::new(StepResponse {
                    grid: Some(engine::grid(&next)),
                    generation: request.generation + 1,
                }))
            }
            Err(engine::Invalid(why)) => {
                eprintln!("{} {peer} refused: {why}", clock());
                Err(Status::invalid_argument(why))
            }
        }
    }
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
    // The factoring exchange (spec 0382): send the number the operator types
    // on stdin, or else maybe a random one, in the next response's tags as
    // "factor <N>"; the client factors it in the background and sends the
    // factors back in a later request's tags, which are checked and printed
    // on stdout. Under --verbose, each request's raw bit field goes to stdout
    // too.
    tags::configure(args.verbose, args.self_echo_percentage);
    life::codec::set_decode_callback(tags::on_request);
    life::codec::set_encode_callback(tags::on_response);
    tags::spawn_stdin_reader();
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
