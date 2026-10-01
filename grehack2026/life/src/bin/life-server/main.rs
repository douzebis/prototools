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
    /// their own. A capture started mid-connection cannot decode gRPC, so
    /// this bounds how long a late spy waits.
    #[arg(long, default_value_t = 10)]
    max_connection_age: u64,
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
                eprintln!(
                    "{} {peer} {}x{} generation {} in {} µs",
                    clock(),
                    cells.first().map_or(0, Vec::len),
                    cells.len(),
                    request.generation,
                    started.elapsed().as_micros()
                );
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
    // The echo handshake (spec 0379): read each request's tags (the verdicts
    // to stdout, the echo checked) and smuggle a fresh "hello client <N>" into
    // every response. The client echoes it back in its next request.
    life::codec::set_decode_callback(tags::on_request);
    life::codec::set_encode_callback(tags::on_response);
    eprintln!(
        "{} serving {} on {} (connections renewed every {} s)",
        clock(),
        life::step_path(),
        args.listen,
        args.max_connection_age
    );
    Server::builder()
        .max_connection_age(Duration::from_secs(args.max_connection_age))
        .add_service(LifeServer::new(Service))
        .serve_with_shutdown(args.listen, shutdown())
        .await?;
    Ok(())
}
