// SPDX-FileCopyrightText: Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Zero-copy loading of a CompiledGraph binary (spec 0047 §5).

use std::path::Path;

use memmap2::Mmap;
use rkyv::{access, api::access_unchecked, util::AlignedVec};

use crate::build_scoring_graph::serial::ArchivedCompiledGraph;

const MAGIC: &[u8; 8] = b"PTSGRAPH";

enum GraphBacking {
    Mmap { _mmap: Mmap },
    Aligned, // copy leaked into aligned heap allocation
}

pub struct LoadedGraph {
    _backing: GraphBacking,
    /// Zero-copy view into the backing storage.
    pub graph: &'static ArchivedCompiledGraph,
}

impl std::ops::Deref for LoadedGraph {
    type Target = ArchivedCompiledGraph;
    fn deref(&self) -> &Self::Target {
        self.graph
    }
}

fn check_header(bytes: &[u8], label: &str) -> Result<usize, Box<dyn std::error::Error>> {
    if bytes.len() < 24 {
        return Err(format!("{label}: file too short").into());
    }
    if &bytes[0..8] != MAGIC {
        return Err(format!("{label}: bad magic").into());
    }
    let version = u32::from_le_bytes(bytes[8..12].try_into()?);
    if version != 2 {
        return Err(format!("{label}: unsupported version {version}").into());
    }
    let root_offset = u64::from_le_bytes(bytes[16..24].try_into()?) as usize;
    Ok(root_offset)
}

impl LoadedGraph {
    /// Construct a `LoadedGraph` from a `'static` byte slice (e.g. from
    /// `include_bytes!`).  Copies into a leaked `AlignedVec` so that rkyv's
    /// alignment requirements are satisfied in both debug and release builds.
    pub fn from_static_bytes(bytes: &'static [u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let root_offset = check_header(bytes, "<embedded>")?;
        // Copy into an aligned allocation so that rkyv's debug-mode alignment
        // assert passes.  include_bytes! gives only 1-byte alignment, which
        // satisfies release builds (access_unchecked skips the check) but
        // triggers a debug_assert in rkyv 0.8.x.  Leaking the AlignedVec gives
        // a 'static reference, matching the field type on LoadedGraph.
        let mut aligned = AlignedVec::<16>::new();
        aligned.extend_from_slice(&bytes[root_offset..]);
        let aligned: &'static [u8] = Box::leak(aligned.into_boxed_slice());
        // Safety: bytes were written by rkyv::to_bytes with the same types and
        // we validated magic + version above.  The buffer is now correctly
        // aligned, so access_unchecked's preconditions are satisfied.
        let graph: &'static ArchivedCompiledGraph =
            unsafe { access_unchecked::<ArchivedCompiledGraph>(aligned) };
        Ok(LoadedGraph {
            _backing: GraphBacking::Aligned,
            graph,
        })
    }
}

pub fn load_graph(path: &Path) -> Result<LoadedGraph, Box<dyn std::error::Error>> {
    let file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mmap = unsafe { Mmap::map(&file) }.map_err(|e| format!("{}: {e}", path.display()))?;

    let root_offset = check_header(&mmap, &path.display().to_string())?;

    // Safety: the bytes were written by rkyv::to_bytes with the same types.
    // We extend the lifetime to 'static, which is safe as long as _mmap lives
    // as long as graph — enforced by keeping both in LoadedGraph.
    let graph: &'static ArchivedCompiledGraph = unsafe {
        let bytes: &'static [u8] =
            std::slice::from_raw_parts(mmap.as_ptr().add(root_offset), mmap.len() - root_offset);
        access::<ArchivedCompiledGraph, rkyv::rancor::Error>(bytes)
            .map_err(|e| format!("{}: rkyv access failed: {e}", path.display()))?
    };

    Ok(LoadedGraph {
        _backing: GraphBacking::Mmap { _mmap: mmap },
        graph,
    })
}
