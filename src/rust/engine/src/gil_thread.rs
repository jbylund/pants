// Copyright 2026 Pants project contributors (see CONTRIBUTORS.md).
// Licensed under the Apache License, Version 2.0 (see LICENSE).

//! A dedicated thread which owns the GIL and runs short Python jobs back to back.
//!
//! When many tokio workers each attach to the interpreter for a few microseconds at a time, most
//! of their time goes to handing the GIL between OS threads (a condvar wake and a context switch
//! per handoff), and the workers are blocked in `take_gil` instead of running native work. Routing
//! the hot attach sites through one thread keeps the GIL on that thread while jobs are queued, so
//! handoffs only happen when it runs out of work (or periodically yields to other attachers).
//!
//! On a free-threaded interpreter there is no GIL to hand around, so the thread is not used.

use std::any::Any;
use std::cell::Cell;
use std::collections::HashMap;
use std::panic::{self, AssertUnwindSafe};
use std::sync::mpsc;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crossbeam_channel::{Receiver, Sender, TryRecvError};
use internment::Intern;
use pyo3::prelude::PyAnyMethods;
use pyo3::{Py, PyAny, Python};

use crate::nodes::{sync_task_context, task_is_side_effecting, try_task_context};

type Job = Box<dyn FnOnce(Python<'_>) + Send>;

tokio::task_local! {
    /// The @rule whose Python code the current tokio task runs.
    pub static RULE_LABEL: Intern<crate::tasks::Task>;
}

/// How long the thread keeps the GIL while waiting for the next job before detaching.
const SPIN: Duration = Duration::from_micros(50);
/// How long the thread may run jobs before briefly detaching to let other attachers in.
const SLICE: Duration = Duration::from_millis(2);
/// Wakes the GIL thread's idle wait at least this often, to release objects sent to it.
const IDLE_WAKE: Duration = Duration::from_millis(100);
/// How many jobs a rule may run while its jobs are still considered urgent.
const URGENT_JOBS_PER_RULE: u32 = 64;

struct Channels {
    jobs: Sender<Job>,
    /// Jobs of rules which have run few jobs so far, run before any queued `jobs`. Rules which run
    /// many jobs flood the queue; a rule which runs few is typically a step of a chain (such as
    /// downloads and processes for a tool), whose latency would otherwise include the whole queue.
    urgent_jobs: Sender<Job>,
    releases: mpsc::Sender<Py<PyAny>>,
}

static CHANNELS: OnceLock<Option<Channels>> = OnceLock::new();

thread_local! {
    static ON_GIL_THREAD: Cell<bool> = const { Cell::new(false) };
}

fn is_urgent(label: Option<Intern<crate::tasks::Task>>) -> bool {
    static JOB_COUNTS: OnceLock<Mutex<HashMap<usize, u32>>> = OnceLock::new();
    let Some(task) = label else {
        return false;
    };
    let key = &*task as *const crate::tasks::Task as usize;
    let mut counts = JOB_COUNTS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .expect("Not poisoned.");
    let count = counts.entry(key).or_insert(0);
    *count = count.saturating_add(1);
    *count <= URGENT_JOBS_PER_RULE
}

/// Whether this interpreter has an enabled GIL (a free-threaded build, or a GIL build run with
/// `PYTHON_GIL=0`, has none).
fn gil_enabled() -> bool {
    Python::attach(|py| {
        py.import("sys")
            .and_then(|sys| sys.call_method0("_is_gil_enabled"))
            .and_then(|enabled| enabled.extract::<bool>())
            // Interpreters without `sys._is_gil_enabled` (before 3.13) always have a GIL.
            .unwrap_or(true)
    })
}

fn channels() -> Option<&'static Channels> {
    CHANNELS
        .get_or_init(|| {
            if std::env::var("PANTS_ENGINE_GIL_THREAD").is_ok_and(|v| v == "0") || !gil_enabled() {
                return None;
            }
            let (jobs_tx, jobs_rx) = crossbeam_channel::unbounded::<Job>();
            let (urgent_tx, urgent_rx) = crossbeam_channel::unbounded::<Job>();
            let (releases_tx, releases_rx) = mpsc::channel::<Py<PyAny>>();
            std::thread::Builder::new()
                .name("pants-gil".to_owned())
                .spawn(move || run(urgent_rx, jobs_rx, releases_rx))
                .expect("Failed to spawn the GIL thread.");
            Some(Channels {
                jobs: jobs_tx,
                urgent_jobs: urgent_tx,
                releases: releases_tx,
            })
        })
        .as_ref()
}

/// Whether hot Python steps run on the GIL thread.
pub fn enabled() -> bool {
    channels().is_some()
}

/// Release a Python object: directly on the GIL thread, otherwise by sending it there.
pub fn release(obj: Py<PyAny>) {
    if ON_GIL_THREAD.get() {
        drop(obj);
        return;
    }
    match channels() {
        Some(channels) => {
            if let Err(mpsc::SendError(obj)) = channels.releases.send(obj) {
                drop(obj);
            }
        }
        None => drop(obj),
    }
}

/// The next job, urgent ones first.
fn try_next(
    urgent: &Receiver<Job>,
    rx: &Receiver<Job>,
) -> Result<Job, TryRecvError> {
    match urgent.try_recv() {
        Ok(job) => Ok(job),
        Err(TryRecvError::Empty) => rx.try_recv(),
        Err(TryRecvError::Disconnected) => Err(TryRecvError::Disconnected),
    }
}

/// Waits up to `timeout` for the next job, urgent ones first.
fn recv_next(
    urgent: &Receiver<Job>,
    rx: &Receiver<Job>,
    timeout: Duration,
) -> Result<Job, crossbeam_channel::RecvTimeoutError> {
    crossbeam_channel::select! {
        recv(urgent) -> job => job.map_err(|_| crossbeam_channel::RecvTimeoutError::Disconnected),
        recv(rx) -> job => job.map_err(|_| crossbeam_channel::RecvTimeoutError::Disconnected),
        default(timeout) => Err(crossbeam_channel::RecvTimeoutError::Timeout),
    }
}

fn run(
    urgent: Receiver<Job>,
    rx: Receiver<Job>,
    releases: mpsc::Receiver<Py<PyAny>>,
) {
    ON_GIL_THREAD.set(true);
    Python::attach(|py| {
        let mut slice_start = Instant::now();
        let mut idle_since: Option<Instant> = None;
        loop {
            while let Ok(obj) = releases.try_recv() {
                drop(obj);
            }
            let job = match try_next(&urgent, &rx) {
                Ok(job) => job,
                Err(TryRecvError::Empty) => {
                    let since = *idle_since.get_or_insert_with(Instant::now);
                    if since.elapsed() <= SPIN {
                        std::hint::spin_loop();
                        continue;
                    }
                    match py.detach(|| recv_next(&urgent, &rx, IDLE_WAKE)) {
                        Ok(job) => {
                            slice_start = Instant::now();
                            job
                        }
                        Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                            idle_since = None;
                            continue;
                        }
                        Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
                    }
                }
                Err(TryRecvError::Disconnected) => break,
            };
            idle_since = None;
            job(py);
            if slice_start.elapsed() > SLICE {
                py.detach(std::thread::yield_now);
                slice_start = Instant::now();
            }
        }
    });
}

/// Run `f` with the GIL held on the GIL thread, preserving the caller's task context, workunit
/// store handle and stdio destination. Falls back to attaching on the calling thread if the GIL
/// thread is disabled or the caller is a side-effecting task (whose Python code may block in place
/// on engine work which itself runs Python).
pub async fn run_py<R, F>(f: F) -> R
where
    R: Send + 'static,
    F: FnOnce(Python<'_>) -> R + Send + 'static,
{
    let Some(channels) = channels() else {
        return Python::attach(f);
    };
    if task_is_side_effecting() {
        return Python::attach(f);
    }
    let (result_tx, result_rx) = tokio::sync::oneshot::channel::<Result<R, Box<dyn Any + Send>>>();
    let workunit_store_handle = workunit_store::get_workunit_store_handle();
    let stdio_destination = stdio::get_destination();
    let task_context = try_task_context();
    let job: Job = Box::new(move |py| {
        workunit_store::set_thread_workunit_store_handle(workunit_store_handle);
        stdio::set_thread_destination(stdio_destination);
        let result = panic::catch_unwind(AssertUnwindSafe(|| match task_context {
            Some(context) => sync_task_context(context, || f(py)),
            None => f(py),
        }));
        workunit_store::set_thread_workunit_store_handle(None);
        let _ = result_tx.send(result);
    });
    let label = RULE_LABEL.try_with(|task| *task).ok();
    let tx = if is_urgent(label) {
        &channels.urgent_jobs
    } else {
        &channels.jobs
    };
    tx.send(job)
        .expect("The GIL thread exited.");
    match result_rx.await.expect("The GIL thread dropped a job.") {
        Ok(result) => result,
        Err(panic_payload) => panic::resume_unwind(panic_payload),
    }
}
