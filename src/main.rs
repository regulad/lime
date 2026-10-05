//! lime: unlock FileVault-encrypted Macs over macOS's pre-boot SSH unlock.
//!
//! lime browses mDNS (systemd-resolved's Varlink `BrowseServices`) for `_ssh._tcp` on
//! the configured interfaces and connects to each server that appears. Only a server
//! presenting one of a configured Mac's host keys gets more than a handshake.
//!
//! lime then logs in as that Mac's unlock account, answering its single hidden
//! keyboard-interactive prompt with the account's password:
//!
//! - At the pre-boot unlock, that unlocks the disk. Apple's `pam_basesystem` says so
//!   mid-login and pivots into macOS mid-connection. lime treats that message, or a
//!   close or hang after the password, as the unlock, and drops the connection.
//! - A booted Mac completes the login, and its drop-in turns the account away
//!   (`ForceCommand /usr/bin/false`, no forwarding); lime disconnects without opening
//!   a session.
//!
//! The same drop-in limits the account to keyboard-interactive on a booted Mac. The
//! pre-boot server can't read it and offers its defaults, so lime knows which stage
//! refused a password. See README.md.

use std::{
    collections::HashMap,
    net::{SocketAddr, SocketAddrV6},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, bail};
use futures_util::{Stream, StreamExt, pin_mut};
use russh::{
    Disconnect, MethodKind,
    client::{self, AuthResult, KeyboardInteractiveAuthResponse as Kbd},
    keys::{PublicKey, PublicKeyOrCertificate},
};
use serde::Deserialize;
use tokio::{sync::mpsc, time};

const RESOLVE: &str = "/run/systemd/resolve/io.systemd.Resolve";
const SSH: &str = "_ssh._tcp";
const TIMEOUT: Duration = Duration::from_secs(20);
/// The text `pam_basesystem` sends once the pre-boot unlock has succeeded.
const UNLOCKED: &str = "System successfully unlocked.";

/// Logs to stderr with a sd-daemon(3) priority prefix, which journald turns into
/// the entry's priority.
macro_rules! log {
    ($priority:literal, $($arg:tt)*) => { eprintln!("<{}>{}", $priority, format_args!($($arg)*)) };
}

// --- configuration ------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    /// Network interfaces to browse mDNS on.
    interfaces: Vec<String>,
    /// Seconds before a Mac that's up and working is checked again (default 30), as
    /// is one that couldn't be checked, such as a Mac still starting.
    heartbeat: Option<u64>,
    /// Seconds before a Mac that refused is first tried again (default 900). Doubles
    /// while it keeps refusing.
    base_retry: Option<u64>,
    /// Upper bound for that backoff (default 21600).
    max_retry: Option<u64>,
    mac: Vec<Mac>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Mac {
    /// A label for logs and for its password credential, `lime.<name>`.
    name: String,
    /// The hidden, FileVault-enabled account that answers the pre-boot unlock.
    unlock_user: String,
    /// Every host key the Mac has. Any one of them identifies it.
    host_keys: Vec<String>,
    #[serde(skip)]
    pinned: Vec<PublicKey>,
}

struct Ctx {
    macs: Arc<Vec<Mac>>,
    ssh: Arc<client::Config>,
    state: PathBuf,
    heartbeat: u64,
    base_retry: u64,
    max_retry: u64,
    dry_run: bool,
}

/// Reads a credential that systemd placed in this service's private
/// `$CREDENTIALS_DIRECTORY` (`ImportCredential=lime.*`).
fn credential(name: &str) -> Result<String> {
    let dir = std::env::var_os("CREDENTIALS_DIRECTORY")
        .context("$CREDENTIALS_DIRECTORY is unset; run lime under systemd with ImportCredential=lime.*")?;
    let text = std::fs::read_to_string(Path::new(&dir).join(name)).with_context(|| format!("reading credential {name}"))?;
    Ok(text.strip_suffix('\n').unwrap_or(&text).to_owned())
}

fn load(path: &str, dry_run: bool) -> Result<(Vec<String>, Ctx)> {
    let cfg: Config = toml::from_str(&std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?)
        .with_context(|| format!("parsing {path}"))?;
    if cfg.interfaces.is_empty() || cfg.mac.is_empty() {
        bail!("{path} needs at least one interface and one [[mac]]");
    }
    let mut macs = cfg.mac;
    for mac in &mut macs {
        let keys = mac.host_keys.iter().map(|k| PublicKey::from_openssh(k).with_context(|| format!("{}: bad host key {k:?}", mac.name)));
        mac.pinned = keys.collect::<Result<_>>()?;
        if mac.pinned.is_empty() {
            bail!("{}: needs at least one host key", mac.name);
        }
    }
    let state = std::env::var_os("STATE_DIRECTORY").map_or_else(|| PathBuf::from("/var/lib/lime"), PathBuf::from);
    let ssh = client::Config { inactivity_timeout: Some(TIMEOUT), ..Default::default() };
    let heartbeat = cfg.heartbeat.unwrap_or(30);
    let base_retry = cfg.base_retry.unwrap_or(900);
    let max_retry = cfg.max_retry.unwrap_or(21600).max(base_retry);
    let ctx = Ctx { macs: Arc::new(macs), ssh: Arc::new(ssh), state, heartbeat, base_retry, max_retry, dry_run };
    Ok((cfg.interfaces, ctx))
}

// --- discovery: systemd-resolved over Varlink ---------------------------------

#[zlink::proxy("io.systemd.Resolve")]
trait Resolve {
    #[zlink(more)]
    async fn browse_services(
        &mut self,
        domain: &str,
        r#type: &str,
        ifindex: i32,
    ) -> zlink::Result<impl Stream<Item = zlink::Result<Result<Browsed, ResolveError>>>>;
    async fn resolve_service(
        &mut self,
        name: &str,
        r#type: &str,
        domain: &str,
        ifindex: i32,
    ) -> zlink::Result<Result<Resolved, ResolveError>>;
}

#[derive(Debug, zlink::ReplyError)]
#[zlink(interface = "io.systemd.Resolve")]
enum ResolveError {
    NoSuchResourceRecord,
    QueryTimedOut,
    NetworkDown,
    NoNameServers,
    MaxAttemptsReached,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Browsed {
    browser_service_data: Vec<ServiceData>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ServiceData {
    update_flag: Update,
    name: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum Update {
    Added,
    Removed,
}

#[derive(Debug, Deserialize)]
struct Resolved {
    services: Vec<SrvRecord>,
}

#[derive(Debug, Deserialize)]
struct SrvRecord {
    port: u16,
    addresses: Option<Vec<Address>>,
}

#[derive(Debug, Deserialize)]
struct Address {
    address: Vec<u8>,
}

/// One announcement or withdrawal of an SSH server on an interface.
struct Event {
    ifindex: i32,
    name: String,
    added: bool,
}

/// Streams the SSH servers' comings and goings on one interface.
async fn watch(ifindex: i32, tx: &mpsc::Sender<Event>) -> Result<()> {
    let mut conn = zlink::tokio::unix::connect(RESOLVE).await.context("connecting to systemd-resolved")?;
    let stream = conn.browse_services("local", SSH, ifindex).await?;
    pin_mut!(stream);
    while let Some(reply) = stream.next().await {
        let reply = reply?.map_err(|e| anyhow!("BrowseServices: {e:?}"))?;
        for s in reply.browser_service_data {
            let Some(name) = s.name else { continue };
            tx.send(Event { ifindex, name, added: s.update_flag == Update::Added }).await?;
        }
    }
    bail!("BrowseServices ended")
}

/// Resolves an `_ssh._tcp` instance to an address, preferring IPv4: an IPv6 answer
/// is often link-local, which works too, but only with the interface as its scope.
async fn resolve(conn: &mut zlink::Connection<zlink::tokio::unix::Stream>, ifindex: i32, name: &str) -> Result<SocketAddr> {
    let resolved = conn.resolve_service(name, SSH, "local", ifindex).await?.map_err(|e| anyhow!("{e:?}"))?;
    let srv = resolved.services.first().context("no SRV record")?;
    let addrs = srv.addresses.as_deref().unwrap_or_default();
    let v4 = addrs.iter().find_map(|a| <[u8; 4]>::try_from(a.address.as_slice()).ok());
    let v6 = addrs.iter().find_map(|a| <[u8; 16]>::try_from(a.address.as_slice()).ok());
    match (v4, v6) {
        (Some(ip), _) => Ok(SocketAddr::from((ip, srv.port))),
        (None, Some(ip)) => Ok(SocketAddr::V6(SocketAddrV6::new(ip.into(), srv.port, 0, ifindex as u32))),
        (None, None) => bail!("no address"),
    }
}

// --- SSH: identify and unlock ---------------------------------------------------

/// Accepts a server only if it presents a configured Mac's host key, and notes
/// which Mac. Also watches for the pre-boot unlock's success banner.
struct Identify {
    macs: Arc<Vec<Mac>>,
    matched: Arc<Mutex<Option<usize>>>,
    unlocked: Arc<AtomicBool>,
}

impl client::Handler for Identify {
    type Error = russh::Error;

    async fn check_server_key(&mut self, offered: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        let PublicKeyOrCertificate::PublicKey { key, .. } = offered else { return Ok(false) };
        let found = self.macs.iter().position(|m| m.pinned.iter().any(|p| p.key_data() == key.key_data()));
        *self.matched.lock().unwrap() = found;
        Ok(found.is_some())
    }

    /// SSH_MSG_USERAUTH_BANNER: sshd's own message during authentication, which
    /// nothing the account runs can produce. A real Mac sends the unlock's success
    /// text in a keyboard-interactive round instead (`says_unlocked`); lime takes it
    /// from a banner too.
    async fn auth_banner(&mut self, banner: &str, _: &mut client::Session) -> Result<(), Self::Error> {
        if banner.contains(UNLOCKED) {
            self.unlocked.store(true, Ordering::Release);
        }
        Ok(())
    }
}

/// Connects, returning the session and which Mac it is, or `None` if the server's
/// host key belongs to no configured Mac.
async fn connect(ctx: &Ctx, addr: SocketAddr, unlocked: &Arc<AtomicBool>) -> Result<Option<(client::Handle<Identify>, usize)>> {
    let matched = Arc::new(Mutex::new(None));
    let handler = Identify { macs: ctx.macs.clone(), matched: matched.clone(), unlocked: unlocked.clone() };
    match time::timeout(TIMEOUT, client::connect(ctx.ssh.clone(), addr, handler)).await {
        Err(_) => bail!("timed out connecting"),
        Ok(Err(russh::Error::UnknownKey)) => Ok(None),
        Ok(Err(e)) => Err(e.into()),
        Ok(Ok(handle)) => Ok(matched.lock().unwrap().map(|mac| (handle, mac))),
    }
}

/// What a visit found. Anything else (an `Err`) is a misconfiguration or a fault,
/// such as a Mac that stalls mid-login while it starts up; no password was refused.
enum Outcome {
    /// Booted: it accepted the password and turned the account away.
    Booted,
    /// At the pre-boot unlock. Dry run only: the password was not sent.
    Locked,
    /// The pre-boot unlock accepted the password and is starting macOS.
    Unlocked,
    /// The password was refused, and why: at the pre-boot unlock, or by a booted Mac.
    Refused { why: String, booted: bool },
}

/// Whether a keyboard-interactive round carries `pam_basesystem`'s success text.
/// OpenSSH passes PAM's text messages on as a round's instruction (as a Mac at the
/// pre-boot unlock does, in a round with no prompts), or ahead of its next prompt.
fn says_unlocked(round: &Kbd) -> bool {
    let Kbd::InfoRequest { instructions, prompts, .. } = round else { return false };
    instructions.contains(UNLOCKED) || prompts.iter().any(|p| p.prompt.contains(UNLOCKED))
}

/// Logs in as the Mac's unlock account with its password.
async fn try_unlock(ssh: &mut client::Handle<Identify>, unlocked: &AtomicBool, ctx: &Ctx, mac: &Mac) -> Result<Outcome> {
    let user = &mac.unlock_user;
    // A booted Mac's drop-in limits the account to keyboard-interactive. The pre-boot
    // server can't read the drop-in, and offers its defaults.
    let methods = match time::timeout(TIMEOUT, ssh.authenticate_none(user.clone())).await.context("timed out")?? {
        AuthResult::Failure { remaining_methods, .. } => remaining_methods,
        AuthResult::Success => bail!("{user} was let in without a password"),
    };
    if !methods.contains(&MethodKind::KeyboardInteractive) {
        bail!("no password prompt offered ({methods:?})");
    }
    // A booted Mac's drop-in offers only keyboard-interactive; the pre-boot server
    // offers its defaults (publickey, password, keyboard-interactive).
    let booted = methods.iter().all(|m| *m == MethodKind::KeyboardInteractive);
    if ctx.dry_run {
        return Ok(if booted { Outcome::Booted } else { Outcome::Locked });
    }
    let first = time::timeout(TIMEOUT, ssh.authenticate_keyboard_interactive_start(user.clone(), None)).await.context("timed out")??;
    if !matches!(&first, Kbd::InfoRequest { prompts, .. } if prompts.len() == 1 && !prompts[0].echo) {
        bail!("expected a single hidden password prompt, got {first:?}");
    }

    // From here the password has been sent. A clean close, a reset, or a hang now all
    // mean the same thing: the pre-boot unlock took it and is restarting the Mac into
    // macOS, which tears the connection down however the network happens to go. Only
    // an explicit refusal (Failure, a re-prompt, or an error message) is a refusal; a
    // wrong password always comes back as one of those, never as a silent drop.
    let password = credential(&format!("lime.{}", mac.name))?;
    let mut reply = time::timeout(TIMEOUT, ssh.authenticate_keyboard_interactive_respond(vec![password])).await;
    loop {
        if unlocked.load(Ordering::Acquire) || matches!(&reply, Ok(Ok(round)) if says_unlocked(round)) {
            return Ok(Outcome::Unlocked);
        }
        let why: String = match reply {
            Err(_) | Ok(Err(_)) => return Ok(Outcome::Unlocked),
            Ok(Ok(Kbd::Success)) => return Ok(Outcome::Booted),
            Ok(Ok(Kbd::Failure { .. })) => "password refused".to_owned(),
            // Asked again: refused. lime never answers a second time.
            Ok(Ok(Kbd::InfoRequest { prompts, .. })) if !prompts.is_empty() => "asked for the password again".to_owned(),
            // PAM's failure text, such as "Account ... is temporarily unavailable."
            // while the Secure Enclave enforces a delay.
            Ok(Ok(Kbd::InfoRequest { instructions, .. })) if !instructions.trim().is_empty() => format!("the Mac says {:?}", instructions.trim()),
            // An empty round: PAM accepted the password. Answer it; the Mac may send
            // its success text and pivot instead of replying, which the checks above catch.
            Ok(Ok(Kbd::InfoRequest { .. })) => {
                reply = time::timeout(TIMEOUT, ssh.authenticate_keyboard_interactive_respond(vec![])).await;
                continue;
            }
        };
        return Ok(Outcome::Refused { why, booted });
    }
}

// --- schedule -------------------------------------------------------------------

/// When a Mac may next be tried, and the backoff that will follow a refusal.
/// Kept in `$STATE_DIRECTORY/<name>`, so a restart cannot shorten it.
#[derive(Clone, Copy)]
struct Schedule {
    not_before: u64,
    backoff: u64,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

fn load_schedule(ctx: &Ctx, mac: &Mac) -> Schedule {
    let saved = std::fs::read_to_string(ctx.state.join(&mac.name)).ok().and_then(|s| {
        let mut n = s.split_whitespace().map(|v| v.parse().ok());
        Some(Schedule { not_before: n.next()??, backoff: n.next()?? })
    });
    saved.unwrap_or(Schedule { not_before: 0, backoff: ctx.base_retry })
}

/// How a visit went, for scheduling the next one.
enum Verdict {
    /// Up and working, or just unlocked.
    Fine,
    /// The password was refused.
    Refused,
    /// Anything else: nothing was learned about the password.
    Fault,
}

/// Pushes the next try back: by the current backoff after a refusal (which then
/// doubles), by `heartbeat` after anything else. Only a Mac that's fine resets the
/// backoff, so faults between refusals can't shorten it. Returns the wait in seconds.
fn reschedule(ctx: &Ctx, mac: &Mac, s: &mut Schedule, verdict: Verdict) -> u64 {
    let (wait, backoff) = match verdict {
        Verdict::Fine => (ctx.heartbeat, ctx.base_retry),
        Verdict::Refused => (s.backoff, (s.backoff * 2).min(ctx.max_retry)),
        Verdict::Fault => (ctx.heartbeat, s.backoff),
    };
    *s = Schedule { not_before: now() + wait, backoff };
    // A dry run's schedule only stops it repeating itself; the service shouldn't inherit it.
    if !ctx.dry_run
        && let Err(e) = std::fs::write(ctx.state.join(&mac.name), format!("{} {}\n", s.not_before, s.backoff))
    {
        log!(3, "{}: could not save its schedule: {e}", mac.name);
    }
    wait
}

// --- main -----------------------------------------------------------------------

/// An `_ssh._tcp` instance currently announced.
struct Service {
    addr: SocketAddr,
    /// Not before this: a pause after a connection error.
    wait_until: Instant,
    /// `None` until connected once, then which Mac it is, if any.
    mac: Option<Option<usize>>,
}

async fn visit(ctx: &Ctx, key: &str, svc: &mut Service, schedules: &mut [Schedule]) {
    if svc.mac == Some(None) || Instant::now() < svc.wait_until {
        return;
    }
    if let Some(Some(i)) = svc.mac
        && now() < schedules[i].not_before
    {
        return;
    }
    let unlocked = Arc::new(AtomicBool::new(false));
    let (mut ssh, i) = match connect(ctx, svc.addr, &unlocked).await {
        Ok(Some(found)) => found,
        Ok(None) => {
            svc.mac = Some(None);
            return log!(6, "{key} ({}): not one of the configured Macs", svc.addr);
        }
        Err(e) => {
            // No password was sent, so no need to back off: this is often a Mac
            // that's restarting.
            svc.wait_until = Instant::now() + Duration::from_secs(ctx.heartbeat);
            return log!(4, "{key} ({}): {e:#}", svc.addr);
        }
    };
    svc.mac = Some(Some(i));
    let (mac, schedule) = (&ctx.macs[i], &mut schedules[i]);
    if now() < schedule.not_before {
        return;
    }
    let outcome = try_unlock(&mut ssh, &unlocked, ctx, mac).await;
    // An unlocking Mac is pivoting into macOS: just drop the connection (with `ssh`).
    if !matches!(outcome, Ok(Outcome::Unlocked)) {
        let _ = ssh.disconnect(Disconnect::ByApplication, "", "en").await;
    }
    let who = format!("{} ({key}, {})", mac.name, svc.addr);
    match outcome {
        Ok(Outcome::Booted) => {
            let wait = reschedule(ctx, mac, schedule, Verdict::Fine);
            let how = if ctx.dry_run { "booted (only keyboard-interactive offered)" } else { "booted (password accepted, account turned away)" };
            log!(6, "{who}: {how}. Next check in {wait}s");
        }
        Ok(Outcome::Locked) => {
            reschedule(ctx, mac, schedule, Verdict::Fine);
            log!(5, "{who}: at the pre-boot unlock: would send the password. Dry run");
        }
        Ok(Outcome::Unlocked) => {
            let wait = reschedule(ctx, mac, schedule, Verdict::Fine);
            log!(5, "{who}: unlocked; macOS is starting. Next check in {wait}s");
        }
        Ok(Outcome::Refused { why, booted }) => {
            let wait = reschedule(ctx, mac, schedule, Verdict::Refused);
            let what = if booted { format!("booted, but {why}") } else { format!("{why} at the pre-boot unlock") };
            log!(4, "{who}: {what}. Next try in {wait}s");
        }
        Err(e) => {
            let wait = reschedule(ctx, mac, schedule, Verdict::Fault);
            log!(4, "{who}: {e:#}. Next try in {wait}s");
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    // zlink's streams are not Send, so the watchers are local tasks.
    tokio::task::LocalSet::new().run_until(run()).await
}

async fn run() -> Result<()> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let dry_run = args.first().is_some_and(|a| a == "--dry-run");
    if dry_run {
        args.remove(0);
    }
    let path = match args.as_slice() {
        [] => "/etc/lime/lime.toml",
        [path] => path.as_str(),
        _ => bail!("usage: lime [--dry-run] [CONFIG]"),
    };
    let (interfaces, ctx) = load(path, dry_run)?;

    let (tx, mut rx) = mpsc::channel(64);
    let mut ifnames = HashMap::new();
    for ifname in interfaces {
        let ifindex: i32 = std::fs::read_to_string(format!("/sys/class/net/{ifname}/ifindex"))
            .with_context(|| format!("no network interface {ifname}"))?
            .trim()
            .parse()?;
        let tx = tx.clone();
        tokio::task::spawn_local(async move {
            let e = watch(ifindex, &tx).await.unwrap_err();
            // systemd restarts the service (Restart=on-failure).
            log!(3, "browsing {SSH} on interface {ifindex}: {e:#}");
            std::process::exit(1);
        });
        ifnames.insert(ifindex, ifname);
    }

    log!(6, "watching for {} Mac(s){}", ctx.macs.len(), if dry_run { " (dry run)" } else { "" });
    let mut resolver = zlink::tokio::unix::connect(RESOLVE).await.context("connecting to systemd-resolved")?;
    let mut schedules: Vec<Schedule> = ctx.macs.iter().map(|m| load_schedule(&ctx, m)).collect();
    let mut services: HashMap<(i32, String), Service> = HashMap::new();
    let mut tick = time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            event = rx.recv() => {
                let Event { ifindex, name, added } = event.context("every watcher stopped")?;
                let key = (ifindex, name);
                if !added {
                    services.remove(&key);
                    continue;
                }
                match resolve(&mut resolver, ifindex, &key.1).await {
                    Ok(addr) => { services.insert(key, Service { addr, wait_until: Instant::now(), mac: None }); }
                    Err(e) => log!(4, "{} on {}: could not resolve: {e:#}", key.1, ifnames[&ifindex]),
                }
            }
            _ = tick.tick() => {
                for ((ifindex, name), svc) in services.iter_mut() {
                    visit(&ctx, &format!("{name} on {}", ifnames[ifindex]), svc, &mut schedules).await;
                }
            }
        }
    }
}
