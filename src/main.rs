use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};

use unbidden::entry::{Flag, Kind, Trigger};
use unbidden::render::{Filters, TableOpts};
use unbidden::root::Root;
use unbidden::scan::{Options, Scan};
use unbidden::{collect, diff, enrich, explain, render, scan};

#[derive(Parser)]
#[command(
    name = "unbidden",
    version,
    about = "Enumerate what runs automatically on a Linux host",
    long_about = "Reports the mechanisms by which code runs without a person invoking it: at \
                  boot, on a schedule, at login, on authentication, on device and network \
                  events, on package operations, and at any time through preloaded \
                  libraries, NSS modules, D-Bus services and the programs the kernel runs \
                  itself.\n\n\
                  Reads only. Never executes a binary on the host under examination.",
    args_conflicts_with_subcommands = true
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    #[command(flatten)]
    scan: ScanArgs,
}

#[derive(Subcommand)]
enum Command {
    /// Enumerate autostart and persistence mechanisms (the default).
    Scan(ScanArgs),
    /// Everything known about one entry, including the text it came from.
    Explain(ExplainArgs),
}

#[derive(Args, Clone)]
struct ScanArgs {
    /// Show every entry, including packaged files that match their manifest.
    #[arg(long)]
    all: bool,

    /// One JSON record per line. Implies --all: machine output is complete.
    #[arg(long)]
    json: bool,

    /// With --json, emit one indented array instead of a record stream.
    #[arg(long)]
    pretty: bool,

    /// Also run the collectors that need a whole-filesystem traversal.
    #[arg(long)]
    deep: bool,

    /// Restrict to these mechanism classes.
    #[arg(long = "kind", value_name = "KIND", value_parser = parse_kind)]
    kinds: Vec<Kind>,

    /// Restrict to entries that fire on these events.
    #[arg(long = "trigger", value_name = "TRIGGER", value_parser = parse_trigger)]
    triggers: Vec<Trigger>,

    /// Restrict to entries carrying any of these flags.
    #[arg(long = "flag", value_name = "FLAG", value_parser = parse_flag)]
    flags: Vec<Flag>,

    /// Write this scan to a file as a baseline.
    #[arg(long, value_name = "PATH")]
    save: Option<PathBuf>,

    /// Compare this scan against a saved baseline.
    #[arg(long, value_name = "PATH")]
    against: Option<PathBuf>,

    /// Scan a mounted image or chroot instead of the running system.
    #[arg(long, value_name = "PATH", default_value = "/")]
    root: PathBuf,
}

#[derive(Args)]
struct ExplainArgs {
    /// An entry id, or any unique prefix of one.
    id: String,

    /// Withhold the raw source text.
    #[arg(long)]
    no_source: bool,

    /// Read the entry from a saved baseline instead of scanning now.
    #[arg(long, value_name = "PATH")]
    from: Option<PathBuf>,

    #[arg(long, value_name = "PATH", default_value = "/")]
    root: PathBuf,

    #[arg(long)]
    deep: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Some(Command::Explain(args)) => run_explain(args),
        Some(Command::Scan(args)) => run_scan(args),
        None => run_scan(cli.scan),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("unbidden: {e}");
            ExitCode::FAILURE
        }
    }
}

fn open_root(path: &std::path::Path) -> Result<Root, String> {
    if path == std::path::Path::new("/") {
        Root::live().map_err(|e| format!("cannot open the running system: {e}"))
    } else {
        Root::at(path).map_err(|e| format!("cannot open scan root {}: {e}", path.display()))
    }
}

fn collect_scan(root: &Root, deep: bool) -> Scan {
    let collectors = collect::all();
    let mut s = scan::run(root, &Options { deep }, &collectors);
    enrich::enrich(root, &mut s);
    enrich::enrich_late(root, &mut s);
    s
}

fn run_scan(args: ScanArgs) -> Result<(), String> {
    let root = open_root(&args.root)?;
    let scan = collect_scan(&root, args.deep);

    if let Some(path) = &args.save {
        let file = std::fs::File::create(path).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        serde_json::to_writer(BufWriter::new(file), &scan)
            .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        eprintln!("baseline written to {}", path.display());
    }

    let filters = Filters {
        kinds: args.kinds.clone(),
        triggers: args.triggers.clone(),
        flags: args.flags.clone(),
    };
    // Machine output is always complete; suppression is the human view's job.
    let opts = TableOpts { all: args.all || args.json, width: render::terminal_width() };

    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());

    let rendered = match &args.against {
        Some(path) => {
            let baseline = load(path)?;
            let diffs = diff::diff(&baseline, &scan)?;
            if args.json {
                render::diff_ndjson(&mut out, &scan, &diffs, &filters)
            } else {
                render::diff_table(&mut out, &scan, &diffs, &filters, &opts)
            }
        }
        None => {
            if args.json && args.pretty {
                render::json_array(&mut out, &scan, &filters)
            } else if args.json {
                render::ndjson(&mut out, &scan, &filters)
            } else {
                render::table(&mut out, &scan, &filters, &opts)
            }
        }
    };

    match rendered {
        Ok(()) => Ok(()),
        // A consumer that stops reading is not an error worth a message.
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

fn run_explain(args: ExplainArgs) -> Result<(), String> {
    let root = open_root(&args.root)?;
    let scan = match &args.from {
        Some(path) => load(path)?,
        None => collect_scan(&root, args.deep),
    };
    let entry = explain::find(&scan, &args.id)?;

    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    explain::write(&mut out, &root, entry, !args.no_source).map_err(|e| e.to_string())?;
    out.flush().map_err(|e| e.to_string())
}

fn load(path: &std::path::Path) -> Result<Scan, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    serde_json::from_reader(std::io::BufReader::new(file))
        .map_err(|e| format!("{} is not an unbidden baseline: {e}", path.display()))
}

fn parse_kind(s: &str) -> Result<Kind, String> {
    Kind::parse(s).ok_or_else(|| format!("unknown kind; one of {}", list(Kind::ALL.iter().map(|k| k.as_str()))))
}

fn parse_trigger(s: &str) -> Result<Trigger, String> {
    Trigger::parse(s)
        .ok_or_else(|| format!("unknown trigger; one of {}", list(Trigger::ALL.iter().map(|t| t.as_str()))))
}

fn parse_flag(s: &str) -> Result<Flag, String> {
    Flag::parse(s).ok_or_else(|| format!("unknown flag; one of {}", list(Flag::ALL.iter().map(|f| f.as_str()))))
}

fn list<'a>(items: impl Iterator<Item = &'a str>) -> String {
    items.collect::<Vec<_>>().join(", ")
}
