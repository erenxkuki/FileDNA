use clap::{Parser, Subcommand};
use filedna_core::config;
use filedna_core::discovery;
use filedna_core::pipeline;
use filedna_core::report;
use filedna_core::storage::Database;
use filedna_core::types::*;
use std::io::{self, Write};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "filedna", version, about = "FileDNA structural intelligence engine")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Scan {
        path: Option<PathBuf>,
        #[arg(long)]
        pick: bool,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        db: Option<PathBuf>,
        #[arg(long)]
        recursive: bool,
    },
    Inspect {
        path: Option<PathBuf>,
        #[arg(long)]
        pick: bool,
        #[arg(long)]
        json: bool,
    },
    Identify {
        path: Option<PathBuf>,
        #[arg(long)]
        pick: bool,
        #[arg(long)]
        json: bool,
    },
    Hash {
        path: Option<PathBuf>,
        #[arg(long)]
        pick: bool,
        #[arg(long)]
        blake3: bool,
    },
    Compare {
        a: Option<PathBuf>,
        b: Option<PathBuf>,
        #[arg(long)]
        pick: bool,
        #[arg(long)]
        json: bool,
    },
    Duplicates {
        path: Option<PathBuf>,
        #[arg(long)]
        pick: bool,
        #[arg(long)]
        json: bool,
    },
    Report {
        path: Option<PathBuf>,
        #[arg(long)]
        pick: bool,
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    Interactive,
    Plugins {
        #[command(subcommand)]
        cmd: PluginCmd,
    },
    Config {
        #[command(subcommand)]
        cmd: ConfigCmd,
    },
}

#[derive(Subcommand)]
enum PluginCmd {
    List,
}

#[derive(Subcommand)]
enum ConfigCmd {
    Show,
}

fn pick_folder() -> Option<PathBuf> {
    rfd::FileDialog::new().pick_folder()
}

fn pick_file() -> Option<PathBuf> {
    rfd::FileDialog::new().pick_file()
}

fn prompt_path(prompt: &str) -> Option<PathBuf> {
    print!("{}", prompt);
    let _ = io::stdout().flush();
    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_ok() {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(PathBuf::from(trimmed))
        }
    } else {
        None
    }
}

fn resolve_path(path: Option<PathBuf>, pick: bool, file: bool) -> Option<PathBuf> {
    if let Some(p) = path {
        return Some(p);
    }
    if pick {
        if file {
            return pick_file();
        }
        return pick_folder();
    }
    // interactive prompt
    prompt_path("Enter path (or leave empty to open picker): ")
        .or_else(|| {
            if file {
                pick_file()
            } else {
                pick_folder()
            }
        })
}

fn main() {
    let cli = Cli::parse();
    let cfg = config::load_config();

    let command = cli.command.unwrap_or(Commands::Interactive);

    match command {
        Commands::Interactive => {
            loop {
                println!();
                println!("FileDNA Interactive");
                println!("1) Scan folder");
                println!("2) Inspect file");
                println!("3) Identify file");
                println!("4) Hash file");
                println!("5) Compare two files");
                println!("6) Find duplicates");
                println!("7) Report");
                println!("8) Config show");
                println!("0) Exit");
                print!("Choice: ");
                let _ = io::stdout().flush();
                let mut c = String::new();
                if io::stdin().read_line(&mut c).is_err() {
                    break;
                }
                match c.trim() {
                    "1" => {
                        let p = resolve_path(None, true, false);
                        if let Some(path) = p {
                            run_scan(&path, &cfg, true, None, false);
                        }
                    }
                    "2" => {
                        let p = resolve_path(None, true, true);
                        if let Some(path) = p {
                            let profile = filedna_core::analysis::analyze_file(&path, &cfg);
                            println!("{}", report::to_text(&[profile]));
                        }
                    }
                    "3" => {
                        let p = resolve_path(None, true, true);
                        if let Some(path) = p {
                            match filedna_core::identification::identify(&path, &cfg) {
                                Ok((res, _)) => {
                                    if let Some(pp) = res.primary {
                                        println!("Detected: {} ({})", pp.format_id, pp.confidence.as_str());
                                        println!("Score: {:.2}", pp.confidence_score);
                                    } else {
                                        println!("Unknown format");
                                    }
                                    if res.extension_mismatch {
                                        println!("Extension mismatch: claimed '{}'", res.claimed_extension.unwrap_or_default());
                                    }
                                }
                                Err(e) => eprintln!("error: {}", e),
                            }
                        }
                    }
                    "4" => {
                        let p = resolve_path(None, true, true);
                        if let Some(path) = p {
                            match filedna_core::fingerprint::sha256_file(&path, 1024 * 1024) {
                                Ok(fp) => println!("{}", fp.hex),
                                Err(e) => eprintln!("error: {}", e),
                            }
                        }
                    }
                    "5" => {
                        println!("Select first file:");
                        let a = resolve_path(None, true, true);
                        println!("Select second file:");
                        let b = resolve_path(None, true, true);
                        if let (Some(a), Some(b)) = (a, b) {
                            let pa = filedna_core::analysis::analyze_file(&a, &cfg);
                            let pb = filedna_core::analysis::analyze_file(&b, &cfg);
                            let sim = filedna_core::similarity::compare_profiles(&pa, &pb);
                            println!("Similarity score: {:.2}", sim.score);
                            for s in &sim.signals {
                                println!("  - {}", s);
                            }
                        }
                    }
                    "6" => {
                        let p = resolve_path(None, true, false);
                        if let Some(path) = p {
                            run_duplicates(&path, &cfg, false);
                        }
                    }
                    "7" => {
                        let p = resolve_path(None, true, false);
                        if let Some(path) = p {
                            run_report(&path, &cfg, None, false);
                        }
                    }
                    "8" => {
                        println!("{}", toml::to_string_pretty(&cfg).unwrap_or_default());
                    }
                    "0" => break,
                    _ => println!("Invalid choice"),
                }
            }
        }
        Commands::Scan { path, pick, json, db, recursive } => {
            let p = match resolve_path(path, pick, false) {
                Some(p) => p,
                None => {
                    eprintln!("No path selected.");
                    return;
                }
            };
            run_scan(&p, &cfg, recursive, db, json);
        }
        Commands::Inspect { path, pick, json } => {
            let p = match resolve_path(path, pick, true) {
                Some(p) => p,
                None => {
                    eprintln!("No path selected.");
                    return;
                }
            };
            let profile = filedna_core::analysis::analyze_file(&p, &cfg);
            if json {
                println!("{}", serde_json::to_string_pretty(&profile).unwrap_or_default());
            } else {
                println!("{}", report::to_text(&[profile]));
            }
        }
        Commands::Identify { path, pick, json } => {
            let p = match resolve_path(path, pick, true) {
                Some(p) => p,
                None => {
                    eprintln!("No path selected.");
                    return;
                }
            };
            match filedna_core::identification::identify(&p, &cfg) {
                Ok((res, _ev)) => {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&res).unwrap_or_default());
                    } else {
                        if let Some(pp) = res.primary {
                            println!("Detected: {} ({})", pp.format_id, pp.confidence.as_str());
                            println!("Score: {:.2}", pp.confidence_score);
                        } else {
                            println!("Unknown format");
                        }
                        if res.extension_mismatch {
                            println!("Extension mismatch: claimed '{}'", res.claimed_extension.unwrap_or_default());
                        }
                    }
                }
                Err(e) => eprintln!("error: {}", e),
            }
        }
        Commands::Hash { path, pick, blake3 } => {
            let p = match resolve_path(path, pick, true) {
                Some(p) => p,
                None => {
                    eprintln!("No path selected.");
                    return;
                }
            };
            if blake3 {
                match filedna_core::fingerprint::blake3_file(&p, 1024 * 1024) {
                    Ok(fp) => println!("{}", fp.hex),
                    Err(e) => eprintln!("error: {}", e),
                }
            } else {
                match filedna_core::fingerprint::sha256_file(&p, 1024 * 1024) {
                    Ok(fp) => println!("{}", fp.hex),
                    Err(e) => eprintln!("error: {}", e),
                }
            }
        }
        Commands::Compare { a, b, pick, json } => {
            let pa = if let Some(p) = a { p } else if pick {
                match pick_file() { Some(p) => p, None => { eprintln!("No file selected."); return; } }
            } else {
                match prompt_path("First file path: ") { Some(p) => p, None => { eprintln!("No path."); return; } }
            };
            let pb = if let Some(p) = b { p } else if pick {
                match pick_file() { Some(p) => p, None => { eprintln!("No file selected."); return; } }
            } else {
                match prompt_path("Second file path: ") { Some(p) => p, None => { eprintln!("No path."); return; } }
            };
            let ppa = filedna_core::analysis::analyze_file(&pa, &cfg);
            let ppb = filedna_core::analysis::analyze_file(&pb, &cfg);
            let sim = filedna_core::similarity::compare_profiles(&ppa, &ppb);
            if json {
                println!("{}", serde_json::to_string_pretty(&sim).unwrap_or_default());
            } else {
                println!("Similarity score: {:.2}", sim.score);
                for s in &sim.signals {
                    println!("  - {}", s);
                }
            }
        }
        Commands::Duplicates { path, pick, json } => {
            let p = match resolve_path(path, pick, false) {
                Some(p) => p,
                None => {
                    eprintln!("No path selected.");
                    return;
                }
            };
            run_duplicates(&p, &cfg, json);
        }
        Commands::Report { path, pick, out, json } => {
            let p = match resolve_path(path, pick, false) {
                Some(p) => p,
                None => {
                    eprintln!("No path selected.");
                    return;
                }
            };
            run_report(&p, &cfg, out, json);
        }
        Commands::Plugins { cmd } => match cmd {
            PluginCmd::List => println!("No plugins installed (plugin system deferred)."),
        },
        Commands::Config { cmd } => match cmd {
            ConfigCmd::Show => println!("{}", toml::to_string_pretty(&cfg).unwrap_or_default()),
        },
    }
}

fn run_scan(path: &PathBuf, cfg: &Config, recursive: bool, db: Option<PathBuf>, json: bool) {
    let opts = discovery::DiscoveryOptions {
        recursive: recursive || true,
        follow_symlinks: cfg.follow_symlinks,
        include_hidden: cfg.include_hidden,
        max_depth: None,
    };
    let ctx = pipeline::ScanContext::default();
    let roots = vec![path.clone()];
    let (profiles, job) = pipeline::scan(&roots, cfg, &opts, &ctx);
    if let Some(dbp) = db {
        if let Ok(database) = Database::open(&dbp) {
            for p in &profiles {
                let _ = database.save_profile(p);
            }
            let _ = database.save_job(&job);
        }
    }
    if json {
        println!("{}", report::to_json(&profiles, Some(&job)).unwrap_or_default());
    } else {
        println!("{}", report::to_text(&profiles));
        println!("Job status: {:?}", job.status);
    }
}

fn run_duplicates(path: &PathBuf, cfg: &Config, json: bool) {
    let opts = discovery::DiscoveryOptions { recursive: true, ..Default::default() };
    let ctx = pipeline::ScanContext::default();
    let (profiles, _) = pipeline::scan(&[path.clone()], cfg, &opts, &ctx);
    let mut groups = filedna_core::duplicate::find_exact_duplicates(&profiles);
    groups.extend(filedna_core::duplicate::find_structural_duplicates(&profiles));
    groups.extend(filedna_core::duplicate::find_metadata_duplicates(&profiles));
    groups.extend(filedna_core::duplicate::find_potential_duplicates(&profiles));
    if json {
        println!("{}", serde_json::to_string_pretty(&groups).unwrap_or_default());
    } else {
        for g in &groups {
            println!("{:?}: {}", g.kind, g.files.len());
            for f in &g.files {
                println!("   {}", f.display());
            }
        }
    }
}

fn run_report(path: &PathBuf, cfg: &Config, out: Option<PathBuf>, json: bool) {
    let opts = discovery::DiscoveryOptions { recursive: true, ..Default::default() };
    let ctx = pipeline::ScanContext::default();
    let (profiles, job) = pipeline::scan(&[path.clone()], cfg, &opts, &ctx);
    if json {
        let s = report::to_json(&profiles, Some(&job)).unwrap_or_default();
        if let Some(o) = out {
            let _ = report::write_report(&o, &s);
        } else {
            println!("{}", s);
        }
    } else {
        let s = report::to_text(&profiles);
        if let Some(o) = out {
            let _ = report::write_report(&o, &s);
            println!("Report written to {}", o.display());
        } else {
            println!("{}", s);
        }
    }
}
