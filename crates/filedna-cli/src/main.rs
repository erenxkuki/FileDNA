use clap::{Parser, Subcommand};
use filedna_core::config;
use filedna_core::discovery;
use filedna_core::pipeline;
use filedna_core::report;
use filedna_core::storage::Database;
use filedna_core::types::*;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "filedna",
    version,
    about = "FileDNA structural intelligence engine"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Scan {
        path: PathBuf,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        db: Option<PathBuf>,
        #[arg(long)]
        recursive: bool,
    },
    Inspect {
        path: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Identify {
        path: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Hash {
        path: PathBuf,
        #[arg(long)]
        blake3: bool,
    },
    Compare {
        a: PathBuf,
        b: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Duplicates {
        path: PathBuf,
        #[arg(long)]
        json: bool,
    },
    History {
        path: PathBuf,
    },
    Report {
        path: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
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

fn main() {
    let cli = Cli::parse();
    let cfg = config::load_config();
    match cli.command {
        Commands::Scan {
            path,
            json,
            db,
            recursive,
        } => {
            let opts = discovery::DiscoveryOptions {
                recursive: recursive || true,
                follow_symlinks: cfg.follow_symlinks,
                include_hidden: cfg.include_hidden,
                max_depth: None,
            };
            let ctx = pipeline::ScanContext::default();
            let roots = vec![path.clone()];
            let (profiles, job) = pipeline::scan(&roots, &cfg, &opts, &ctx);
            if let Some(dbp) = db {
                if let Ok(database) = Database::open(&dbp) {
                    for p in &profiles {
                        let _ = database.save_profile(p);
                    }
                    let _ = database.save_job(&job);
                }
            }
            if json {
                println!(
                    "{}",
                    report::to_json(&profiles, Some(&job)).unwrap_or_default()
                );
            } else {
                println!("{}", report::to_text(&profiles));
                println!("Job status: {:?}", job.status);
            }
        }
        Commands::Inspect { path, json } => {
            let profile = filedna_core::analysis::analyze_file(&path, &cfg);
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&profile).unwrap_or_default()
                );
            } else {
                println!("{}", report::to_text(&[profile]));
            }
        }
        Commands::Identify { path, json } => {
            match filedna_core::identification::identify(&path, &cfg) {
                Ok((res, _ev)) => {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&res).unwrap_or_default());
                    } else {
                        if let Some(p) = res.primary {
                            println!("Detected: {} ({})", p.format_id, p.confidence.as_str());
                            println!("Score: {:.2}", p.confidence_score);
                        } else {
                            println!("Unknown format");
                        }
                        if res.extension_mismatch {
                            println!(
                                "Extension mismatch: claimed '{}'",
                                res.claimed_extension.unwrap_or_default()
                            );
                        }
                    }
                }
                Err(e) => eprintln!("error: {}", e),
            }
        }
        Commands::Hash { path, blake3 } => {
            if blake3 {
                match filedna_core::fingerprint::blake3_file(&path, 1024 * 1024) {
                    Ok(fp) => println!("{}", fp.hex),
                    Err(e) => eprintln!("error: {}", e),
                }
            } else {
                match filedna_core::fingerprint::sha256_file(&path, 1024 * 1024) {
                    Ok(fp) => println!("{}", fp.hex),
                    Err(e) => eprintln!("error: {}", e),
                }
            }
        }
        Commands::Compare { a, b, json } => {
            let pa = filedna_core::analysis::analyze_file(&a, &cfg);
            let pb = filedna_core::analysis::analyze_file(&b, &cfg);
            let sim = filedna_core::similarity::compare_profiles(&pa, &pb);
            if json {
                println!("{}", serde_json::to_string_pretty(&sim).unwrap_or_default());
            } else {
                println!("Similarity score: {:.2}", sim.score);
                for s in &sim.signals {
                    println!("  - {}", s);
                }
            }
        }
        Commands::Duplicates { path, json } => {
            let opts = discovery::DiscoveryOptions {
                recursive: true,
                ..Default::default()
            };
            let ctx = pipeline::ScanContext::default();
            let (profiles, _) = pipeline::scan(&[path], &cfg, &opts, &ctx);
            let mut groups = filedna_core::duplicate::find_exact_duplicates(&profiles);
            groups.extend(filedna_core::duplicate::find_structural_duplicates(
                &profiles,
            ));
            groups.extend(filedna_core::duplicate::find_metadata_duplicates(&profiles));
            groups.extend(filedna_core::duplicate::find_potential_duplicates(
                &profiles,
            ));
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&groups).unwrap_or_default()
                );
            } else {
                for g in &groups {
                    println!("{:?}: {}", g.kind, g.files.len());
                    for f in &g.files {
                        println!("   {}", f.display());
                    }
                }
            }
        }
        Commands::History { path } => {
            println!("History tracking not yet implemented (deferred).");
            let _ = path;
        }
        Commands::Report { path, out, json } => {
            let opts = discovery::DiscoveryOptions {
                recursive: true,
                ..Default::default()
            };
            let ctx = pipeline::ScanContext::default();
            let (profiles, job) = pipeline::scan(&[path], &cfg, &opts, &ctx);
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
        Commands::Plugins { cmd } => match cmd {
            PluginCmd::List => println!("No plugins installed (plugin system deferred)."),
        },
        Commands::Config { cmd } => match cmd {
            ConfigCmd::Show => println!("{}", toml::to_string_pretty(&cfg).unwrap_or_default()),
        },
    }
}
