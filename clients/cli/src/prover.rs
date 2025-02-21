use nexus_sdk::{stwo::seq::Stwo, Local, Prover, Viewable};

use crate::analytics;
use crate::config;
use crate::flops;
use crate::orchestrator_client::OrchestratorClient;
use crate::setup;
use crate::utils;
use colored::Colorize;
use sha3::{Digest, Keccak256};

/// Proves a program with a given node ID
#[allow(dead_code)]
async fn authenticated_proving(
    node_id: &str,
    environment: &config::Environment,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = OrchestratorClient::new(environment.clone());

    // 添加获取任务的重试逻辑
    let mut retries = 5;  // 增加到5次重试
    let proof_task = loop {
        println!("1. Fetching a task to prove from Nexus Orchestrator... (Attempt {} of 5)", 6 - retries);
        match client.get_proof_task(node_id).await {
            Ok(task) => break task,
            Err(e) => {
                if retries <= 1 {
                    return Err(format!("Failed to fetch proof task after all retries: {:?}", e).into());
                }
                retries -= 1;
                println!("Failed to fetch task: {:?}", e);
                println!("Retrying in 2 seconds..."); // 缩短等待时间到2秒
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }
    };

    println!("2. Received a task to prove from Nexus Orchestrator...");

    let public_input: u32 = proof_task.public_inputs[0] as u32;

    println!("3. Compiling guest program...");
    let elf_file_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("assets")
        .join("fib_input");
    let prover =
        Stwo::<Local>::new_from_file(&elf_file_path).expect("failed to load guest program");

    println!("4. Creating ZK proof with inputs");
    let (view, proof) = prover
        .prove_with_input::<(), u32>(&(), &public_input)
        .expect("Failed to run prover");

    assert_eq!(view.exit_code().expect("failed to retrieve exit code"), 0);

    let proof_bytes = serde_json::to_vec(&proof)?;
    let proof_hash = format!("{:x}", Keccak256::digest(&proof_bytes));

    println!("\tProof size: {} bytes", proof_bytes.len());
    
    // 提交证明的重试逻辑
    let mut submit_retries = 3;
    while submit_retries > 0 {
        println!("5. Submitting ZK proof to Nexus Orchestrator... (Attempt {} of 3)", 4 - submit_retries);
        match client.submit_proof(node_id, &proof_hash, proof_bytes.clone()).await {
            Ok(_) => {
                println!("{}", "6. ZK proof successfully submitted".green());
                return Ok(());
            }
            Err(e) => {
                println!("Submit attempt failed: {:?}", e);
                submit_retries -= 1;
                if submit_retries > 0 {
                    println!("Retrying in 5 seconds...");
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
            }
        }
    }

    Err("Failed to submit proof after all retries".into())
}

fn anonymous_proving() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Instead of fetching the proof task from the orchestrator, we will use hardcoded input program and values

    // The 10th term of the Fibonacci sequence is 55
    let public_input: u32 = 9;

    //2. Compile the guest program
    println!("1. Compiling guest program...");
    let elf_file_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("assets")
        .join("fib_input");
    let prover =
        Stwo::<Local>::new_from_file(&elf_file_path).expect("failed to load guest program");

    //3. Run the prover
    println!("2. Creating ZK proof...");
    let (view, proof) = prover
        .prove_with_input::<(), u32>(&(), &public_input)
        .expect("Failed to run prover");

    assert_eq!(view.exit_code().expect("failed to retrieve exit code"), 0);

    let proof_bytes = serde_json::to_vec(&proof)?;

    println!(
        "{}",
        format!(
            "3. ZK proof successfully created with size: {} bytes",
            proof_bytes.len()
        )
        .green(),
    );
    Ok(())
}

/// Starts the prover, which can be anonymous or connected to the Nexus Orchestrator
pub async fn start_prover(
    environment: &config::Environment,
) -> Result<(), Box<dyn std::error::Error>> {
    // Print the banner at startup
    utils::cli_branding::print_banner();

    println!(
        "\n===== {} =====\n",
        "Setting up CLI configuration"
            .bold()
            .underline()
            .bright_cyan(),
    );

    // Run the initial setup to determine anonymous or connected node
    match setup::run_initial_setup().await {
        //each arm of the match is a choice by the user: anonymous or connected or invalid as catchall
        setup::SetupResult::Anonymous => {
            println!(
                "\n===== {} =====\n",
                "Starting Anonymous proof generation for programs"
                    .bold()
                    .underline()
                    .bright_cyan()
            );
            let client_id = format!("{:x}", md5::compute(b"anonymous"));
            // Run the proof generation loop with anonymous proving
            let mut proof_count = 1;
            loop {
                println!("\n================================================");
                println!(
                    "{}",
                    format!("\nStarting proof #{} ...\n", proof_count).yellow()
                );
                match anonymous_proving() {
                    Ok(_) => (),
                    Err(e) => println!("Error in anonymous proving: {}", e),
                }
                proof_count += 1;

                analytics::track(
                    "cli_proof_anon".to_string(),
                    format!("Completed anon proof iteration #{}", proof_count),
                    serde_json::json!({
                        "node_id": "anonymous",
                        "proof_count": proof_count,
                    }),
                    false,
                    environment,
                    client_id.clone(),
                );
                tokio::time::sleep(std::time::Duration::from_secs(4)).await;
            }
        }
        setup::SetupResult::Connected(node_id) => {
            println!(
                "\n===== {} =====\n",
                "Starting proof generation for programs"
                    .bold()
                    .underline()
                    .bright_cyan()
            );
            let flops = flops::measure_flops();
            let flops_formatted = format!("{:.2}", flops);
            let flops_str = format!("{} FLOPS", flops_formatted);
            println!(
                "{}: {}",
                "Computational capacity of this node".bold(),
                flops_str.bright_cyan()
            );
            println!(
                "{}: {}",
                "You are proving with node ID".bold(),
                node_id.bright_cyan()
            );
            println!(
                "{}: {}",
                "Environment".bold(),
                environment.to_string().bright_cyan()
            );

            let client_id = format!("{:x}", md5::compute(node_id.as_bytes()));
            let mut proof_count = 1;
            loop {
                println!("\n================================================");
                println!(
                    "{}",
                    format!(
                        "\n[node: {}] Starting proof #{} ...\n",
                        node_id, proof_count
                    )
                    .yellow()
                );

                match authenticated_proving(&node_id, environment).await {
                    Ok(_) => (),
                    Err(_e) => (),
                }

                proof_count += 1;

                analytics::track(
                    "cli_proof_node".to_string(),
                    format!("Completed proof iteration #{}", proof_count),
                    serde_json::json!({
                        "node_id": node_id,
                        "proof_count": proof_count,
                    }),
                    false,
                    environment,
                    client_id.clone(),
                );
                tokio::time::sleep(std::time::Duration::from_secs(4)).await;
            }
        }
        setup::SetupResult::Invalid => Err("Invalid setup option selected".into()),
    }
}
