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

use std::sync::Arc;
use crate::nexus_orchestrator::GetProofTaskResponse;

async fn fetch_task_with_timeout(
    client: Arc<OrchestratorClient>,
    node_id: &str,
    thread_id: usize,
) -> Result<GetProofTaskResponse, Box<dyn std::error::Error + Send + Sync>> {
    const STEP1_MAX_RETRIES: u32 = 300;
    const STEP1_TIMEOUT_SECS: u64 = 2;
    let mut fetch_retries = STEP1_MAX_RETRIES;

    loop {
        let current_time = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
        println!(
            "[{}] Thread {} - Fetching task (Attempt {} of {})",
            current_time,
            thread_id,
            STEP1_MAX_RETRIES - fetch_retries + 1,
            STEP1_MAX_RETRIES
        );

        match tokio::time::timeout(
            tokio::time::Duration::from_secs(STEP1_TIMEOUT_SECS),
            client.get_proof_task(node_id),
        )
        .await
        {
            Ok(Ok(task)) => {
                println!(
                    "[{}] Thread {} - Successfully fetched task!",
                    current_time, thread_id
                );
                return Ok(task);
            }
            Ok(Err(e)) => {
                println!(
                    "[{}] Thread {} - Failed to fetch task: {}",
                    current_time, thread_id, e
                );
            }
            Err(_) => {
                println!(
                    "[{}] Thread {} - Request timed out after {} seconds",
                    current_time, thread_id, STEP1_TIMEOUT_SECS
                );
            }
        }

        if fetch_retries <= 1 {
            return Err("Failed to fetch proof task after all retries".into());
        }
        fetch_retries -= 1;
    }
}

async fn authenticated_proving(
    node_id: &str,
    environment: &config::Environment,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = Arc::new(OrchestratorClient::new(environment.clone()));

    // 启动多个任务获取线程
    const NUM_THREADS: usize = 3;
    let mut handles = Vec::with_capacity(NUM_THREADS);

    for thread_id in 0..NUM_THREADS {
        let client = Arc::clone(&client);
        let node_id = node_id.to_string();
        
        handles.push(tokio::spawn(async move {
            fetch_task_with_timeout(client, &node_id, thread_id).await
        }));
    }

    // 等待任意一个线程成功获取任务
    let proof_task = tokio::select! {
        // 对每个handle进行处理
        result = async {
            let mut tasks = Vec::new();
            for handle in handles {
                if let Ok(result) = handle.await {
                    if let Ok(task) = result {
                        tasks.push(task);
                    }
                }
            }
            // 返回第一个成功的任务
            tasks.into_iter().next()
        } => {
            result.ok_or("All threads failed to fetch task")?
        }
    };

    let current_time = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
    println!("[{}] 2. Received a task to prove from Nexus Orchestrator...", current_time);

    let public_input: u32 = proof_task.public_inputs[0] as u32;

    let current_time = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
    println!("[{}] 3. Compiling guest program...", current_time);
    let elf_file_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("assets")
        .join("fib_input");
    let prover =
        Stwo::<Local>::new_from_file(&elf_file_path).expect("failed to load guest program");

    let current_time = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
    println!("[{}] 4. Creating ZK proof with inputs", current_time);
    let (view, proof) = prover
        .prove_with_input::<(), u32>(&(), &public_input)
        .expect("Failed to run prover");

    assert_eq!(view.exit_code().expect("failed to retrieve exit code"), 0);

    let proof_bytes = serde_json::to_vec(&proof)?;
    let proof_hash = format!("{:x}", Keccak256::digest(&proof_bytes));

    let current_time = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
    println!("[{}] \tProof size: {} bytes", current_time, proof_bytes.len());
    
    // 提交证明的重试配置 
    const STEP6_MAX_RETRIES: u32 = 120;
    const STEP6_TIMEOUT_SECS: u64 = 5;
    const STEP6_RETRY_DELAY_SECS: u64 = 1;
    let mut submit_retries = STEP6_MAX_RETRIES;

    while submit_retries > 0 {
        let current_time = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
        println!(
            "[{}] 5. Submitting ZK proof to Nexus Orchestrator... (Attempt {} of {})",
            current_time,
            STEP6_MAX_RETRIES - submit_retries + 1,
            STEP6_MAX_RETRIES
        );
        
        match tokio::time::timeout(
            tokio::time::Duration::from_secs(STEP6_TIMEOUT_SECS),
            client.submit_proof(node_id, &proof_hash, proof_bytes.clone())
        ).await {
            Ok(Ok(_)) => {
                let current_time = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                println!("[{}] {}", current_time, "6. ZK proof successfully submitted".green());
                return Ok(());
            },
            Ok(Err(e)) => {
                let current_time = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                println!("[{}] Submit attempt failed: {}", current_time, e);
            },
            Err(_) => {
                let current_time = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                println!(
                    "[{}] Submit attempt timed out after {} seconds",
                    current_time, STEP6_TIMEOUT_SECS
                );
            }
        }

        submit_retries -= 1;
        if submit_retries > 0 {
            let current_time = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
            println!("[{}] Retrying in {} seconds...", current_time, STEP6_RETRY_DELAY_SECS);
            tokio::time::sleep(tokio::time::Duration::from_secs(STEP6_RETRY_DELAY_SECS)).await;
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
