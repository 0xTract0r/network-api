use nexus_sdk::{stwo::seq::Stwo, Local, Prover, Viewable};

use crate::analytics;
use crate::config;
use crate::flops;
use crate::orchestrator_client::OrchestratorClient;
use crate::setup;
use crate::utils;
use colored::Colorize;
use sha3::{Digest, Keccak256};

use std::sync::Arc;
use futures::{StreamExt};
use crate::nexus_orchestrator::GetProofTaskResponse;
use futures::stream::FuturesUnordered;
use tokio::sync::broadcast;

// 自定义错误类型
#[derive(Debug)]
pub struct ProverError {
    message: String,
}

impl ProverError {
    fn new<T: Into<String>>(message: T) -> Self {
        ProverError {
            message: message.into(),
        }
    }
}

impl std::error::Error for ProverError {}

impl std::fmt::Display for ProverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

// 配置结构体
#[derive(Clone)]
struct ProverConfig {
    feach_num_threads: usize,
    submit_num_threads: usize,
    fetch_max_retries: u32,
    fetch_timeout_secs: u64,
    submit_max_retries: u32,
    submit_timeout_secs: u64,
}

impl Default for ProverConfig {
    fn default() -> Self {
        Self {
            feach_num_threads: 30,
            fetch_max_retries: 300,
            fetch_timeout_secs: 3,
            submit_num_threads: 30,
            submit_max_retries: 300,
            submit_timeout_secs: 3,
        }
    }
}


// 核心的任务获取函数
async fn fetch_task_with_timeout(
    client: Arc<OrchestratorClient>,
    node_id: &str,
    thread_id: usize,
    mut shutdown_rx: broadcast::Receiver<()>,
    shutdown_tx: broadcast::Sender<()>,
    config: &ProverConfig,
) -> Result<GetProofTaskResponse, ProverError> {
    let mut fetch_retries = config.fetch_max_retries;

    loop {
        // 检查是否收到关闭信号
        if shutdown_rx.try_recv().is_ok() {
            return Err(ProverError::new("Task cancelled - another thread succeeded"));
        }

        tokio::select! {
            _ = shutdown_rx.recv() => {
                return Err(ProverError::new("Task cancelled - another thread succeeded"));
            }
            result = async {
                let current_time = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                println!(
                    "[{}] Thread {} - Fetching task (Attempt {} of {})",
                    current_time,
                    thread_id,
                    config.fetch_max_retries - fetch_retries + 1,
                    config.fetch_max_retries
                );

                match tokio::time::timeout(
                    tokio::time::Duration::from_secs(config.fetch_timeout_secs),
                    client.get_proof_task(node_id),
                ).await {
                    Ok(Ok(task)) => {
                        let current_time = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                        println!(
                            "[{}] Thread {} - {}",
                            current_time, 
                            thread_id,
                            "Successfully fetched task!!!".green()
                        );
                        Ok(task)
                    }
                    Ok(Err(e)) => {
                        let current_time = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                        println!(
                            "[{}] Thread {} - Failed to fetch task: {}",
                            current_time, thread_id, e
                        );
                        Err(ProverError::new(e.to_string()))
                    }
                    Err(_) => {
                        let current_time = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                        println!(
                            "[{}] Thread {} - Request timed out after {} seconds",
                            current_time, thread_id, config.fetch_timeout_secs
                        );
                        Err(ProverError::new("Timeout"))
                    }
                }
            } => {
                match result {
                    Ok(task) => {
                        // 成功获取任务后立即发送停止信号
                        let current_time = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                        println!(
                            "[{}] Thread {} - Task fetched, sending shutdown signal to other threads.",
                            current_time, thread_id
                        );
                        let _ = shutdown_tx.send(());
                        return Ok(task);
                    },
                    Err(e) => {
                        if fetch_retries <= 1 {
                            return Err(e);
                        }
                    }
                }
            }
        }

        fetch_retries -= 1;
    }
}

// 提交证明的函数
async fn submit_proof_with_timeout(
    client: Arc<OrchestratorClient>,
    node_id: &str,
    proof_hash: String,
    proof_bytes: Vec<u8>,
    thread_id: usize,
    mut shutdown_rx: broadcast::Receiver<()>,
    config: &ProverConfig,
) -> Result<(), ProverError> {
    let mut submit_retries = config.submit_max_retries;

    while submit_retries > 0 {
        if shutdown_rx.try_recv().is_ok() {
            return Err(ProverError::new("Task cancelled - another thread succeeded"));
        }

        tokio::select! {
            _ = shutdown_rx.recv() => {
                return Err(ProverError::new("Task cancelled - another thread succeeded"));
            }
            result = async {
                let current_time = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                println!(
                    "[{}] Thread {} - Submitting proof (Attempt {} of {})",
                    current_time,
                    thread_id,
                    config.submit_max_retries - submit_retries + 1,
                    config.submit_max_retries
                );

                match tokio::time::timeout(
                    tokio::time::Duration::from_secs(config.submit_timeout_secs),
                    client.submit_proof(node_id, &proof_hash, proof_bytes.clone())
                ).await {
                    Ok(Ok(_)) => {
                        let current_time = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                        println!(
                            "[{}] Thread {} - {}",
                            current_time, 
                            thread_id,
                            "Successfully submitted proof!!!".green()
                        );
                        Ok(())
                    }
                    Ok(Err(e)) => {
                        let current_time = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                        println!(
                            "[{}] Thread {} - Failed to submit proof: {}",
                            current_time, thread_id, e
                        );
                        Err(ProverError::new(e.to_string()))
                    }
                    Err(_) => {
                        let current_time = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                        println!(
                            "[{}] Thread {} - Submit timed out after {} seconds",
                            current_time, thread_id, config.submit_timeout_secs
                        );
                        Err(ProverError::new("Timeout"))
                    }
                }
            } => {
                match result {
                    Ok(()) => return Ok(()),
                    Err(e) => {
                        if submit_retries <= 1 {
                            return Err(e);
                        }
                    }
                }
            }
        }

        submit_retries -= 1;
    }

    Err(ProverError::new("Failed to submit proof after all retries"))
}


async fn authenticated_proving(
    node_id: &str,
    environment: &config::Environment,
) -> Result<(), ProverError> {
    let client = Arc::new(OrchestratorClient::new(environment.clone()));
    let config = ProverConfig::default();
    
    // 获取任务
    let proof_task = {
        let (shutdown_tx, _) = broadcast::channel(1);
        let shutdown_tx = Arc::new(shutdown_tx);
        let mut handles = Vec::with_capacity(config.feach_num_threads);

        for thread_id in 0..config.feach_num_threads {
            let client = Arc::clone(&client);
            let node_id = node_id.to_string();
            let shutdown_tx = Arc::clone(&shutdown_tx);  // 在循环中克隆 Arc
            let shutdown_rx = shutdown_tx.subscribe();
            let config = config.clone();

            let delay = rand::random::<u64>() % 100;
            tokio::time::sleep(tokio::time::Duration::from_millis(delay)).await;

            handles.push(tokio::spawn(async move {
                fetch_task_with_timeout(
                    client,
                    &node_id,
                    thread_id,
                    shutdown_rx,
                    (*shutdown_tx).clone(),
                    &config
                ).await
            }));
        }

        let mut futures = FuturesUnordered::new();
        for handle in handles {
            futures.push(handle);
        }

        let mut success_task = None;
        while let Some(result) = futures.next().await {
            match result {
                Ok(Ok(task)) => {
                    success_task = Some(task);
                    break;
                }
                Ok(Err(_)) => continue,
                Err(_) => continue,
            }
        }

        // 等待一小段时间确保其他线程收到停止信号
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        success_task.ok_or_else(|| ProverError::new("All threads failed to fetch task"))?
    };

    let current_time = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
    println!("[{}] 2. Received a task to prove from Nexus Orchestrator...", current_time);

    let public_input: u32 = proof_task.public_inputs[0] as u32;

    let current_time = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
    println!("[{}] 3. Compiling guest program...", current_time);
    let elf_file_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("assets")
        .join("fib_input");
    let prover = Stwo::<Local>::new_from_file(&elf_file_path)
        .map_err(|e| ProverError::new(e.to_string()))?;

    let current_time = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
    println!("[{}] 4. Creating ZK proof with inputs", current_time);
    let (view, proof) = prover
        .prove_with_input::<(), u32>(&(), &public_input)
        .map_err(|e| ProverError::new(e.to_string()))?;

    assert_eq!(view.exit_code().expect("failed to retrieve exit code"), 0);

    let proof_bytes = serde_json::to_vec(&proof)
        .map_err(|e| ProverError::new(e.to_string()))?;
    let proof_hash = format!("{:x}", Keccak256::digest(&proof_bytes));

    let current_time = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
    println!("[{}] \tProof size: {} bytes", current_time, proof_bytes.len());

    // 提交证明部分
    {
        let (shutdown_tx, _) = broadcast::channel(1);
        let shutdown_tx = Arc::new(shutdown_tx);
        let mut handles = Vec::with_capacity(config.submit_num_threads);
        
        for thread_id in 0..config.submit_num_threads {
            let client = Arc::clone(&client);
            let node_id = node_id.to_string();
            let proof_hash = proof_hash.clone();
            let proof_bytes = proof_bytes.clone();
            let shutdown_rx = shutdown_tx.subscribe();
            let config = config.clone();  // 克隆config
            // 直接在调用时克隆，避免中间变量
            
            let delay = rand::random::<u64>() % 100;
            tokio::time::sleep(tokio::time::Duration::from_millis(delay)).await;

            handles.push(tokio::spawn(async move {
                submit_proof_with_timeout(
                    client, 
                    &node_id,
                    proof_hash,
                    proof_bytes,
                    thread_id,
                    shutdown_rx,
                    &config
                ).await
            }));
        }

        let mut futures = FuturesUnordered::new();
        for handle in handles {
            futures.push(handle);
        }

        let mut success = false;
        while let Some(result) = futures.next().await {
            match result {
                Ok(Ok(_)) => {
                    success = true;
                    let _ = shutdown_tx.send(());  // 确保成功时发送停止信号
                    break;
                }
                Ok(Err(_)) | Err(_) => continue,
            }
        }

        // 等待一小段时间确保其他线程收到停止信号
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        if success {
            let current_time = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
            println!("[{}] {}", current_time, "6. ZK proof successfully submitted".green());
            Ok(())
        } else {
            Err(ProverError::new("All threads failed to submit proof"))
        }
    }
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
