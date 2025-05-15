use std::process::{Command, Stdio};
use std::collections::HashMap;
use std::error::Error;

/// Deploy contracts using the provided configuration
///
/// # Arguments
///
/// * `rpc_url` - The RPC URL for the blockchain node
/// * `deployer_private_key` - Private key for the deployer account
/// * `faucet_private_key` - Private key for the faucet account to fund the deployer
/// * `assertion_da_private_key` - Private key for the DA prover
///
/// # Returns
///
/// * `Result<(), Box<dyn Error>>` - Success or error
pub fn deploy_contracts(
    rpc_url: &str,
    deployer_private_key: &str,
    faucet_private_key: &str,
    assertion_da_private_key: &str,
) -> Result<(), Box<dyn Error>> {
    // Build the bash script with the provided arguments
    let script_content = format!(r#"
RPC_URL='{}'
DEPLOYER_PRIVATE_KEY='{}'
PLAYGROUND_FAUCET_PRIVATE_KEY='{}'
PLAYGROUND_ASSERTION_DA_PRIVATE_KEY='{}'

cast chain-id --rpc-url $RPC_URL
DEPLOYER_ADDRESS="$(cast w a ${{DEPLOYER_PRIVATE_KEY}})"
# Fund the deployer account with 1 ETH
cast send --rpc-url "$RPC_URL" \
  --private-key "$PLAYGROUND_FAUCET_PRIVATE_KEY" \
  --value 1ether \
  "$DEPLOYER_ADDRESS"
# Set the DA_PROVER_ADDRESS environment variable
export DA_PROVER_ADDRESS="$(cast w a ${{PLAYGROUND_ASSERTION_DA_PRIVATE_KEY}})"
forge script script/DeployCore.s.sol:DeployCore \
  --rpc-url "$RPC_URL" \
  --private-key "$DEPLOYER_PRIVATE_KEY" \
  --root "PROJECT_ROOT" \
  --broadcast
"#, rpc_url, deployer_private_key, faucet_private_key, assertion_da_private_key);

    // Validate inputs
    if rpc_url.is_empty() {
        return Err("RPC URL cannot be empty".into());
    }
    if deployer_private_key.is_empty() {
        return Err("Deployer private key cannot be empty".into());
    }
    if faucet_private_key.is_empty() {
        return Err("Faucet private key cannot be empty".into());
    }
    if assertion_da_private_key.is_empty() {
        return Err("Assertion DA private key cannot be empty".into());
    }

    // Execute the bash script directly using bash -c
    println!("Executing blockchain deployment script...");
    let mut cmd = Command::new("bash");
    cmd.arg("-c")
       .arg(script_content)
       .stdout(Stdio::inherit())
       .stderr(Stdio::inherit());
    
    let status = cmd.status()?;

    // Check if the script executed successfully
    if status.success() {
        println!("Script executed successfully!");
        Ok(())
    } else {
        eprintln!("Script execution failed with exit code: {:?}", status.code());
        Err("Script execution failed".into())
    }
}
