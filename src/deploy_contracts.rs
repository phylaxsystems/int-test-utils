use alloy_signer::k256::ecdsa::SigningKey;
use std::process::{Command, ExitStatus, Stdio};

use alloy_node_bindings::AnvilInstance;
use alloy_primitives::{Address, address};
use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DeployContractsError {
    #[error("Command execution failed: {0}")]
    CommandError(ExitStatus),
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),
}

fn get_anvil_deployer(anvil_instance: &AnvilInstance) -> SigningKey {
    // Get the first private key from anvil's default accounts
    anvil_instance.keys()[0].clone().into()
}

/// Deploy the CREATE3 factory contract
///
/// # Arguments
///
/// * `anvil` - The Anvil instance to deploy to
/// * `project_root` - Root directory of the project
///
/// # Returns
///
/// * `Result<(), DeployContractsError>` - Success or error
pub fn deploy_create_factory(
    anvil: &AnvilInstance,
    project_root: std::path::PathBuf,
) -> Result<(), DeployContractsError> {
    let rpc_url = anvil.endpoint();

    let funder_private_key = get_anvil_deployer(anvil);

    let funder_pk_bytes = funder_private_key.to_bytes();
    let script_path = project_root.join("shell/deploy_create_x.sh");
    let fmt_funder_key = format!("{funder_pk_bytes:x}");

    // Execute the shell script
    let mut cmd = Command::new("bash");
    cmd.arg(script_path)
        .env("RPC_URL", rpc_url)
        .env("FUNDER_PRIVATE_KEY", fmt_funder_key)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let status = cmd.status()?;
    if !status.success() {
        return Err(DeployContractsError::CommandError(status));
    }

    Ok(())
}

#[derive(Debug)]
pub struct Contracts {
    pub state_oracle: Address,
}

/// Deploy contracts using the provided configuration
///
/// # Arguments
///
/// * `anvil` - The Anvil instance to deploy to
/// * `assertion_da_private_key` - Private key for the DA prover
/// * `project_root` - Root directory of the project
/// * `state_oracle_assertion_timelock_blocks` - Number of blocks to timelock assertions for
///
/// # Returns
///
/// * `Result<Contracts, DeployContractsError>` - The deployed contract addresses or an error
pub fn deploy_contracts(
    anvil: &AnvilInstance,
    assertion_da_private_key: SigningKey,
    project_root: std::path::PathBuf,
    state_oracle_assertion_timelock_blocks: usize,
) -> Result<Contracts, DeployContractsError> {
    let deployer_private_key = get_anvil_deployer(anvil);

    let rpc_url = anvil.endpoint();
    // Validate inputs
    deploy_create_factory(anvil, project_root.clone())?;

    let project_root = project_root.to_string_lossy();

    let deployer_pk_bytes = deployer_private_key.to_bytes();
    // Build the bash script with the provided arguments
    let mut cmd = Command::new("forge");
    cmd.arg("script")
        .arg("DeployCore")
        .arg("--rpc-url")
        .arg(rpc_url)
        .arg("--private-key")
        .arg(format!("{deployer_pk_bytes:x}"))
        .arg("--root")
        .arg(project_root.as_ref())
        .arg("--broadcast")
        .env("STATE_ORACLE_MAX_ASSERTIONS_PER_AA", "10")
        .env(
            "STATE_ORACLE_ASSERTION_TIMELOCK_BLOCKS",
            state_oracle_assertion_timelock_blocks.to_string(),
        )
        .env("STATE_ORACLE_ADMIN_ADDRESS", {
            let address = alloy_primitives::Address::from_private_key(&deployer_private_key);
            format!("{:#x}", address)
        })
        .env("DA_PROVER_ADDRESS", {
            let address = alloy_primitives::Address::from_private_key(&assertion_da_private_key);
            format!("{:#x}", address)
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let status = cmd.status()?;

    // Check if the script executed successfully
    if status.success() {
        Ok(Contracts {
            state_oracle: address!("f4e6da19139B9846b7d8712A05C218d9109b4308"),
        })
    } else {
        eprintln!(
            "Script execution failed with exit code: {:?}",
            status.code()
        );
        Err(DeployContractsError::CommandError(status))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use alloy_node_bindings::{Anvil, AnvilInstance};
    use std::error::Error;

    fn setup_anvil() -> Result<AnvilInstance, Box<dyn Error>> {
        // Configure and spawn anvil
        let anvil = Anvil::new().spawn();

        Ok(anvil)
    }

    #[test]
    fn test_deploy_contracts() -> Result<(), Box<dyn Error>> {
        let anvil = setup_anvil()?;

        let result = deploy_contracts(
            &anvil,
            SigningKey::random(&mut rand::thread_rng()), // Using same key for both roles in test
            std::path::PathBuf::from("lib/credible-layer-contracts"),
            5,
        );

        // Anvil instance will automatically be killed when dropped

        // Check deployment result
        assert!(
            result.is_ok(),
            "Contract deployment failed: {:?}",
            result.err()
        );
        Ok(())
    }

    #[test]
    fn test_deploy_deployer() -> Result<(), Box<dyn Error>> {
        let anvil = setup_anvil()?;

        let result = deploy_create_factory(
            &anvil,
            std::path::PathBuf::from("lib/credible-layer-contracts"),
        );

        // Check deployment result
        assert!(
            result.is_ok(),
            "Deployer deployment failed: {:?}",
            result.err()
        );
        Ok(())
    }
}
