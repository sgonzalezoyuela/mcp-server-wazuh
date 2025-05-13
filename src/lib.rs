use crate::wazuh::client::WazuhIndexerClient;
use tokio::sync::Mutex;

pub mod http_service;
pub mod logging_utils;
pub mod mcp;
pub mod stdio_service;
pub mod wazuh;

#[derive(Debug)]
pub struct AppState {
    pub wazuh_client: Mutex<WazuhIndexerClient>,
}
