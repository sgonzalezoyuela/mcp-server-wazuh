// Re-export the wazuh-client crate types for convenience
pub use wazuh_client::{
    WazuhClientFactory, WazuhClients, WazuhIndexerClient, WazuhApiError,
    AgentsClient, RulesClient, ConfigurationClient, VulnerabilityClient,
    ActiveResponseClient, ClusterClient, LogsClient, ConnectivityStatus
};
