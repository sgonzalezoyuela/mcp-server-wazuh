use reqwest::{header, Client};
use serde_json::Value;
use std::time::{Duration, SystemTime};
use tracing::{info, warn};

use super::error::WazuhApiError;

pub struct WazuhApiClient {
    username: String,
    password: String,
    base_url: String,
    jwt_token: Option<String>,
    jwt_expiration: Option<SystemTime>,
    auth_endpoint: String,
    http_client: Client,
}

impl WazuhApiClient {
    pub fn new(
        host: String,
        port: u16,
        username: String,
        password: String,
        verify_ssl: bool,
    ) -> Self {
        let base_url = format!("https://{}:{}", host, port);
        let http_client = Client::builder()
            .danger_accept_invalid_certs(!verify_ssl)
            .timeout(Duration::from_secs(10))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            username,
            password,
            base_url,
            jwt_token: None,
            jwt_expiration: None,
            auth_endpoint: "/security/user/authenticate".to_string(),
            http_client,
        }
    }

    fn is_jwt_valid(&self) -> bool {
        match (self.jwt_token.as_ref(), self.jwt_expiration) {
            (Some(_), Some(expiration)) => match expiration.duration_since(SystemTime::now()) {
                Ok(remaining) => remaining.as_secs() > 60,
                Err(_) => false,
            },
            _ => false,
        }
    }

    pub async fn get_jwt(&mut self) -> Result<String, WazuhApiError> {
        if self.is_jwt_valid() {
            return Ok(self.jwt_token.clone().unwrap());
        }

        let auth_url = format!("{}{}", self.base_url, self.auth_endpoint);
        info!("Requesting new JWT token from {}", auth_url);

        let response = self
            .http_client
            .post(&auth_url)
            .basic_auth(&self.username, Some(&self.password))
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(WazuhApiError::AuthenticationError(format!(
                "Authentication failed with status {}: {}",
                status, error_text
            )));
        }

        let data: Value = response.json().await?;
        let token = data
            .get("jwt")
            .and_then(|t| t.as_str())
            .ok_or(WazuhApiError::JwtNotFound)?
            .to_string();

        self.jwt_token = Some(token.clone());

        self.jwt_expiration = Some(SystemTime::now() + Duration::from_secs(5 * 60));

        info!("Obtained new JWT token valid for 5 minutes");
        Ok(token)
    }

    async fn make_request(
        &mut self,
        method: reqwest::Method,
        endpoint: &str,
        body: Option<Value>,
    ) -> Result<Value, WazuhApiError> {
        let jwt_token = self.get_jwt().await?;
        let url = format!("{}{}", self.base_url, endpoint);

        let mut request_builder = self
            .http_client
            .request(method.clone(), &url)
            .header(header::AUTHORIZATION, format!("Bearer {}", jwt_token));

        if let Some(json_body) = &body {
            request_builder = request_builder.json(json_body);
        }

        let response = request_builder.send().await?;

        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            warn!("JWT expired. Re-authenticating and retrying request.");
            self.jwt_token = None;
            let new_jwt_token = self.get_jwt().await?;

            let mut retry_builder = self
                .http_client
                .request(method, &url)
                .header(header::AUTHORIZATION, format!("Bearer {}", new_jwt_token));

            if let Some(json_body) = &body {
                retry_builder = retry_builder.json(json_body);
            }

            let retry_response = retry_builder.send().await?;

            if !retry_response.status().is_success() {
                let status = retry_response.status();
                let error_text = retry_response
                    .text()
                    .await
                    .unwrap_or_else(|_| "Unknown error".to_string());
                return Err(WazuhApiError::ApiError(format!(
                    "API request failed with status {}: {}",
                    status, error_text
                )));
            }

            Ok(retry_response.json().await?)
        } else if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            Err(WazuhApiError::ApiError(format!(
                "API request failed with status {}: {}",
                status, error_text
            )))
        } else {
            Ok(response.json().await?)
        }
    }

    pub async fn get_alerts(&mut self, query: Value) -> Result<Value, WazuhApiError> {
        let index_pattern = "wazuh-alerts-*";
        let endpoint = format!("/{}_search", index_pattern);

        info!("Retrieving alerts with index pattern '{}'", index_pattern);
        self.make_request(reqwest::Method::GET, &endpoint, Some(query))
            .await
    }
}
