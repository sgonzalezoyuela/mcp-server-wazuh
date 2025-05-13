use std::fs::OpenOptions;
use std::io::Write;
use tracing::error;

const REQUEST_LOG_FILE: &str = "mcp_requests.log";
const RESPONSE_LOG_FILE: &str = "mcp_responses.log";

fn log_to_file(filename: &str, message: &str) {
    match OpenOptions::new().create(true).append(true).open(filename) {
        Ok(mut file) => {
            if let Err(e) = writeln!(file, "{}", message) {
                error!("Failed to write to {}: {}", filename, e);
            }
        }
        Err(e) => {
            error!("Failed to open {} for appending: {}", filename, e);
        }
    }
}

pub fn log_mcp_request(request_str: &str) {
    log_to_file(REQUEST_LOG_FILE, request_str);
}

pub fn log_mcp_response(response_str: &str) {
    log_to_file(RESPONSE_LOG_FILE, response_str);
}
