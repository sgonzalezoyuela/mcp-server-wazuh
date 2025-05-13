use chrono::{DateTime, Utc, SecondsFormat};
use serde_json::{json, Value};
use tracing::{debug, warn};

pub fn transform_to_mcp(event: Value, event_type: String) -> Value {
    debug!(?event, %event_type, "Entering transform_to_mcp");

    let source_obj = event.get("_source").unwrap_or(&event);
    if event.get("_source").is_some() {
        debug!("Event contains '_source' field, using it for transformation.");
    } else {
        debug!("Event does not contain '_source' field, using the event root for transformation.");
    }

    let id = source_obj.get("id")
        .and_then(|v| v.as_str())
        .or_else(|| event.get("_id").and_then(|v| v.as_str()))
        .unwrap_or("unknown_id")
        .to_string();
    debug!(%id, "Transformed: id");

    let default_rule = json!({});
    let rule = source_obj.get("rule").unwrap_or(&default_rule);
    if source_obj.get("rule").is_none() {
        debug!("Transformed: rule (defaulted to empty object)");
    } else {
        debug!(?rule, "Transformed: rule");
    }
    let category = rule.get("groups")
        .and_then(|g| g.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| v.as_str())
        .unwrap_or("unknown_category")
        .to_string();
    debug!(%category, "Transformed: category");

    let severity_level = rule.get("level").and_then(|v| v.as_u64());
    let severity = severity_level
        .map(|level| match level {
            0..=3 => "low",
            4..=7 => "medium",
            8..=11 => "high",
            _ => "critical",
        })
        .unwrap_or("unknown_severity")
        .to_string();
    debug!(?severity_level, %severity, "Transformed: severity");

    let description = rule.get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    debug!(%description, "Transformed: description");

    let default_data = json!({});
    let data = source_obj.get("data").cloned().unwrap_or_else(|| {
        debug!("Transformed: data (defaulted to empty object)");
        default_data.clone()
    });
    if source_obj.get("data").is_some() {
        debug!(?data, "Transformed: data");
    }


    let default_agent = json!({});
    let agent = source_obj.get("agent").cloned().unwrap_or_else(|| {
        debug!("Transformed: agent (defaulted to empty object)");
        default_agent.clone()
    });
    if source_obj.get("agent").is_some() {
        debug!(?agent, "Transformed: agent");
    }


    let timestamp_str = source_obj.get("timestamp")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    debug!(%timestamp_str, "Attempting to parse timestamp");

    let timestamp = DateTime::parse_from_rfc3339(timestamp_str)
        .map(|dt| dt.with_timezone(&Utc))
        .or_else(|_| DateTime::parse_from_str(timestamp_str, "%Y-%m-%dT%H:%M:%S%.fZ").map(|dt| dt.with_timezone(&Utc)))
        .unwrap_or_else(|_| {
            warn!("Failed to parse timestamp '{}' for alert ID '{}'. Using current time.", timestamp_str, id);
            Utc::now()
        });
    debug!(%timestamp, "Transformed: timestamp");

    let notes = "Data fetched via Wazuh API".to_string();
    debug!(%notes, "Transformed: notes");

    let mcp_message = json!({
        "protocolVersion": "1.0", // Match initialize response
        "source": "Wazuh",
        "timestamp": timestamp.to_rfc3339_opts(SecondsFormat::Secs, true),
        "event_type": event_type,
        "context": {
            "id": id,
            "category": category,
            "severity": severity,
            "description": description,
            "agent": agent,
            "data": data
        },
        "metadata": {
            "integration": "Wazuh-MCP",
            "notes": notes
        }
    });
    debug!(?mcp_message, "Exiting transform_to_mcp with result");
    mcp_message
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use serde_json::json;

    #[test]
    fn test_transform_to_mcp_basic() {
        let event_time_str = "2023-10-27T10:30:00.123Z";
        let event_time = Utc.datetime_from_str(event_time_str, "%Y-%m-%dT%H:%M:%S%.fZ").unwrap();

        let event = json!({
            "id": "alert1",
            "_id": "wazuh_alert_id_1",
            "timestamp": event_time_str,
            "rule": {
                "level": 10,
                "description": "High severity rule triggered",
                "id": "1002",
                "groups": ["gdpr", "pci_dss", "intrusion_detection"]
            },
            "agent": {
                "id": "001",
                "name": "server-db"
            },
            "data": {
                "srcip": "1.2.3.4",
                "dstport": "22"
            }
        });

        let result = transform_to_mcp(event.clone(), "alert".to_string());

        assert_eq!(result["protocol_version"], "1.0");
        assert_eq!(result["source"], "Wazuh");
        assert_eq!(result["event_type"], "alert");
        assert_eq!(result["timestamp"], event_time.to_rfc3339_opts(SecondsFormat::Secs, true));

        let context = &result["context"];
        assert_eq!(context["id"], "alert1");
        assert_eq!(context["category"], "gdpr");
        assert_eq!(context["severity"], "high");
        assert_eq!(context["description"], "High severity rule triggered");
        assert_eq!(context["agent"]["name"], "server-db");
        assert_eq!(context["data"]["srcip"], "1.2.3.4");

        let metadata = &result["metadata"];
        assert_eq!(metadata["integration"], "Wazuh-MCP");
        assert_eq!(metadata["notes"], "Data fetched via Wazuh API");
    }

     #[test]
    fn test_transform_to_mcp_with_source_nesting() {
         let event_time_str = "2023-10-27T11:00:00Z";
         let event_time = DateTime::parse_from_rfc3339(event_time_str).unwrap().with_timezone(&Utc);

        let event = json!({
            "_index": "wazuh-alerts-4.x-2023.10.27",
            "_id": "alert_source_nested",
            "_source": {
                 "id": "nested_alert_id",
                 "timestamp": event_time_str,
                 "rule": {
                     "level": 5,
                     "description": "Medium severity rule",
                     "groups": ["system_audit"]
                 },
                 "agent": { "id": "002", "name": "web-server" },
                 "data": { "command": "useradd test" }
            }
        });

        let result = transform_to_mcp(event.clone(), "alert".to_string());
        assert_eq!(result["timestamp"], event_time.to_rfc3339_opts(SecondsFormat::Secs, true));
        let context = &result["context"];
        assert_eq!(context["id"], "nested_alert_id");
        assert_eq!(context["category"], "system_audit");
        assert_eq!(context["severity"], "medium");
        assert_eq!(context["description"], "Medium severity rule");
        assert_eq!(context["agent"]["name"], "web-server");
        assert_eq!(context["data"]["command"], "useradd test");
     }


    #[test]
    fn test_transform_to_mcp_with_defaults() {
        let event = json!({});
        let before_transform = Utc::now();
        let result = transform_to_mcp(event, "alert".to_string());
        let after_transform = Utc::now();

        assert_eq!(result["context"]["id"], "unknown_id");
        assert_eq!(result["context"]["category"], "unknown_category");
        assert_eq!(result["context"]["severity"], "unknown_severity");
        assert_eq!(result["context"]["description"], "");
        assert!(result["context"]["data"].is_object());
        assert!(result["context"]["agent"].is_object());
        assert_eq!(result["metadata"]["notes"], "Data fetched via Wazuh API");

        let result_ts_str = result["timestamp"].as_str().unwrap();
        let result_ts = DateTime::parse_from_rfc3339(result_ts_str).unwrap().with_timezone(&Utc);
        assert!(result_ts.timestamp() >= before_transform.timestamp() && result_ts.timestamp() <= after_transform.timestamp());
    }

    #[test]
    fn test_transform_timestamp_parsing_fallback() {
        let event = json!({
            "id": "ts_test",
            "timestamp": "invalid-timestamp-format",
             "rule": { "level": 3 },
        });
        let before_transform = Utc::now();
        let result = transform_to_mcp(event, "alert".to_string());
        let after_transform = Utc::now();

        let result_ts_str = result["timestamp"].as_str().unwrap();
        let result_ts = DateTime::parse_from_rfc3339(result_ts_str).unwrap().with_timezone(&Utc);
        assert!(result_ts.timestamp() >= before_transform.timestamp() && result_ts.timestamp() <= after_transform.timestamp());
        assert_eq!(result["context"]["id"], "ts_test");
        assert_eq!(result["context"]["severity"], "low");
    }
}
