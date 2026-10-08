//! Run explicitly with `cargo test -p logshield-api --test lab_e2e -- --ignored`.
//! This test boots only the fixed-target localhost Docker lab.
use reqwest::Client;
use serde_json::Value;
use std::{process::Command, time::Duration};

const API: &str = "http://127.0.0.1:3000/api";
async fn json(client: &Client, path: &str) -> Value {
    client
        .get(format!("{API}{path}"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap()
}
async fn post(client: &Client, path: &str) -> Value {
    client
        .post(format!("{API}{path}"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap()
}
async fn wait_for<F: Fn(&Value) -> bool>(client: &Client, path: &str, predicate: F) -> Value {
    for _ in 0..80 {
        if let Ok(r) = client.get(format!("{API}{path}")).send().await
            && let Ok(v) = r.json::<Value>().await
            && predicate(&v)
        {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("timed out waiting for {path}")
}
#[tokio::test]
#[ignore = "requires Docker Compose; boots the isolated local lab"]
async fn real_logs_gateway_containment_and_failure() {
    let started = Command::new("docker")
        .args(["compose", "up", "-d"])
        .status()
        .expect("docker compose");
    assert!(started.success());
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let _ = wait_for(&client, "/status", |v| {
        v["gateway"] == true && v["sensor"] == true && v["services_online"] == 3
    })
    .await;
    post(&client, "/lab/clear").await;
    post(&client, "/lab/run/normal").await;
    let normal = wait_for(&client, "/stats", |v| {
        v["events_processed"].as_u64().unwrap_or(0) >= 3
    })
    .await;
    assert_eq!(normal["critical_incidents"], 0);
    let run = post(&client, "/lab/run/distributed").await;
    let requests = run["requests"].as_array().unwrap();
    assert_eq!(requests.len(), 5);
    assert!(requests.iter().all(|x| x["status"] == 401));
    let incidents = wait_for(&client, "/incidents", |v| {
        v.as_array().is_some_and(|a| {
            a.iter().any(|i| {
                i["kind"] == "DISTRIBUTED AUTHENTICATION ATTACK" && i["status"] == "CONTAINED"
            })
        })
    })
    .await;
    let incident = incidents
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["kind"] == "DISTRIBUTED AUTHENTICATION ATTACK")
        .unwrap();
    assert!(incident["risk"].as_u64().unwrap() >= 85);
    let events = incident["events"].as_array().unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|e| e["event_type"] == "failed_login")
            .count(),
        5
    );
    for host in ["app-a", "app-b", "app-c"] {
        assert!(
            events
                .iter()
                .filter(|e| e["hostname"] == host && e["event_type"] == "failed_login")
                .count()
                < 5
        );
    }
    assert_eq!(
        incident["response"]["proof"]
            .as_array()
            .unwrap()
            .last()
            .unwrap()["stage"],
        "CONTAINMENT_VERIFIED"
    );
    let id = incident["id"].as_str().unwrap();
    let verification = json(&client, &format!("/incidents/{id}/response")).await;
    assert_eq!(verification["verification_attempts"][0]["status"], 403);
    assert_eq!(
        verification["verification_attempts"][0]["body"]["blocked"],
        true
    );
    assert!(
        !json(&client, "/events")
            .await
            .as_array()
            .unwrap()
            .is_empty()
    );
    let restarted = Command::new("docker")
        .args(["compose", "restart", "logshield-api"])
        .status()
        .expect("restart API container");
    assert!(restarted.success());
    let _ = wait_for(&client, "/status", |v| v["database"] == true).await;
    let persisted = json(&client, "/incidents").await;
    assert!(persisted.as_array().unwrap().iter().any(|i| i["id"] == id));
    assert!(
        !json(&client, "/events")
            .await
            .as_array()
            .unwrap()
            .is_empty()
    );
    post(&client, "/lab/clear").await;
    client
        .post(format!("{API}/lab/force-failure"))
        .json(&serde_json::json!({"enabled":true}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let failed_run = post(&client, "/lab/run/distributed").await;
    assert!(
        failed_run["requests"]
            .as_array()
            .unwrap()
            .iter()
            .all(|x| x["status"] == 401)
    );
    let failed = wait_for(&client, "/incidents", |v| {
        v.as_array()
            .is_some_and(|a| a.iter().any(|i| i["status"] == "RESPONSE_FAILED"))
    })
    .await;
    let i = &failed.as_array().unwrap()[0];
    assert_eq!(i["status"], "RESPONSE_FAILED");
    assert_eq!(
        i["response"]["proof"].as_array().unwrap().last().unwrap()["stage"],
        "RESPONSE_FAILED"
    );
    let verify = json(
        &client,
        &format!("/incidents/{}/response", i["id"].as_str().unwrap()),
    )
    .await;
    assert_eq!(verify["verification_attempts"][0]["status"], 401);
    assert_ne!(i["status"], "CONTAINED");
}
