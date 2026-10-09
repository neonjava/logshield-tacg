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

    // Manual requests from the three visible sample pages use the same real log path.
    post(&client, "/lab/clear").await;
    for app in ["app-a", "app-a", "app-b", "app-b", "app-c"] {
        let attempt = client
            .post(format!("{API}/lab/attempt"))
            .json(&serde_json::json!({
                "app": app,
                "operation": "login",
                "source": "attacker-lab",
                "password": "wrong"
            }))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json::<Value>()
            .await
            .unwrap();
        assert_eq!(attempt["attempt"]["status"], 401);
    }
    let manual_incident = wait_for(&client, "/incidents", |v| {
        v.as_array().is_some_and(|items| {
            items.iter().any(|i| {
                i["kind"] == "DISTRIBUTED AUTHENTICATION ATTACK" && i["status"] == "CONTAINED"
            })
        })
    })
    .await;
    assert!(manual_incident[0]["risk"].as_u64().unwrap_or(0) >= 85);

    post(&client, "/lab/clear").await;
    let normal_infra = post(&client, "/infra/run/normal").await;
    let steps = normal_infra["requests"].as_array().unwrap();
    assert_eq!(steps[0]["status"], 200); // password accepted, MFA still required
    assert!(steps[0]["body"].get("token").is_none());
    assert_eq!(steps[1]["status"], 200); // MFA completes login
    assert_eq!(steps[1]["body"]["authenticated"], true);
    let replicas: std::collections::HashSet<_> = steps[2..5]
        .iter()
        .filter_map(|r| r["body"]["served_by"].as_str())
        .collect();
    assert_eq!(replicas.len(), 3); // one session works on all three replicas
    assert!(steps[5..].iter().all(|r| r["status"] == 200));
    let ingested = wait_for(&client, "/events", |v| {
        v.as_array().is_some_and(|a| {
            a.iter().any(|e| e["origin"] == "agent:infra-a")
                && a.iter().any(|e| e["origin"] == "agent:infra-b")
                && a.iter().any(|e| e["origin"] == "agent:infra-c")
        })
    })
    .await;
    assert!(ingested.as_array().unwrap().len() >= 6);
    assert_eq!(json(&client, "/stats").await["critical_incidents"], 0);
    assert!(
        json(&client, "/infra/activities").await["activities"]
            .as_array()
            .unwrap()
            .len()
            >= 3
    );

    for (scenario, kind) in [
        ("bruteforce", "BRUTE FORCE AUTHENTICATION"),
        ("suspicious", "SUSPICIOUS SUCCESSFUL LOGIN"),
        ("mfa", "REPEATED MFA FAILURES"),
        ("distributed", "DISTRIBUTED AUTHENTICATION ATTACK"),
    ] {
        post(&client, "/lab/clear").await;
        let run = post(&client, &format!("/infra/run/{scenario}")).await;
        assert!(run["requests"].as_array().unwrap().len() >= 3);
        let incident = wait_for(&client, "/incidents", |v| {
            v.as_array()
                .is_some_and(|a| a.iter().any(|i| i["kind"] == kind))
        })
        .await;
        let found = incident
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["kind"] == kind)
            .unwrap();
        assert!(found["risk"].as_u64().unwrap() >= 70);
        if scenario == "suspicious" {
            let contained = wait_for(&client, "/incidents", |v| {
                v.as_array().is_some_and(|a| {
                    a.iter()
                        .any(|i| i["kind"] == kind && i["status"] == "CONTAINED")
                })
            })
            .await;
            let proof = contained
                .as_array()
                .unwrap()
                .iter()
                .find(|i| i["kind"] == kind)
                .unwrap()["response"]["proof"]
                .as_array()
                .unwrap()
                .clone();
            assert!(
                proof
                    .iter()
                    .any(|step| step["stage"] == "SESSION_REVOCATION_VERIFIED")
            );
        }
        if scenario == "distributed" {
            let contained = wait_for(&client, "/incidents", |v| {
                v.as_array().is_some_and(|a| {
                    a.iter()
                        .any(|i| i["kind"] == kind && i["status"] == "CONTAINED")
                })
            })
            .await;
            let i = contained
                .as_array()
                .unwrap()
                .iter()
                .find(|i| i["kind"] == kind)
                .unwrap();
            for host in ["infra-a", "infra-b", "infra-c"] {
                assert!(
                    i["events"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .filter(|e| e["hostname"] == host && e["event_type"] == "failed_login")
                        .count()
                        < 5
                );
            }
            assert_eq!(
                i["response"]["proof"].as_array().unwrap().last().unwrap()["stage"],
                "CONTAINMENT_VERIFIED"
            );
        }
    }
    post(&client, "/lab/clear").await;
    let sample = client
        .get(format!("{API}/logs/sample/mfa"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let upload = |bytes: Vec<u8>| {
        reqwest::multipart::Form::new().part(
            "file",
            reqwest::multipart::Part::bytes(bytes).file_name("mfa.jsonl"),
        )
    };
    let imported: Value = client
        .post(format!("{API}/logs/upload"))
        .multipart(upload(sample.to_vec()))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(imported["accepted"], 3);
    let imported_incident = wait_for(&client, "/incidents", |v| {
        v.as_array()
            .is_some_and(|a| a.iter().any(|i| i["kind"] == "REPEATED MFA FAILURES"))
    })
    .await;
    assert!(imported_incident[0]["response"].is_null());
    let repeat: Value = client
        .post(format!("{API}/logs/upload"))
        .multipart(upload(sample.to_vec()))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(repeat["duplicates"], 3);
    let exported = client
        .get(format!("{API}/logs/export"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(exported.lines().count(), 3);
}
