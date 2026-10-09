# Remote showcase and local fallback

The VPS hosts the same controlled LogShield lab as the laptop. It is a remote, production-style **demonstration**, not a publicly exposed production security service. Three Rust application replicas use one Redis-backed session and PostgreSQL application records. Each replica writes JSON logs; a read-only Rust agent sends those records through the authenticated ingestion API. TACG and the gateway run in Rust. All test requests target these fixed Docker services. The dashboard and API listen only on the VPS loopback interface.

## Open the VPS dashboard

On the Fedora laptop, keep this SSH tunnel open:

```bash
ssh -i ~/.ssh/logshield_vps -N -L 127.0.0.1:5174:127.0.0.1:5173 root@YOUR_VPS_HOST
```

Open <http://127.0.0.1:5174>. The VPS serves the built frontend through Nginx, which proxies `/api` and `/ws/events` to LogShield. No application, database, gateway, or dashboard port is published on the VPS public address.

## Five-step demonstration

1. **Dashboard:** show seven components healthy and zero events before the test.
2. **Infrastructure:** run **Normal shared login**. Real requests flow through the gateway, password/MFA, Redis session, and three Rust replicas. Open **SDK Live Logs** to show the three agent streams. No critical incident should appear.
3. **Local lab:** clear the data, then return to **Infrastructure** and run **Distributed 2/2/1**. The five actual HTTP responses are 401, distributed across `infra-a`, `infra-b`, and `infra-c`.
4. **SDK Live Logs and Incidents:** show the five agent-origin logs, the 2/2/1 per-host evidence, a `DISTRIBUTED AUTHENTICATION ATTACK` incident, and its explainable risk.
5. **Responses:** show `ACTION_REQUESTED → GATEWAY_BLOCK_APPLIED → VERIFICATION_REQUEST_SENT → HTTP_403_RECEIVED → CONTAINMENT_VERIFIED`. The incident becomes `CONTAINED` only after the gateway's real 403 response. Clear the lab after presenting.

To show the failure proof separately, clear the lab, enable **Force response failure**, and repeat the distributed test. The gateway rejects the block with HTTP 503; the verification request reaches an app and returns HTTP 401; the incident becomes `RESPONSE_FAILED`. Clear the lab to disable the switch.

## Restart VPS services

```bash
ssh -i ~/.ssh/logshield_vps root@YOUR_VPS_HOST
cd /opt/logshield
docker compose -f docker-compose.yml -f docker-compose.vps.yml up -d --no-build
curl -fsS http://127.0.0.1:5173/api/status
```

The remote `.env` contains locally generated demo credentials and is readable only by root. Do not copy the laptop `.env` to the VPS or commit either file.

## Local fallback

The laptop runs the same application pipeline and has been tested end to end. If the VPS or SSH tunnel is unavailable:

```bash
cd /home/neonjava/logshield
docker compose up -d
cd frontend
npm run dev
```

Open <http://127.0.0.1:5173>. Use the same five-step demonstration. The local frontend proxies `/api` and `/ws/events` to the local Rust API. **Clear lab data** before the presentation so the counters start at zero.

## Verified on 2026-10-09

- VPS: `infra-a = 2`, `infra-b = 2`, `infra-c = 1` failed logins, all below the per-host threshold of five; five event origins were `agent:infra-*`.
- VPS: TACG assigned risk 92 and the gateway verification recorded HTTP 403 before `CONTAINED`.
- VPS failure mode: gateway refusal was HTTP 503, subsequent request was HTTP 401, and the incident was `RESPONSE_FAILED`.
- VPS and laptop were cleared afterward: zero events and incidents, response failure off, all services online.
- Laptop: `cargo test -p logshield-api --test lab_e2e -- --ignored` passed and tested normal traffic, containment, persistence, and response failure.

The remote deployment is intentionally private. Operator authentication, TLS for non-tunneled access, secret rotation, durable agent acknowledgments, and tenant isolation are future requirements before use on an organization’s real logs.
