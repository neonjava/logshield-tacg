# Exact two-minute demonstration

Prepare once: run the release build, `docker compose build`, `docker compose up -d`, and `npm run dev`. Open `http://127.0.0.1:5173`, go to **Lab**, and click **Clear lab data**. Return to Overview. All traffic stays inside fixed Docker networks.

| Time | Action and narration |
|---|---|
| 0:00–0:15 | Open **Overview**. Point to Gateway ONLINE, Sensor ONLINE, TACG ONLINE, Database ONLINE and Lab Services 3/3. “These are live processes, not dashboard placeholders.” |
| 0:15–0:30 | Open **Lab**, click **Start normal traffic**. Return to Overview or Events. Show three real successful login records and zero critical incidents. |
| 0:30–0:45 | Back in Lab, click **Start distributed auth test**. Show five actual HTTP 401 results from the controlled client. |
| 0:45–1:00 | Open **Events**. Show app-a twice, app-b twice, app-c once, all source `attacker-lab`, username `demo`. Click a row to show the raw JSON log. |
| 1:00–1:15 | Open the new **Incident**. Point to each host's count under 5/5 and to the three-host TACG graph. “The per-host rule sees no alert; TACG sees one linked attack.” |
| 1:15–1:35 | Show the score bars, reasons, time window and actual event edges. “Every point is explainable.” |
| 1:35–1:50 | Scroll to Response. Show `GATEWAY_BLOCK_APPLIED`, `VERIFICATION_REQUEST_SENT`, `HTTP_403_RECEIVED`, `CONTAINMENT_VERIFIED`. “The client retried and the gateway denied it.” |
| 1:50–2:00 | “The whole monitoring and response pipeline is native Rust. This proves cross-host detection and measured containment in our isolated local lab.” |

Optional judge follow-up: clear lab data, enable **Force response failure**, rerun distributed auth and show gateway HTTP 503, client HTTP 401, and `RESPONSE_FAILED` with human intervention required.

## Hands-on three-app showcase

Open **Lab** and use the three sample-app links, or open `http://127.0.0.1:5173/lab/app-a`, `/lab/app-b`, and `/lab/app-c` in separate tabs. These are client views for the fixed Docker services. Choose `attacker-lab` as the source and enter any incorrect password. Each click sends a real request through the Rust client and gateway to that app; the app writes a JSON log, and the Rust sensor reads it. The page displays the actual gateway HTTP status. The only valid dummy password is `hackathon123`.

For a terminal presentation, run these fixed-target commands from the host. No arbitrary URL or external destination is accepted:

```bash
cd /home/neonjava/logshield
curl -sS -X POST http://127.0.0.1:3000/api/lab/clear
for app in app-a app-a app-b app-b app-c; do
  curl -sS -X POST http://127.0.0.1:3000/api/lab/attempt \
    -H 'Content-Type: application/json' \
    -d "{\"app\":\"$app\",\"operation\":\"login\",\"source\":\"attacker-lab\",\"password\":\"wrong\"}"
  echo
  sleep 1
done
```

Then open **Events** and **Incidents**. Each host has fewer than five failures; TACG correlates all three hosts. The fifth request creates the incident. The automatic verification retry receives HTTP 403, after which the incident becomes `CONTAINED`. To show a multi-stage sequence, clear lab data and use **Start multi-stage test** in Lab; it sends two failures, a valid dummy login, a safe lab admin operation, and a local outbound-style request through the same path.
