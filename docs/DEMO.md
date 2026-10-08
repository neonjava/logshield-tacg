# Exact two-minute demo

Before presenting, start both services and open `http://127.0.0.1:5173`. Use a fresh local `logshield.db` for clean counts.

- **0:00–0:15:** “Traditional monitoring sees events independently. LogShield reconstructs a cross-host, multi-stage attack story with a native Rust engine.” Show empty command center and live stream.
- **0:15–0:30:** Click **Normal activity**. Point to processed events and zero incidents. “Normal activity remains quiet.”
- **0:30–0:50:** Click **Distributed low & slow**. Open the incident. Point to two failures on A, two on B, one on C, all from one source. “No single host sees a brute force threshold, but the graph sees five linked failures across three hosts.”
- **0:50–1:15:** Point to graph links, reasons and the six numeric score contributions. “The score is reproducible; the bonus reflects a coherent pattern.”
- **1:15–1:35:** Click **Multi-stage intrusion**. Open its critical incident. Walk down connection → port activity → failures → success → privilege → outbound activity.
- **1:35–1:50:** Point to the simulated response: source isolation, quarantine and evidence IDs. Wait three seconds for `CONTAINED`. “Verification checked the local observation window; no external firewall was touched.”
- **1:50–2:00:** “Rust lets this correlation pipeline run concurrently with memory safety and predictable performance. The entire security engine is native Rust.”
