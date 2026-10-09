# LogShield workflow

Copy this flowchart to a slide or draw the same boxes and arrows on a sheet. The left browser window sends requests to the controlled application; the right window displays the SDK log stream and investigation.

```mermaid
flowchart TD
    A([Start]) --> B[User sends a login or app request]
    B --> C[Rust gateway routes request]
    C --> D{Application replica}
    D --> E[infra-a]
    D --> F[infra-b]
    D --> G[infra-c]
    E --> H[Replica writes its own JSON log]
    F --> H
    G --> H
    H --> I[Rust agent reads new log lines]
    I --> J[Authenticated LogShield ingestion API]
    J --> K[Normalize and save event in SQLite]
    K --> L[SDK Live Logs tab updates]
    K --> M[TACG links source, user, host and time]
    M --> N{Suspicious linked pattern?}
    N -- No --> O[Keep event for monitoring]
    N -- Yes --> P[Create incident and explain risk]
    P --> Q{Risk and confidence permit response?}
    Q -- No --> R[Alert analyst and recommend action]
    Q -- Yes --> S[Gateway blocks controlled source]
    S --> T[Client retries through gateway]
    T --> U{Actual HTTP 403?}
    U -- Yes --> V([Contained and verified])
    U -- No --> W([Response failed: human review])
```

**Distributed example:** five failed requests from one controlled source reach `infra-a` twice, `infra-b` twice, and `infra-c` once. Every replica stays below a five-failure host threshold. TACG links the agent-delivered logs across all three replicas and creates one explainable incident. A gateway block is considered successful only after a real retry returns HTTP 403.

**Fallback:** the same boxes run on the laptop if the VPS or SSH tunnel is unavailable. Only the dashboard URL changes from port `5174` (VPS tunnel) to port `5173` (local Vite).
