# Real-world problem

Per-host authentication rules see only their own logs. If an adversary spreads a few attempts across several systems, each host can remain below its local alert threshold. Analysts must then manually connect source identity, account, timing and later actions across log streams.

LogShield demonstrates that failure mode in a controlled environment: two failed requests to app A, two to B, one to C. The apps actually receive the HTTP requests and write the log lines. The sensor ingests those files. TACG links the records and produces a cross-host incident. The gateway blocks the controlled source, and the client retries so the response has observable proof.

This is a defensive prototype, not a production intrusion prevention system. It demonstrates a verifiable approach to correlation and response without claiming to invent event correlation or to protect external infrastructure.
