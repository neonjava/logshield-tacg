import { useState } from "react";
import {
  ArrowRight,
  ExternalLink,
  FlaskConical,
  ShieldAlert,
} from "lucide-react";
import { post, safeJson } from "../api";
import {
  Badge,
  Card,
  ErrorNotice,
  Heading,
  RequestResults,
} from "../components/ui";
import type { SecurityStore } from "../hooks/useSecurity";
import type { HttpResult, ScenarioResult } from "../types";
const scenarios = [
  ["normal", "Normal traffic", "Valid local logins across the three apps."],
  [
    "distributed",
    "Distributed auth test",
    "Two failures on A, two on B, one on C.",
  ],
  [
    "multistage",
    "Multi-stage test",
    "Failures, success, lab admin action, and local outbound traffic.",
  ],
] as const;
export function Lab({ store }: { store: SecurityStore }) {
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [result, setResult] = useState<ScenarioResult | null>(null);
  const [force, setForce] = useState(
    store.health?.force_response_failure || false,
  );
  const [requests, setRequests] = useState<HttpResult[]>([]);
  const run = async (name: string) => {
    setBusy(name);
    setError("");
    try {
      const response = await post<ScenarioResult>(`/lab/run/${name}`);
      setResult(response);
      setRequests(response.requests || []);
      await store.refresh();
    } catch (error) {
      setError(String(error));
    } finally {
      setBusy("");
    }
  };
  const toggle = async () => {
    setBusy("toggle");
    setError("");
    try {
      const next = !force;
      await post("/lab/force-failure", { enabled: next });
      setForce(next);
      store.notify(
        "Lab response mode",
        next
          ? "Forced gateway failure enabled."
          : "Forced gateway failure disabled.",
        "neutral",
      );
      await store.refresh();
    } catch (error) {
      setError(String(error));
    } finally {
      setBusy("");
    }
  };
  const clear = async () => {
    setBusy("clear");
    setError("");
    try {
      await post("/lab/clear");
      setForce(false);
      setResult(null);
      setRequests([]);
      await store.refresh();
      store.notify(
        "Lab cleared",
        "Events, incidents, responses, and local blocks were reset.",
        "success",
      );
    } catch (error) {
      setError(String(error));
    } finally {
      setBusy("");
    }
  };
  return (
    <>
      <Heading
        title="Local lab"
        description="Generate controlled requests and watch real logs become security evidence."
      />
      <div className="safety-note">
        <FlaskConical size={18} />
        <span>
          Isolated local security lab · all traffic is restricted to controlled
          Docker services
        </span>
      </div>
      <Card
        title="Choose a test"
        subtitle="Start with normal traffic, then show TACG finding a distributed attack."
      >
        <div className="test-grid">
          {scenarios.map(([name, title, description]) => (
            <button
              className="test-button"
              key={name}
              disabled={!!busy}
              onClick={() => void run(name)}
            >
              <strong>{title}</strong>
              <span>{description}</span>
              <ArrowRight size={16} />
            </button>
          ))}
        </div>
        <div className="lab-controls">
          <button
            className={`button ${force ? "danger-button" : ""}`}
            disabled={!!busy}
            onClick={() => void toggle()}
          >
            <ShieldAlert size={16} />
            Force response failure: {force ? "On" : "Off"}
          </button>
          <button
            className="button"
            disabled={!!busy}
            onClick={() => void clear()}
          >
            Clear lab data
          </button>
          {busy && <span className="muted">Running {busy}…</span>}
        </div>
      </Card>
      <ErrorNotice message={error} />
      {result && <RequestResults requests={requests} raw={result} />}
      <div className="lab-lower">
        <Card
          title="Per-host threshold"
          subtitle="Failed logins from attacker-lab in the last five minutes; standalone threshold is five per host."
        >
          <div className="threshold-grid">
            {["app-a", "app-b", "app-c"].map((host) => {
              const count = store.events.filter(
                (event) =>
                  event.hostname === host &&
                  event.event_type === "failed_login" &&
                  event.source_ip === "attacker-lab" &&
                  Date.now() - new Date(event.timestamp).getTime() <= 300_000,
              ).length;
              return (
                <div key={host}>
                  <strong>{host}</strong>
                  <b>{count} / 5</b>
                  <Badge
                    value={count < 5 ? "Below threshold" : "Threshold met"}
                  />
                </div>
              );
            })}
          </div>
          <p className="helper-copy">
            TACG can still correlate the same source across all three hosts.
          </p>
        </Card>
        <Card
          title="Open the sample apps"
          subtitle="Send individual local requests through the Rust gateway."
        >
          <div className="app-links">
            {["app-a", "app-b", "app-c"].map((host) => (
              <a
                className="button"
                href={`/lab/${host}`}
                target="_blank"
                rel="noreferrer"
                key={host}
              >
                {host}
                <ExternalLink size={15} />
              </a>
            ))}
          </div>
          <p className="helper-copy">
            The apps write actual logs that the Rust sensor reads.
          </p>
        </Card>
      </div>
    </>
  );
}
export function SampleApp({ app }: { app: string }) {
  const [source, setSource] = useState("attacker-lab");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<ScenarioResult | null>(null);
  const [error, setError] = useState("");
  const send = async (operation: string) => {
    setBusy(true);
    setError("");
    try {
      setResult(
        await post<ScenarioResult>("/lab/attempt", {
          app,
          source,
          password,
          operation,
        }),
      );
    } catch (error) {
      setError(String(error));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="sample-shell">
      <div className="sample-header">
        <strong>LogShield / {app}</strong>
        <a className="button small" href="/">
          Open dashboard <ArrowRight size={15} />
        </a>
      </div>
      <div className="sample-content">
        <div className="safety-note">
          <FlaskConical size={18} />
          Fixed local Docker service · no external targets
        </div>
        <Card
          title={
            {
              "app-a": "Operations portal",
              "app-b": "Support console",
              "app-c": "Inventory admin",
            }[app] || app
          }
          subtitle="Each request passes through the Rust gateway. This application writes a real log."
        >
          <div className="sample-form">
            <label>
              Account
              <input value="demo" readOnly />
            </label>
            <label>
              Lab source
              <select
                value={source}
                onChange={(event) => setSource(event.target.value)}
              >
                <option value="attacker-lab">attacker-lab</option>
                <option value="normal-client">normal-client</option>
              </select>
            </label>
            <label>
              Dummy password
              <input
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                maxLength={128}
                placeholder="Test password"
              />
            </label>
            <button
              className="button primary"
              disabled={busy}
              onClick={() => void send("login")}
            >
              Send login request
            </button>
          </div>
          <div className="protected-actions">
            <button
              className="button"
              disabled={busy}
              onClick={() => void send("lab/admin-operation")}
            >
              Lab admin operation
            </button>
            <button
              className="button"
              disabled={busy}
              onClick={() => void send("lab/outbound")}
            >
              Local outbound request
            </button>
          </div>
          <ErrorNotice message={error} />
          {result && (
            <div className="sample-result">
              <strong>
                Actual gateway result · HTTP {result.attempt?.status || "—"}
              </strong>
              <pre>{safeJson(result)}</pre>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
