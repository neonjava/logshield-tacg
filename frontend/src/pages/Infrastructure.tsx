import { useEffect, useState } from "react";
import {
  ArrowRight,
  Database,
  LockKeyhole,
  Server,
  ShieldCheck,
} from "lucide-react";
import { api, post, time } from "../api";
import {
  Badge,
  Card,
  Empty,
  ErrorNotice,
  Heading,
  LoginSuccess,
  RequestResults,
} from "../components/ui";
import type { SecurityStore } from "../hooks/useSecurity";
import type {
  AppActivity,
  HttpResult,
  InfraHealth,
  ScenarioResult,
} from "../types";
const tests = [
  ["normal", "Normal login", "Complete login and use all three servers."],
  [
    "bruteforce",
    "Brute force",
    "Repeated incorrect passwords on the local portal.",
  ],
  [
    "distributed",
    "Distributed 2 / 2 / 1",
    "Five weak failures spread across three hosts.",
  ],
  ["suspicious", "Suspicious login", "Completed login after failed attempts."],
  ["mfa", "MFA failures", "Repeated incorrect verification codes."],
] as const;
export function Infrastructure({ store }: { store: SecurityStore }) {
  const [status, setStatus] = useState<InfraHealth | null>(null);
  const [activities, setActivities] = useState<AppActivity[]>([]);
  const [source, setSource] = useState("normal-client");
  const [password, setPassword] = useState("");
  const [challenge, setChallenge] = useState("");
  const [code, setCode] = useState("");
  const [token, setToken] = useState("");
  const [result, setResult] = useState<unknown>(null);
  const [requests, setRequests] = useState<HttpResult[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [loginSuccess, setLoginSuccess] = useState(false);
  useEffect(() => {
    let active = true;
    const refresh = async () => {
      try {
        const [nextStatus, nextActivities] = await Promise.all([
          api<InfraHealth>("/infra/status"),
          api<{ activities: AppActivity[] }>("/infra/activities"),
        ]);
        if (active) {
          setStatus(nextStatus);
          setActivities(nextActivities.activities || []);
        }
      } catch {
        if (active) setStatus(null);
      }
    };
    void refresh();
    const interval = setInterval(() => void refresh(), 4000);
    return () => {
      active = false;
      clearInterval(interval);
    };
  }, []);
  const action = async (operation: string) => {
    setBusy(true);
    setError("");
    if (operation === "password") {
      setChallenge("");
      setCode("");
      setToken("");
    }
    try {
      const response = await post<HttpResult>("/infra/request", {
        action: operation,
        source,
        password,
        challenge_id: challenge,
        code,
        token,
      });
      setResult(response);
      setRequests([response]);
      if (response.body?.challenge_id) setChallenge(response.body.challenge_id);
      if (response.body?.demo_code) setCode(response.body.demo_code);
      if (
        operation === "mfa" &&
        response.status === 200 &&
        response.body?.token &&
        response.body.authenticated
      ) {
        setToken(response.body.token);
        setLoginSuccess(true);
        store.notify(
          "Login successful",
          "MFA verified and a shared session was issued.",
          "success",
        );
      }
      if (response.status >= 400)
        setError(
          response.body?.error ||
            `HTTP ${response.status} from the application`,
        );
      const activityResult = await api<{ activities: AppActivity[] }>(
        "/infra/activities",
      );
      setActivities(activityResult.activities || []);
      await store.refresh();
    } catch (error) {
      setError(String(error));
    } finally {
      setBusy(false);
    }
  };
  const run = async (name: string) => {
    setBusy(true);
    setError("");
    try {
      const response = await post<ScenarioResult>(`/infra/run/${name}`);
      setResult(response);
      setRequests(response.requests || []);
      await store.refresh();
      const activityResult = await api<{ activities: AppActivity[] }>(
        "/infra/activities",
      );
      setActivities(activityResult.activities || []);
    } catch (error) {
      setError(String(error));
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <Heading
        title="Infrastructure"
        description="One application behind three Rust servers, with shared sessions and real log agents."
      />
      <div className="safety-note">
        <ShieldCheck size={18} />
        <span>Isolated local infrastructure · fixed Docker targets only</span>
      </div>
      <div className="infra-grid">
        <Card
          title="Application servers"
          subtitle="Three replicas of one portal."
        >
          <div className="service-list">
            {["infra-a", "infra-b", "infra-c"].map((name) => {
              const replica = status?.replicas.find(
                (item) => item.name === name,
              );
              return (
                <div key={name}>
                  <Server size={18} />
                  <strong>{name}</strong>
                  <Badge value={replica?.online ? "Online" : "Offline"} />
                </div>
              );
            })}
          </div>
        </Card>
        <Card
          title="Log collection"
          subtitle="Read-only agents submit each server's log."
        >
          <div className="service-list">
            {["infra-a", "infra-b", "infra-c"].map((name) => {
              const agent = status?.agents.find((item) => item.name === name);
              return (
                <div key={name}>
                  <Database size={18} />
                  <strong>{name} agent</strong>
                  <Badge value={agent?.online ? "Online" : "Offline"} />
                </div>
              );
            })}
          </div>
        </Card>
      </div>
      <Card
        title="Try one shared login"
        subtitle="The password creates a challenge. MFA completes the login and issues the shared session."
      >
        <div className="auth-form">
          <label>
            Lab source
            <select
              value={source}
              onChange={(event) => setSource(event.target.value)}
            >
              <option value="normal-client">normal-client</option>
              <option value="attacker-lab">attacker-lab</option>
            </select>
          </label>
          <label>
            Dummy password
            <input
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              placeholder="Enter local test password"
              maxLength={128}
            />
          </label>
          <button
            className="button primary"
            disabled={busy || !password}
            onClick={() => void action("password")}
          >
            1 · Submit password
          </button>
          <ArrowRight className="step-arrow" size={18} />
          <button
            className="button"
            disabled={busy || !challenge}
            onClick={() => void action("demo-code")}
          >
            Reveal lab MFA code
          </button>
          <label>
            MFA code
            <input
              inputMode="numeric"
              value={code}
              onChange={(event) => setCode(event.target.value)}
              placeholder="6 digits"
              maxLength={6}
            />
          </label>
          <button
            className="button primary"
            disabled={busy || !challenge || !code}
            onClick={() => void action("mfa")}
          >
            2 · Complete login
          </button>
        </div>
        <div className="protected-actions">
          <span>
            <LockKeyhole size={17} />
            Shared session
          </span>
          <button
            className="button small"
            disabled={busy || !token}
            onClick={() => void action("session")}
          >
            Check session
          </button>
          {["operations", "reports", "inventory"].map((operation) => (
            <button
              className="button small"
              key={operation}
              disabled={busy || !token}
              onClick={() => void action(operation)}
            >
              {operation}
            </button>
          ))}
        </div>
      </Card>
      <Card
        title="Controlled security tests"
        subtitle="Every test sends requests through the gateway, application, log agent, and TACG engine."
      >
        <div className="test-grid">
          {tests.map(([name, title, description]) => (
            <button
              className="test-button"
              key={name}
              disabled={busy}
              onClick={() => void run(name)}
            >
              <strong>{title}</strong>
              <span>{description}</span>
              <ArrowRight size={16} />
            </button>
          ))}
        </div>
      </Card>
      <ErrorNotice message={error} />
      {result && <RequestResults requests={requests} raw={result} />}
      <Card
        title="Completed activities"
        subtitle="Protected actions stored in PostgreSQL across the application servers."
      >
        {activities.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Account</th>
                  <th>Action</th>
                  <th>Server</th>
                </tr>
              </thead>
              <tbody>
                {activities.map((activity) => (
                  <tr key={activity.id}>
                    <td className="mono">{time(activity.created_at)}</td>
                    <td>{activity.username}</td>
                    <td>{activity.service}</td>
                    <td className="mono">{activity.replica}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty
            title="No activity yet"
            text="Complete a login and run an operation, report, or inventory action."
          />
        )}
      </Card>
      {loginSuccess && <LoginSuccess onClose={() => setLoginSuccess(false)} />}
    </>
  );
}
