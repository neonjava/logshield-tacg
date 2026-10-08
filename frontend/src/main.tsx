import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity,
  Shield,
  ShieldAlert,
  Lock,
  Radio,
  Server,
  Upload,
  ArrowRight,
  X,
  Database,
  FlaskConical,
  Network,
} from "lucide-react";
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  Tooltip,
  CartesianGrid,
} from "recharts";
import "./style.css";
type Event = {
  id: string;
  timestamp: string;
  event_type: string;
  source_ip?: string;
  destination_ip?: string;
  hostname?: string;
  username?: string;
  result?: string;
  raw_message: string;
};
type Step = {
  timestamp: string;
  stage: string;
  detail: string;
  http_status?: number;
};
type Incident = {
  id: string;
  kind: string;
  source_ip?: string;
  target: string;
  risk: number;
  severity: string;
  status: string;
  confidence: number;
  score: Record<string, number>;
  reasons: string[];
  events: Event[];
  edges: { from: string; to: string; strength: number; reasons: string[] }[];
  response?: { result: string; proof: Step[] };
};
type Stats = {
  events_processed: number;
  active_incidents: number;
  critical_incidents: number;
  contained_incidents: number;
  response_failures: number;
  host_activity: Record<string, number>;
};
type Health = {
  gateway: boolean;
  force_response_failure: boolean;
  sensor: boolean;
  tacg: boolean;
  database: boolean;
  services_online: number;
  events_per_second: number;
  last_event?: string;
};
type Entity = {
  kind: string;
  value: string;
  event_count: number;
  first_seen: string;
  last_seen: string;
};
type Page =
  "overview" | "incidents" | "events" | "entities" | "responses" | "lab";
const empty: Stats = {
  events_processed: 0,
  active_incidents: 0,
  critical_incidents: 0,
  contained_incidents: 0,
  response_failures: 0,
  host_activity: {},
};
const api = async (path: string, init?: RequestInit) => {
  const r = await fetch("/api" + path, init);
  if (!r.ok) throw Error(await r.text());
  return r.json();
};
const fmt = (s?: string) => (s ? new Date(s).toLocaleTimeString() : "—");
const title = (s: string) =>
  s.replaceAll("_", " ").replace(/\b\w/g, (c) => c.toUpperCase());
const short = (s: string) => s.slice(0, 8).toUpperCase();
function App() {
  const [page, setPage] = useState<Page>("overview"),
    [events, setEvents] = useState<Event[]>([]),
    [incidents, setIncidents] = useState<Incident[]>([]),
    [stats, setStats] = useState<Stats>(empty),
    [health, setHealth] = useState<Health | null>(null),
    [entities, setEntities] = useState<Entity[]>([]),
    [selected, setSelected] = useState<string | null>(null),
    [event, setEvent] = useState<Event | null>(null),
    [graphNode, setGraphNode] = useState(""),
    [busy, setBusy] = useState(""),
    [error, setError] = useState(""),
    [live, setLive] = useState(false),
    [force, setForce] = useState(false),
    [runResult, setRunResult] = useState<any>(null);
  const refresh = async () => {
    try {
      const [e, i, s, h, n] = await Promise.all([
        api("/events"),
        api("/incidents"),
        api("/stats"),
        api("/status"),
        api("/entities"),
      ]);
      setEvents(e);
      setIncidents(i);
      setStats(s);
      setHealth(h);
      setForce(h.force_response_failure);
      setEntities(n);
    } catch (e) {
      setError(String(e));
    }
  };
  useEffect(() => {
    refresh();
    const timer = setInterval(refresh, 2500);
    const ws = new WebSocket(`ws://${location.host}/ws/events`);
    ws.onopen = () => setLive(true);
    ws.onclose = () => setLive(false);
    ws.onmessage = () => refresh();
    return () => {
      clearInterval(timer);
      ws.close();
    };
  }, []);
  const act = async (name: string, fn: () => Promise<any>) => {
    setBusy(name);
    setError("");
    try {
      setRunResult(await fn());
      await refresh();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy("");
    }
  };
  const run = (name: string) =>
    act(name, () => api("/lab/run/" + name, { method: "POST" }));
  const toggle = () =>
    act("toggle", async () => {
      const next = !force;
      const r = await api("/lab/force-failure", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled: next }),
      });
      setForce(next);
      return r;
    });
  const clear = () =>
    act("clear", async () => {
      const r = await api("/lab/clear", { method: "POST" });
      setSelected(null);
      setEvent(null);
      setForce(false);
      return r;
    });
  const upload = async (file?: File) => {
    if (!file) return;
    const form = new FormData();
    form.append("file", file);
    await act("upload", () =>
      api("/logs/upload", { method: "POST", body: form }),
    );
  };
  const chosen = incidents.find((i) => i.id === selected);
  const membership = new Map(
    incidents.flatMap((i) => i.events.map((e) => [e.id, i.id] as const)),
  );
  const chart = [...events]
    .reverse()
    .reduce<{ time: string; events: number }[]>((a, e) => {
      const t = fmt(e.timestamp),
        found = a.find((x) => x.time === t);
      if (found) found.events++;
      else a.push({ time: t, events: 1 });
      return a;
    }, [])
    .slice(-20);
  const navigate = (p: Page) => {
    setPage(p);
    setSelected(null);
    setEvent(null);
  };
  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <div className="brandicon">
            <Shield size={23} />
          </div>
          <div>
            <strong>LOGSHIELD</strong>
            <small>TACG / SECURITY ENGINE</small>
          </div>
        </div>
        {(
          [
            ["overview", <Activity />],
            ["incidents", <ShieldAlert />],
            ["events", <Radio />],
            ["entities", <Network />],
            ["responses", <Lock />],
            ["lab", <FlaskConical />],
          ] as [Page, React.ReactNode][]
        ).map(([p, icon]) => (
          <button
            className={"nav nav-button " + (page === p ? "active" : "")}
            key={p}
            onClick={() => navigate(p)}
          >
            {icon}
            {p.toUpperCase()}
            {p === "incidents" && <span>{incidents.length}</span>}
          </button>
        ))}
        <div className="sidebar-bottom">
          <div className="engine">
            <span className="green-dot" /> RUST SENSOR{" "}
            {health?.sensor ? "ONLINE" : "OFFLINE"}
          </div>
          <small>
            ISOLATED LOCAL LAB
            <br />
            AI26CY03 · TACG
          </small>
        </div>
      </aside>
      <main>
        <header>
          <div>
            <div className="eyebrow">
              SECURITY OPERATIONS / {page.toUpperCase()}
            </div>
            <h1>
              {chosen
                ? "Incident " + short(chosen.id)
                : page === "overview"
                  ? "Command Center"
                  : title(page)}
            </h1>
            <p>
              {chosen
                ? chosen.kind
                : "Live evidence from the Rust sensor and gateway."}
            </p>
          </div>
          <span className={"live " + (live ? "" : "offline")}>
            <span className="green-dot" />
            {live ? "LIVE STREAM" : "CONNECTING"}
          </span>
        </header>
        {error && (
          <div className="error" onClick={() => setError("")}>
            {error} ×
          </div>
        )}
        {page === "overview" && (
          <>
            <div className="section-title">
              <div>
                <span className="eyebrow">OPERATIONAL STATUS</span>
                <h2>Pipeline health</h2>
              </div>
              <span className="panel-meta">
                LAST EVENT {fmt(health?.last_event)}
              </span>
            </div>
            <div className="health-grid">
              {[
                ["GATEWAY", !!health?.gateway, ""],
                ["LOG SENSOR", !!health?.sensor, ""],
                ["TACG ENGINE", !!health?.tacg, ""],
                ["DATABASE", !!health?.database, ""],
                [
                  "LAB SERVICES",
                  health?.services_online === 3,
                  `${health?.services_online || 0}/3`,
                ],
              ].map(([label, ok, value]) => (
                <div className="health-item" key={String(label)}>
                  <i className={ok ? "ok" : ""} />
                  <small>{label}</small>
                  <strong>
                    {value || ((ok as boolean) ? "ONLINE" : "OFFLINE")}
                  </strong>
                </div>
              ))}
            </div>
            <div className="metrics">
              <Metric
                icon={<Activity />}
                label="EVENTS INGESTED"
                value={stats.events_processed}
                sub="Persisted log records"
              />
              <Metric
                icon={<Radio />}
                label="EVENTS / SEC"
                value={(health?.events_per_second || 0).toFixed(2)}
                sub="Last 60 seconds"
              />
              <Metric
                icon={<ShieldAlert />}
                label="OPEN INCIDENTS"
                value={stats.active_incidents}
                sub="Requires attention"
                tone="red"
              />
              <Metric
                icon={<Lock />}
                label="VERIFIED CONTAINED"
                value={stats.contained_incidents}
                sub="HTTP 403 proven"
                tone="green"
              />
              <Metric
                icon={<Shield />}
                label="RESPONSE FAILURES"
                value={stats.response_failures}
                sub="Human review required"
              />
            </div>
            <div className="grid-two">
              <section className="panel">
                <div className="panel-head">
                  <div>
                    <span className="eyebrow">DETECTIONS</span>
                    <h2>Latest incidents</h2>
                  </div>
                  <button
                    className="textbtn"
                    onClick={() => navigate("incidents")}
                  >
                    VIEW ALL →
                  </button>
                </div>
                {incidents.length ? (
                  incidents.slice(0, 5).map((i) => (
                    <IncidentRow
                      key={i.id}
                      i={i}
                      onClick={() => {
                        setPage("incidents");
                        setSelected(i.id);
                      }}
                    />
                  ))
                ) : (
                  <Empty text="No incident. Start normal activity in Lab." />
                )}
              </section>
              <section className="panel">
                <div className="panel-head">
                  <div>
                    <span className="eyebrow">TELEMETRY</span>
                    <h2>Event timeline</h2>
                  </div>
                  <span className="panel-meta">REAL LOG INGESTION</span>
                </div>
                <div className="chartbox">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={chart}>
                      <CartesianGrid stroke="#263345" vertical={false} />
                      <XAxis
                        dataKey="time"
                        tick={{ fill: "#7f91a8", fontSize: 10 }}
                        axisLine={false}
                        tickLine={false}
                      />
                      <Tooltip
                        contentStyle={{
                          background: "#152334",
                          border: "1px solid #35475a",
                          color: "#fff",
                        }}
                      />
                      <Area
                        type="monotone"
                        dataKey="events"
                        stroke="#49d5b5"
                        strokeWidth={2}
                        fill="#49d5b5"
                        fillOpacity={0.14}
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </section>
            </div>
            <div className="grid-two lower">
              <section className="panel">
                <div className="panel-head">
                  <div>
                    <span className="eyebrow">LIVE FEED</span>
                    <h2>Recent events</h2>
                  </div>
                  <button
                    className="textbtn"
                    onClick={() => navigate("events")}
                  >
                    EVENT TABLE →
                  </button>
                </div>
                {events.slice(0, 7).map((e) => (
                  <button
                    className="feed-row feed-button"
                    key={e.id}
                    onClick={() => {
                      setPage("events");
                      setEvent(e);
                    }}
                  >
                    <span
                      className={
                        "event-dot " +
                        (e.event_type === "failed_login" ? "warn" : "")
                      }
                    />
                    <span>
                      <strong>{title(e.event_type)}</strong>
                      <small>
                        {e.source_ip} → {e.hostname}
                      </small>
                    </span>
                    <time>{fmt(e.timestamp)}</time>
                  </button>
                ))}
                {!events.length && <Empty text="Waiting for app logs..." />}
              </section>
              <section className="panel">
                <div className="panel-head">
                  <div>
                    <span className="eyebrow">ENTITY VIEW</span>
                    <h2>Host activity</h2>
                  </div>
                </div>
                <div className="hosts">
                  {Object.entries(stats.host_activity).map(([host, count]) => (
                    <div className="host" key={host}>
                      <Server size={16} />
                      <span>{host}</span>
                      <strong>{count} events</strong>
                    </div>
                  ))}
                </div>
              </section>
            </div>
          </>
        )}
        {page === "incidents" &&
          (chosen ? (
            <>
              <button className="back" onClick={() => setSelected(null)}>
                ← INCIDENT QUEUE
              </button>
              <div className="detail-summary">
                <div>
                  <span className="eyebrow">
                    {short(chosen.id)} · {chosen.kind}
                  </span>
                  <h2>
                    {chosen.risk}
                    <small> / 100 RISK</small>
                  </h2>
                </div>
                <div>
                  <span className={"status " + chosen.status.toLowerCase()}>
                    {chosen.status}
                  </span>
                  <p>Confidence {chosen.confidence}%</p>
                </div>
                <div>
                  <small>SOURCE</small>
                  <strong>{chosen.source_ip}</strong>
                </div>
                <div>
                  <small>TARGETS</small>
                  <strong>
                    {[
                      ...new Set(
                        chosen.events.map((e) => e.hostname).filter(Boolean),
                      ),
                    ].join(", ")}
                  </strong>
                </div>
              </div>
              <div className="detail-grid">
                <section className="panel">
                  <div className="panel-head">
                    <div>
                      <span className="eyebrow">01 / EVIDENCE</span>
                      <h2>Attack timeline</h2>
                    </div>
                    <span className="panel-meta">
                      {chosen.events.length} LOGGED EVENTS
                    </span>
                  </div>
                  <div className="chain">
                    {chosen.events.map((e, j) => (
                      <button
                        className="chain-event chain-button"
                        key={e.id}
                        onClick={() => setEvent(e)}
                      >
                        <span className="chain-index">
                          {String(j + 1).padStart(2, "0")}
                        </span>
                        <div>
                          <strong>{e.event_type.toUpperCase()}</strong>
                          <small>
                            {fmt(e.timestamp)} · {e.source_ip} → {e.hostname} ·{" "}
                            {e.username}
                          </small>
                          {j > 0 && (
                            <em>
                              {chosen.edges
                                .find((x) => x.to === e.id)
                                ?.reasons.join(" · ") ||
                                "Temporal relationship"}
                            </em>
                          )}
                        </div>
                      </button>
                    ))}
                  </div>
                </section>
                <section className="panel">
                  <div className="panel-head">
                    <div>
                      <span className="eyebrow">02 / TACG</span>
                      <h2>Evidence-backed graph</h2>
                    </div>
                  </div>
                  <div className="graph">
                    <button
                      className="graph-node"
                      onClick={() => setGraphNode(chosen.source_ip || "")}
                    >
                      {chosen.source_ip}
                      <small>SOURCE</small>
                    </button>
                    <div className="graph-arrow">↘　↓　↙</div>
                    <div className="graph-hosts">
                      {[
                        ...new Set(
                          chosen.events.map((e) => e.hostname).filter(Boolean),
                        ),
                      ].map((h) => (
                        <button
                          className="graph-node"
                          key={h}
                          onClick={() => setGraphNode(h!)}
                        >
                          {h}
                          <small>
                            {
                              chosen.events.filter((e) => e.hostname === h)
                                .length
                            }{" "}
                            EVENTS
                          </small>
                        </button>
                      ))}
                    </div>
                    <div className="graph-arrow">↘　↓　↙</div>
                    <button
                      className="graph-node"
                      onClick={() =>
                        setGraphNode(chosen.events[0]?.username || "")
                      }
                    >
                      {chosen.events[0]?.username || "—"}
                      <small>ACCOUNT</small>
                    </button>
                  </div>
                  <div className="graph-evidence">
                    {graphNode ? (
                      <>
                        <strong>
                          {graphNode}:{" "}
                          {
                            chosen.events.filter(
                              (e) =>
                                e.source_ip === graphNode ||
                                e.hostname === graphNode ||
                                e.username === graphNode,
                            ).length
                          }{" "}
                          linked event(s)
                        </strong>
                        {chosen.events
                          .filter(
                            (e) =>
                              e.source_ip === graphNode ||
                              e.hostname === graphNode ||
                              e.username === graphNode,
                          )
                          .map((e) => (
                            <button key={e.id} onClick={() => setEvent(e)}>
                              {fmt(e.timestamp)} · {e.event_type.toUpperCase()}{" "}
                              · {e.hostname}
                            </button>
                          ))}
                      </>
                    ) : (
                      <span>Click a node to inspect its logged events.</span>
                    )}
                  </div>
                </section>
              </div>
              <div className="detail-grid">
                <section className="panel">
                  <div className="panel-head">
                    <div>
                      <span className="eyebrow">03 / CROSS-HOST PROOF</span>
                      <h2>Per-host threshold vs TACG</h2>
                    </div>
                  </div>
                  <div className="host-proof">
                    {[
                      ...new Set(
                        chosen.events.map((e) => e.hostname).filter(Boolean),
                      ),
                    ].map((h) => {
                      const n = chosen.events.filter(
                        (e) =>
                          e.hostname === h && e.event_type === "failed_login",
                      ).length;
                      return (
                        <div key={h}>
                          <strong>{h}</strong>
                          <span>{n} / 5</span>
                          <small>
                            {n < 5 ? "NO HOST ALERT" : "HOST THRESHOLD MET"}
                          </small>
                        </div>
                      );
                    })}
                  </div>
                  <div className="correlation-summary">
                    <strong>TACG CORRELATION</strong>
                    <span>Same source: YES</span>
                    <span>
                      Hosts:{" "}
                      {
                        [...new Set(chosen.events.map((e) => e.hostname))]
                          .length
                      }
                    </span>
                    <span>
                      Failed logins:{" "}
                      {
                        chosen.events.filter(
                          (e) => e.event_type === "failed_login",
                        ).length
                      }
                    </span>
                    <span>
                      Time window:{" "}
                      {Math.round(
                        (new Date(chosen.events.at(-1)!.timestamp).getTime() -
                          new Date(chosen.events[0].timestamp).getTime()) /
                          1000,
                      )}{" "}
                      sec
                    </span>
                  </div>
                </section>
                <section className="panel">
                  <div className="panel-head">
                    <div>
                      <span className="eyebrow">04 / EXPLAINABILITY</span>
                      <h2>Risk calculation</h2>
                    </div>
                  </div>
                  <div className="scores">
                    {[
                      ["Event rarity", "event_rarity", 20],
                      ["Temporal correlation", "temporal_strength", 20],
                      ["Entity relationship", "entity_relationship", 15],
                      ["Transition risk", "transition_risk", 20],
                      ["Cross-host activity", "cross_host_score", 10],
                      ["Behavior deviation", "behaviour_deviation", 15],
                      ["Attack-chain bonus", "attack_chain_bonus", 25],
                    ].map(([label, key, max]) => (
                      <div className="score" key={key}>
                        <span>{label}</span>
                        <div>
                          <i
                            style={{
                              width: `${Math.min(100, (chosen.score[String(key)] / Number(max)) * 100)}%`,
                            }}
                          />
                        </div>
                        <b>
                          {chosen.score[String(key)].toFixed(1)} / {max}
                        </b>
                      </div>
                    ))}
                  </div>
                  <p className="formula">
                    Weighted evidence + chain bonus = <b>{chosen.risk} / 100</b>
                  </p>
                  <ul className="reasons">
                    {chosen.reasons.map((r, j) => (
                      <li key={j}>{r}</li>
                    ))}
                  </ul>
                </section>
              </div>
              <section className="panel proof-panel">
                <div className="panel-head">
                  <div>
                    <span className="eyebrow">05 / DEFENSIVE ACTION</span>
                    <h2>Response and actual verification</h2>
                  </div>
                  <span className={"status " + chosen.status.toLowerCase()}>
                    {chosen.status}
                  </span>
                </div>
                {chosen.response ? (
                  <>
                    <div className="proof-steps">
                      {chosen.response.proof.map((step, j) => (
                        <div className="proof-step" key={j}>
                          <time>{fmt(step.timestamp)}</time>
                          <span className="proof-dot" />
                          <div>
                            <strong>{step.stage.replaceAll("_", " ")}</strong>
                            <p>{step.detail}</p>
                          </div>
                          <b>
                            {step.http_status ? `HTTP ${step.http_status}` : ""}
                          </b>
                        </div>
                      ))}
                    </div>
                    <div
                      className={
                        "proof-result " +
                        (chosen.status === "RESPONSE_FAILED" ? "fail" : "")
                      }
                    >
                      {chosen.response.result}
                    </div>
                  </>
                ) : (
                  <Empty text="No automatic response: risk or confidence did not reach the response gate." />
                )}
              </section>
            </>
          ) : (
            <section className="panel">
              <div className="panel-head">
                <div>
                  <span className="eyebrow">CORRELATED DETECTIONS</span>
                  <h2>Incident queue</h2>
                </div>
                <span className="panel-meta">{incidents.length} RECORDS</span>
              </div>
              {incidents.map((i) => (
                <IncidentRow
                  key={i.id}
                  i={i}
                  onClick={() => setSelected(i.id)}
                />
              ))}
              {!incidents.length && (
                <Empty text="No incidents detected from ingested logs." />
              )}
            </section>
          ))}
        {page === "events" && (
          <section className="panel">
            <div className="panel-head">
              <div>
                <span className="eyebrow">SENSOR OUTPUT</span>
                <h2>Normalized events</h2>
              </div>
              <label className="upload">
                <Upload size={14} /> IMPORT LOGS
                <input
                  type="file"
                  accept=".log,.txt,.jsonl"
                  hidden
                  onChange={(e) => upload(e.target.files?.[0])}
                />
              </label>
            </div>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    {[
                      "TIME",
                      "SOURCE",
                      "DESTINATION",
                      "USER",
                      "HOST",
                      "EVENT",
                      "RESULT",
                      "CORRELATED",
                      "INCIDENT",
                    ].map((x) => (
                      <th key={x}>{x}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {events.map((e) => (
                    <tr key={e.id} onClick={() => setEvent(e)}>
                      <td>{fmt(e.timestamp)}</td>
                      <td>{e.source_ip || "—"}</td>
                      <td>{e.destination_ip || "—"}</td>
                      <td>{e.username || "—"}</td>
                      <td>{e.hostname || "—"}</td>
                      <td>
                        <span className="event-tag">
                          {e.event_type.toUpperCase()}
                        </span>
                      </td>
                      <td>{e.result || "—"}</td>
                      <td>{membership.has(e.id) ? "YES" : "NO"}</td>
                      <td>
                        {membership.has(e.id)
                          ? short(membership.get(e.id)!)
                          : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {!events.length && <Empty text="No app logs ingested yet." />}
            </div>
          </section>
        )}
        {page === "entities" && (
          <section className="panel">
            <div className="panel-head">
              <div>
                <span className="eyebrow">OBSERVED IDENTITIES</span>
                <h2>Entity inventory</h2>
              </div>
            </div>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>TYPE</th>
                    <th>VALUE</th>
                    <th>EVENTS</th>
                    <th>FIRST SEEN</th>
                    <th>LAST SEEN</th>
                  </tr>
                </thead>
                <tbody>
                  {entities.map((e) => (
                    <tr key={e.kind + e.value}>
                      <td>{e.kind.toUpperCase()}</td>
                      <td>{e.value}</td>
                      <td>{e.event_count}</td>
                      <td>{fmt(e.first_seen)}</td>
                      <td>{fmt(e.last_seen)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {!entities.length && <Empty text="No entities yet." />}
            </div>
          </section>
        )}
        {page === "responses" && (
          <section className="panel">
            <div className="panel-head">
              <div>
                <span className="eyebrow">AUTOMATED DEFENSE</span>
                <h2>Response ledger</h2>
              </div>
              <span className="panel-meta">ACTUAL GATEWAY VERIFICATION</span>
            </div>
            {incidents
              .filter((i) => i.response)
              .map((i) => (
                <button
                  className="response-row"
                  key={i.id}
                  onClick={() => {
                    setPage("incidents");
                    setSelected(i.id);
                  }}
                >
                  <span className={"status " + i.status.toLowerCase()}>
                    {i.status}
                  </span>
                  <span>{short(i.id)}</span>
                  <strong>{i.source_ip}</strong>
                  <span>
                    {i.response?.proof.find(
                      (p) => p.stage === "HTTP_403_RECEIVED",
                    )
                      ? "HTTP 403"
                      : "VIEW RESULT"}
                  </span>
                  <ArrowRight size={15} />
                </button>
              ))}
            {!incidents.some((i) => i.response) && (
              <Empty text="No gateway response recorded." />
            )}
          </section>
        )}
        {page === "lab" && (
          <>
            <div className="lab-banner">
              <FlaskConical size={22} />
              <div>
                <strong>ISOLATED LOCAL TEST ENVIRONMENT</strong>
                <p>
                  Fixed requests stay inside the Docker lab. No arbitrary
                  targets or external systems.
                </p>
              </div>
            </div>
            <section className="panel lab-panel">
              <div className="panel-head">
                <div>
                  <span className="eyebrow">CONTROLLED TRAFFIC</span>
                  <h2>Lab operations</h2>
                </div>
                <span className="panel-meta">
                  CLIENT → GATEWAY → APP LOG → SENSOR
                </span>
              </div>
              <div className="lab-actions">
                {[
                  [
                    "normal",
                    "START NORMAL TRAFFIC",
                    "Valid logins on all three apps.",
                  ],
                  [
                    "distributed",
                    "START DISTRIBUTED AUTH TEST",
                    "2 failures on A, 2 on B, 1 on C.",
                  ],
                  [
                    "multistage",
                    "START MULTI-STAGE TEST",
                    "Failures, success, lab admin action, local outbound.",
                  ],
                ].map(([key, label, desc]) => (
                  <button
                    className="lab-button"
                    key={key}
                    onClick={() => run(key)}
                    disabled={!!busy}
                  >
                    <strong>{label}</strong>
                    <small>{desc}</small>
                    <ArrowRight size={16} />
                  </button>
                ))}
              </div>
              <div className="lab-options">
                <button
                  className={"lab-toggle " + (force ? "on" : "")}
                  onClick={toggle}
                  disabled={!!busy}
                >
                  FORCE RESPONSE FAILURE: {force ? "ON" : "OFF"}
                </button>
                <button className="lab-clear" onClick={clear} disabled={!!busy}>
                  CLEAR LAB DATA
                </button>
              </div>
              {busy && (
                <p className="lab-note">
                  Running {busy} through the lab client…
                </p>
              )}
              {runResult && (
                <pre className="lab-output">
                  {JSON.stringify(runResult, null, 2)}
                </pre>
              )}
            </section>
            <section className="panel">
              <div className="panel-head">
                <div>
                  <span className="eyebrow">DETECTION PROOF</span>
                  <h2>Traditional per-host threshold: 5 failures</h2>
                </div>
              </div>
              <div className="host-proof">
                {["app-a", "app-b", "app-c"].map((h) => {
                  const n = events.filter(
                    (e) =>
                      e.hostname === h &&
                      e.event_type === "failed_login" &&
                      e.source_ip === "attacker-lab",
                  ).length;
                  return (
                    <div key={h}>
                      <strong>{h}</strong>
                      <span>{n} / 5</span>
                      <small>
                        {n < 5 ? "NO HOST ALERT" : "HOST THRESHOLD MET"}
                      </small>
                    </div>
                  );
                })}
              </div>
            </section>
          </>
        )}
        <footer>
          LOGSHIELD TACG{" "}
          <span>RUST SENSOR · ACTUAL LAB LOGS · GATEWAY VERIFICATION</span>
        </footer>
      </main>
      {event && (
        <div className="event-overlay" onClick={() => setEvent(null)}>
          <div className="event-detail" onClick={(e) => e.stopPropagation()}>
            <button className="close" onClick={() => setEvent(null)}>
              <X size={18} />
            </button>
            <span className="eyebrow">EVENT EVIDENCE / {event.id}</span>
            <h2>{event.event_type.toUpperCase()}</h2>
            <h3>Raw log</h3>
            <pre>{event.raw_message}</pre>
            <h3>Normalized event</h3>
            <pre>{JSON.stringify(event, null, 2)}</pre>
            <h3>Relationships</h3>
            <p>
              {incidents
                .flatMap((i) => i.edges)
                .filter((x) => x.from === event.id || x.to === event.id)
                .flatMap((x) => x.reasons)
                .join(" · ") || "No graph edge"}
            </p>
            <p>
              Incident:{" "}
              {membership.has(event.id)
                ? short(membership.get(event.id)!)
                : "NONE"}
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
function Metric({
  icon,
  label,
  value,
  sub,
  tone = "",
}: {
  icon: React.ReactNode;
  label: string;
  value: string | number;
  sub: string;
  tone?: string;
}) {
  return (
    <div className={"metric " + tone}>
      <div className="metric-icon">{icon}</div>
      <small>{label}</small>
      <strong>{value}</strong>
      <span>{sub}</span>
    </div>
  );
}
function Empty({ text }: { text: string }) {
  return <div className="empty">{text}</div>;
}
function IncidentRow({ i, onClick }: { i: Incident; onClick: () => void }) {
  return (
    <button className="incident-row" onClick={onClick}>
      <span className={"risk-badge " + i.severity.toLowerCase()}>{i.risk}</span>
      <span className="incident-main">
        <strong>
          {i.kind || i.severity} · {i.source_ip}
        </strong>
        <small>
          {short(i.id)} · {i.events.length} real events · {i.edges.length} graph
          edges
        </small>
      </span>
      <span className={"status " + i.status.toLowerCase()}>{i.status}</span>
      <ArrowRight size={15} />
    </button>
  );
}
createRoot(document.getElementById("root")!).render(<App />);
