import { useEffect, useMemo, useState } from "react";
import { Radio, RefreshCw, Search } from "lucide-react";
import { api, isFailure, time } from "../api";
import { Badge, Card, Empty, EventName, Heading } from "../components/ui";
import type { SecurityStore } from "../hooks/useSecurity";
import type { InfraHealth, SecurityEvent } from "../types";

const SERVERS = ["infra-a", "infra-b", "infra-c"] as const;

export function SdkLogs({
  store,
  onEvent,
}: {
  store: SecurityStore;
  onEvent: (event: SecurityEvent) => void;
}) {
  const [server, setServer] = useState("all");
  const [query, setQuery] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);
  const [status, setStatus] = useState<InfraHealth | null>(null);
  useEffect(() => {
    let active = true;
    const load = async () => {
      try {
        const next = await api<InfraHealth>("/infra/status");
        if (active) setStatus(next);
      } catch {
        if (active) setStatus(null);
      }
    };
    void load();
    const timer = setInterval(() => void load(), 5000);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, []);

  const liveEvents = useMemo(
    () =>
      store.events
        .filter((event) => event.origin === "lab_sensor" || event.origin?.startsWith("agent:infra-"))
        .sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp)),
    [store.events],
  );
  const visible = liveEvents
    .filter((event) => server === "all" || event.hostname === server)
    .filter((event) =>
      [
        event.source_ip,
        event.hostname,
        event.username,
        event.event_type,
        event.raw_message,
      ]
        .join(" ")
        .toLowerCase()
        .includes(query.toLowerCase()),
    )
    .slice(0, 100);

  return (
    <>
      <Heading
        title="SDK Live Logs"
        description="Actual application log lines read by the Rust file sensor or three Rust agents. Manual uploads are excluded."
        action={
          <span className={`connection ${store.live ? "online" : ""}`}>
            <i />
            {store.live ? "Live connection" : "Reconnecting"}
          </span>
        }
      />
      <div className="sdk-agent-grid" aria-label="Rust agent status">
        {SERVERS.map((name) => {
          const online = status?.agents.find(
            (item) => item.name === name,
          )?.online;
          const count = liveEvents.filter(
            (event) => event.hostname === name,
          ).length;
          return (
            <div className="sdk-agent" key={name}>
              <span className="sdk-agent-name">
                <Radio size={15} />
                {name}
              </span>
              <strong>{count} logs</strong>
              <Badge
                value={status ? (online ? "Online" : "Offline") : "Checking"}
              />
            </div>
          );
        })}
      </div>
      <p className="sdk-source-note">Sample app-a/b/c requests appear as <strong>lab_sensor</strong>. Shared portal infra-a/b/c requests appear as <strong>agent:infra-*</strong>. Open the app and this dashboard on the same port so they use the same backend.</p>
      <Card
        title="Live application log files"
        subtitle="Application writes JSON to its log file → Rust sensor or agent reads the new line → LogShield stores it. The original written line is shown below."
        action={
          <button className="button small" onClick={() => void store.refresh()}>
            <RefreshCw size={14} /> Refresh
          </button>
        }
      >
        <div className="sdk-stream-meta">
          <span>{liveEvents.length} live logs stored</span>
          <span>Latest: {time(liveEvents[0]?.timestamp)}</span>
          <span>
            {store.live ? "WebSocket connected" : "Polling while reconnecting"}
          </span>
        </div>
        <div className="toolbar">
          <label className="search-field">
            <Search size={17} />
            <input
              aria-label="Search SDK logs"
              placeholder="Search source, account, event, or raw log…"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
            />
          </label>
          <select
            aria-label="Filter agent server"
            value={server}
            onChange={(event) => setServer(event.target.value)}
          >
            <option value="all">All live sources</option>
            {SERVERS.map((name) => (
              <option value={name} key={name}>
                {name}
              </option>
            ))}
            <option value="app-a">Sample app-a</option>
            <option value="app-b">Sample app-b</option>
            <option value="app-c">Sample app-c</option>
          </select>
        </div>
        {visible.length ? (
          <div className="table-scroll">
            <table className="sdk-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Agent / server</th>
                  <th>Source</th>
                  <th>Account</th>
                  <th>Event</th>
                  <th>Result</th>
                  <th>Raw application log</th>
                </tr>
              </thead>
              <tbody>
                {visible.map((event) => (
                  <tr key={event.id} className={isFailure(event) ? "failed-row" : ""}>
                    <td className="mono">{time(event.timestamp)}</td>
                    <td>
                      <strong>
                        {event.hostname || event.origin?.slice(6)}
                      </strong>
                      <small className="cell-subtitle mono">
                        {event.origin}
                      </small>
                    </td>
                    <td className="mono">{event.source_ip || "—"}</td>
                    <td>{event.username || "—"}</td>
                    <td>
                      <button
                        className="table-link"
                        onClick={() => onEvent(event)}
                      >
                        <EventName event={event} />
                      </button>
                    </td>
                    <td className={isFailure(event) ? "text-danger bold" : ""}>
                      {event.result || "—"}
                    </td>
                    <td>
                      <button
                        className="sdk-raw-link"
                        onClick={() => setExpanded(expanded === event.id ? null : event.id)}
                        aria-expanded={expanded === event.id}
                        title="Show original application log line"
                      >
                        {expanded === event.id ? "Hide raw log" : "Show raw log"}
                      </button>
                      {expanded === event.id && (
                        <pre className="sdk-raw-record">{event.raw_message || "No raw line stored"}</pre>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty
            title={
              liveEvents.length
                ? "No matching live logs"
                : "Waiting for application logs"
            }
            text={
              liveEvents.length
                ? "Try another server or search term."
                : "Send a request to a sample app or run a controlled test on Infrastructure. Use the same dashboard port as the app."
            }
          />
        )}
        {visible.length === 100 && (
          <p className="sdk-limit">
            Showing the latest 100 matching records. All evidence remains
            available on Events.
          </p>
        )}
      </Card>
    </>
  );
}
