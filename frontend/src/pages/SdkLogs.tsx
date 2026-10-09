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

  const agentEvents = useMemo(
    () =>
      store.events
        .filter((event) => event.origin?.startsWith("agent:infra-"))
        .sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp)),
    [store.events],
  );
  const visible = agentEvents
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
        description="Application logs delivered by the three Rust agents. Manual uploads and generated demo events are excluded."
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
          const count = agentEvents.filter(
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
      <Card
        title="Agent-delivered event stream"
        subtitle="Each row is an application log normalized by the Rust agent and accepted by LogShield. New records appear automatically."
        action={
          <button className="button small" onClick={() => void store.refresh()}>
            <RefreshCw size={14} /> Refresh
          </button>
        }
      >
        <div className="sdk-stream-meta">
          <span>{agentEvents.length} agent logs stored</span>
          <span>Latest: {time(agentEvents[0]?.timestamp)}</span>
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
            <option value="all">All three servers</option>
            {SERVERS.map((name) => (
              <option value={name} key={name}>
                {name}
              </option>
            ))}
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
                  <tr
                    key={event.id}
                    className={isFailure(event) ? "failed-row" : ""}
                  >
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
                        onClick={() => onEvent(event)}
                        title="Open complete raw event"
                      >
                        {event.raw_message || "—"}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty
            title={
              agentEvents.length
                ? "No matching agent logs"
                : "Waiting for application logs"
            }
            text={
              agentEvents.length
                ? "Try another server or search term."
                : "Run a normal login or controlled test on the Infrastructure page. The three application agents will deliver their actual logs here."
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
