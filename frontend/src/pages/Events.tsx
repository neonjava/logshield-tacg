import { useState } from "react";
import { Download, Search, Upload } from "lucide-react";
import { api, isFailure, shortId, time } from "../api";
import { Card, Empty, ErrorNotice, EventName, Heading } from "../components/ui";
import type { SecurityStore } from "../hooks/useSecurity";
import type { ImportResult, SecurityEvent } from "../types";

export function Events({
  store,
  onEvent,
}: {
  store: SecurityStore;
  onEvent: (event: SecurityEvent) => void;
}) {
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState("all");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<ImportResult | null>(null);
  const memberships = new Map(
    store.incidents.flatMap((incident) =>
      incident.events.map((event) => [event.id, incident.id] as const),
    ),
  );
  const events = store.events.filter(
    (event) =>
      (filter !== "failures" || isFailure(event)) &&
      [
        event.source_ip,
        event.hostname,
        event.username,
        event.event_type,
        event.destination_ip,
      ]
        .join(" ")
        .toLowerCase()
        .includes(query.toLowerCase()),
  );
  const upload = async (file?: File) => {
    if (!file) return;
    setBusy(true);
    setError("");
    try {
      const body = new FormData();
      body.append("file", file);
      const imported = await api<ImportResult>("/logs/upload", {
        method: "POST",
        body,
      });
      setResult(imported);
      store.notify(
        "Log import complete",
        `${imported.accepted} added · ${imported.duplicates} duplicates · ${imported.rejected} rejected`,
        imported.rejected ? "danger" : "success",
      );
      await store.refresh();
    } catch (error) {
      setError(String(error));
      store.notify("Import failed", String(error), "danger");
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <Heading
        title="Events"
        description="Search your logs, inspect raw evidence, or import a file for analysis."
        action={
          <>
            <a className="button" href="/api/logs/export" download>
              <Download size={16} />
              Export JSONL
            </a>
            <label className={`button primary ${busy ? "disabled" : ""}`}>
              <Upload size={16} />
              {busy ? "Importing…" : "Import logs"}
              <input
                className="sr-only"
                type="file"
                disabled={busy}
                accept=".log,.txt,.jsonl"
                onChange={(event) => {
                  void upload(event.target.files?.[0]);
                  event.target.value = "";
                }}
              />
            </label>
          </>
        }
      />
      <ErrorNotice message={error} />
      <Card
        title="Log explorer"
        action={<span className="muted">{events.length} records</span>}
      >
        <div className="toolbar">
          <label className="search-field">
            <Search size={17} />
            <input
              aria-label="Search events"
              placeholder="Search source, host, account, or event…"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
            />
          </label>
          <select
            aria-label="Filter events"
            value={filter}
            onChange={(event) => setFilter(event.target.value)}
          >
            <option value="all">All events</option>
            <option value="failures">Failures & denials</option>
          </select>
        </div>
        <details className="sample-downloads">
          <summary>Download sample logs for a manual demo</summary>
          <div className="sample-buttons">
            {["normal", "bruteforce", "distributed", "suspicious", "mfa"].map(
              (name) => (
                <a
                  className="button small"
                  href={`/api/logs/sample/${name}`}
                  download
                  key={name}
                >
                  <Download size={14} />
                  {name === "mfa" ? "MFA failures" : name}
                </a>
              ),
            )}
          </div>
        </details>
        {result && (
          <div className="import-summary" role="status">
            <strong>{result.accepted} events imported</strong>
            <span>
              {result.duplicates} duplicates · {result.rejected} rejected.
              Uploaded files cannot authorize automatic containment.
            </span>
          </div>
        )}
        {events.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  {[
                    "Time",
                    "Source",
                    "Destination / host",
                    "Account",
                    "Event",
                    "Result",
                    "Origin",
                    "Incident",
                  ].map((name) => (
                    <th key={name}>{name}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {events.map((event) => (
                  <tr
                    className={isFailure(event) ? "failed-row" : ""}
                    key={event.id}
                  >
                    <td className="mono">{time(event.timestamp)}</td>
                    <td className="mono">{event.source_ip || "—"}</td>
                    <td>
                      <strong>{event.hostname || "—"}</strong>
                      <small className="cell-subtitle mono">
                        {event.destination_ip || ""}
                      </small>
                    </td>
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
                    <td className="mono muted">{event.origin || "—"}</td>
                    <td className="mono">
                      {memberships.has(event.id)
                        ? shortId(memberships.get(event.id)!)
                        : "Unlinked"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty
            title={query ? "No matching events" : "No events yet"}
            text="Import logs or run a local test to see recorded activity."
          />
        )}
      </Card>
    </>
  );
}
