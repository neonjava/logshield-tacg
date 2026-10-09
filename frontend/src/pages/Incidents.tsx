import { useState } from "react";
import { ArrowLeft, ArrowUpRight, Search } from "lucide-react";
import { label, shortId, time } from "../api";
import {
  Badge,
  Card,
  Empty,
  EventName,
  Heading,
  IncidentsTable,
  RawJson,
} from "../components/ui";
import type { SecurityStore } from "../hooks/useSecurity";
import type { Incident, SecurityEvent } from "../types";
const features: [string, string, number][] = [
  ["Event rarity", "event_rarity", 20],
  ["Temporal correlation", "temporal_strength", 20],
  ["Entity relationship", "entity_relationship", 15],
  ["Transition risk", "transition_risk", 20],
  ["Cross-host activity", "cross_host_score", 10],
  ["Behavior deviation", "behaviour_deviation", 15],
  ["Attack chain bonus", "attack_chain_bonus", 25],
];
export function Incidents({
  store,
  selected,
  onSelect,
  onEvent,
}: {
  store: SecurityStore;
  selected: string | null;
  onSelect: (id: string | null) => void;
  onEvent: (event: SecurityEvent) => void;
}) {
  const [query, setQuery] = useState("");
  const incident = store.incidents.find((item) => item.id === selected);
  if (!incident) {
    const list = store.incidents.filter((item) =>
      `${item.kind} ${item.source_ip} ${item.status}`
        .toLowerCase()
        .includes(query.toLowerCase()),
    );
    return (
      <>
        <Heading
          title="Incidents"
          description="Attack stories reconstructed from correlated security events."
          action={
            <span className="page-count">
              {store.incidents.length} total · {store.stats.active_incidents}{" "}
              open
            </span>
          }
        />
        <Card title="Incident queue">
          <div className="toolbar">
            <label className="search-field">
              <Search size={17} />
              <input
                aria-label="Search incidents"
                placeholder="Search source, type, or status…"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
              />
            </label>
          </div>
          <IncidentsTable incidents={list} onSelect={onSelect} />
        </Card>
      </>
    );
  }
  const targets = [
    ...new Set(incident.events.map((event) => event.hostname).filter(Boolean)),
  ];
  const failures = incident.events.filter(
    (event) => event.event_type === "failed_login",
  );
  const times = incident.events
    .map((event) => new Date(event.timestamp).getTime())
    .filter(Number.isFinite);
  const span =
    times.length > 1
      ? Math.round((Math.max(...times) - Math.min(...times)) / 1000)
      : 0;
  return (
    <>
      <button className="back-link" onClick={() => onSelect(null)}>
        <ArrowLeft size={16} />
        All incidents
      </button>
      <Heading
        title={label(incident.kind)}
        description={`Incident LS-${shortId(incident.id)} · ${time(incident.created_at || incident.events[0]?.timestamp)}`}
        action={<Badge value={incident.status} />}
      />
      <div className="incident-hero card">
        <div className="hero-risk">
          <span>Risk score</span>
          <strong className={incident.risk >= 70 ? "text-danger" : ""}>
            {incident.risk}
            <small>/100</small>
          </strong>
          <Badge value={incident.severity} />
        </div>
        <div>
          <span>Detection confidence</span>
          <strong>{incident.confidence}%</strong>
          <small>Based on linked evidence</small>
        </div>
        <div>
          <span>Source</span>
          <strong className="mono">{incident.source_ip || "Unknown"}</strong>
          <small>{targets.length} affected hosts</small>
        </div>
        <div>
          <span>Incident status</span>
          <strong>{label(incident.status)}</strong>
          <small>
            {incident.response
              ? incident.response.result
              : "Response pending or not eligible"}
          </small>
        </div>
      </div>
      <div className="detail-grid">
        <Card
          title="Attack timeline"
          subtitle={`${incident.events.length} recorded events in ${span} seconds.`}
        >
          {incident.events.length ? (
            <div className="timeline">
              {incident.events.map((event, index) => (
                <button
                  key={event.id}
                  className="timeline-row"
                  onClick={() => onEvent(event)}
                >
                  <span className="timeline-index">
                    {String(index + 1).padStart(2, "0")}
                  </span>
                  <span className="timeline-body">
                    <EventName event={event} />
                    <strong className="mono">
                      {event.source_ip || "—"} →{" "}
                      {event.hostname || event.destination_ip || "—"}
                    </strong>
                    <small>
                      {event.username || "No account"}
                      {index > 0
                        ? ` · ${incident.edges.find((edge) => edge.to === event.id)?.reasons.join(" · ") || "Linked in time"}`
                        : ""}
                    </small>
                  </span>
                  <time className="mono">{time(event.timestamp)}</time>
                  <ArrowUpRight size={16} />
                </button>
              ))}
            </div>
          ) : (
            <Empty text="No event evidence is attached." />
          )}
        </Card>
        <Card
          title="TACG relationships"
          subtitle="Click an identity to inspect the logs behind it."
        >
          <CorrelationGraph incident={incident} onEvent={onEvent} />
        </Card>
      </div>
      <div className="detail-grid">
        <Card
          title="Detection evidence"
          subtitle="Why the events were grouped into one incident."
        >
          <div className="proof-facts">
            <div>
              <span>Failed logins</span>
              <strong>{failures.length}</strong>
            </div>
            <div>
              <span>Related hosts</span>
              <strong>{targets.length}</strong>
            </div>
            <div>
              <span>Graph edges</span>
              <strong>{incident.edges.length}</strong>
            </div>
            <div>
              <span>Time window</span>
              <strong>{span}s</strong>
            </div>
          </div>
          {failures.length > 0 && (
            <div className="host-threshold">
              <h3>Per-host threshold: 5 failures</h3>
              {targets.map((host) => {
                const count = failures.filter(
                  (event) => event.hostname === host,
                ).length;
                return (
                  <div key={host}>
                    <span className="mono">{host}</span>
                    <strong>{count} / 5</strong>
                    <Badge
                      value={count < 5 ? "Below threshold" : "Threshold met"}
                    />
                  </div>
                );
              })}
            </div>
          )}
          <ul className="reason-list">
            {incident.reasons.map((reason, index) => (
              <li key={index}>{reason}</li>
            ))}
          </ul>
        </Card>
        <Card
          title="Risk calculation"
          subtitle="Each bar shows its exact weighted contribution."
        >
          <div className="score-list">
            {features.map(([name, key, maximum]) => {
              const value = Number(incident.score[key] || 0);
              return (
                <div className="score-line" key={key}>
                  <span>{name}</span>
                  <div className="score-track">
                    <i
                      style={{
                        width: `${Math.min(100, (value / maximum) * 100)}%`,
                      }}
                    />
                  </div>
                  <strong className="mono">
                    {value.toFixed(1)} / {maximum}
                  </strong>
                </div>
              );
            })}
          </div>
          <div className="risk-formula">
            <span>Weighted evidence + attack chain bonus</span>
            <strong>{incident.risk} / 100</strong>
          </div>
        </Card>
      </div>
      <Card
        title="Response and verification"
        subtitle="The incident is contained only after the gateway retry confirms the block."
      >
        {incident.response?.proof?.length ? (
          <div className="verification-list">
            {incident.response.proof.map((step, index) => (
              <div className="verification-row" key={`${step.stage}-${index}`}>
                <time className="mono">{time(step.timestamp)}</time>
                <span className="verification-dot" />
                <div>
                  <strong>{label(step.stage)}</strong>
                  <p>{step.detail}</p>
                </div>
                <span
                  className={
                    step.http_status === 403
                      ? "text-success mono"
                      : "mono muted"
                  }
                >
                  {step.http_status ? `HTTP ${step.http_status}` : ""}
                </span>
              </div>
            ))}
          </div>
        ) : (
          <Empty
            title="No response recorded"
            text="Manual log uploads stay in investigation mode. Eligible live threats can trigger local gateway containment."
          />
        )}
        {incident.recommended_actions?.length ? (
          <div className="recommendations">
            <h3>Recommended actions</h3>
            <ul>
              {incident.recommended_actions.map((action, index) => (
                <li key={index}>{action}</li>
              ))}
            </ul>
          </div>
        ) : null}
        <RawJson value={incident.response} summary="Inspect response record" />
      </Card>
    </>
  );
}
function CorrelationGraph({
  incident,
  onEvent,
}: {
  incident: Incident;
  onEvent: (event: SecurityEvent) => void;
}) {
  const [entity, setEntity] = useState(incident.source_ip || "");
  const hosts = [
    ...new Set(incident.events.map((event) => event.hostname).filter(Boolean)),
  ] as string[];
  const account = incident.events.find((event) => event.username)?.username;
  const related = incident.events.filter((event) =>
    [event.source_ip, event.hostname, event.username].includes(entity),
  );
  return (
    <>
      <div className="entity-graph">
        <button
          className={entity === incident.source_ip ? "selected" : ""}
          onClick={() => setEntity(incident.source_ip || "")}
        >
          {incident.source_ip || "Unknown source"}
          <small>Source</small>
        </button>
        <div className="graph-connector">↓ shared source &amp; time</div>
        <div className="graph-hosts">
          {hosts.map((host) => (
            <button
              className={entity === host ? "selected" : ""}
              key={host}
              onClick={() => setEntity(host)}
            >
              {host}
              <small>
                {
                  incident.events.filter((event) => event.hostname === host)
                    .length
                }{" "}
                events
              </small>
            </button>
          ))}
        </div>
        {account && (
          <>
            <div className="graph-connector">↓ shared account</div>
            <button
              className={entity === account ? "selected" : ""}
              onClick={() => setEntity(account)}
            >
              {account}
              <small>Account</small>
            </button>
          </>
        )}
      </div>
      <div className="related-events">
        <strong>
          {related.length} events linked to {entity}
        </strong>
        {related.map((event) => (
          <button key={event.id} onClick={() => onEvent(event)}>
            <time>{time(event.timestamp)}</time>
            <span>{label(event.event_type)}</span>
            <span className="mono">{event.hostname}</span>
            <ArrowUpRight size={15} />
          </button>
        ))}
      </div>
    </>
  );
}
