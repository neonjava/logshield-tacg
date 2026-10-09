import { useEffect, useRef, type ReactNode } from "react";
import { ArrowUpRight, CheckCircle2, Inbox, X } from "lucide-react";
import { isFailure, label, safeJson, shortId, time } from "../api";
import type { HttpResult, Incident, SecurityEvent } from "../types";

export function Card({
  title,
  subtitle,
  action,
  children,
  className = "",
}: {
  title: string;
  subtitle?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`card ${className}`}>
      <div className="card-heading">
        <div>
          <h2>{title}</h2>
          {subtitle && <p>{subtitle}</p>}
        </div>
        {action}
      </div>
      {children}
    </section>
  );
}
export function Heading({
  title,
  description,
  action,
}: {
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="page-heading">
      <div>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {action && <div className="heading-actions">{action}</div>}
    </div>
  );
}
export function Badge({ value }: { value: string }) {
  const tone = /critical|failed|failure|denied|blocked/i.test(value)
    ? "danger"
    : /contained|success|online|verified/i.test(value)
      ? "success"
      : /high|medium|pending/i.test(value)
        ? "warning"
        : "neutral";
  return <span className={`badge ${tone}`}>{label(value)}</span>;
}
export function Empty({
  title = "No records yet",
  text,
}: {
  title?: string;
  text: string;
}) {
  return (
    <div className="empty">
      <Inbox size={25} />
      <strong>{title}</strong>
      <p>{text}</p>
    </div>
  );
}
export function ErrorNotice({ message }: { message: string }) {
  return message ? (
    <div className="inline-error" role="alert">
      {message}
    </div>
  ) : null;
}
export function RawJson({
  value,
  summary = "Inspect raw JSON",
}: {
  value: unknown;
  summary?: string;
}) {
  return (
    <details className="raw-details">
      <summary>{summary}</summary>
      <pre>{safeJson(value)}</pre>
    </details>
  );
}
export function Modal({
  title,
  children,
  onClose,
  drawer = false,
}: {
  title: string;
  children: ReactNode;
  onClose: () => void;
  drawer?: boolean;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const previous = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    ref.current?.showModal();
    return () => {
      document.body.style.overflow = previous;
    };
  }, []);
  return (
    <dialog
      ref={ref}
      className={`dialog ${drawer ? "drawer" : ""}`}
      onCancel={(event) => {
        event.preventDefault();
        onClose();
      }}
    >
      <div className="dialog-heading">
        <h2>{title}</h2>
        <button
          className="icon-button"
          aria-label="Close dialog"
          onClick={onClose}
        >
          <X size={20} />
        </button>
      </div>
      <div className="dialog-content">{children}</div>
    </dialog>
  );
}
export function LoginSuccess({ onClose }: { onClose: () => void }) {
  return (
    <Modal title="Login successful" onClose={onClose}>
      <div className="login-success">
        <CheckCircle2 size={48} />
        <h3>You’re signed in</h3>
        <p>
          Password and MFA verified. One shared session is ready across the
          three application servers.
        </p>
        <button className="button primary" onClick={onClose}>
          Continue
        </button>
      </div>
    </Modal>
  );
}
export function EventDetails({
  event,
  incidents,
  onClose,
  onIncident,
}: {
  event: SecurityEvent;
  incidents: Incident[];
  onClose: () => void;
  onIncident: (id: string) => void;
}) {
  const memberships = incidents.filter((incident) =>
    incident.events.some((item) => item.id === event.id),
  );
  const edges = memberships.flatMap((incident) =>
    incident.edges.filter(
      (edge) => edge.from === event.id || edge.to === event.id,
    ),
  );
  return (
    <Modal drawer title="Event evidence" onClose={onClose}>
      <div className="event-detail-title">
        <Badge value={event.event_type} />
        <span className="mono muted">{time(event.timestamp)}</span>
      </div>
      <dl className="key-values">
        {[
          ["Source", event.source_ip],
          ["Destination", event.destination_ip || event.hostname],
          ["Account", event.username],
          ["Result", event.result],
          ["Origin", event.origin],
        ].map(([key, value]) => (
          <div key={key}>
            <dt>{key}</dt>
            <dd>{value || "—"}</dd>
          </div>
        ))}
      </dl>
      <h3>Raw event</h3>
      <pre>{event.raw_message || "No raw message supplied"}</pre>
      <h3>Normalized event</h3>
      <pre>{safeJson(event)}</pre>
      <h3>Temporal relationships</h3>
      {edges.length ? (
        edges.map((edge, index) => (
          <div
            className="relationship"
            key={`${edge.from}-${edge.to}-${index}`}
          >
            <span className="mono">
              {shortId(edge.from)} → {shortId(edge.to)}
            </span>
            <p>{edge.reasons.join(" · ")}</p>
            <small>Strength {Number(edge.strength).toFixed(3)}</small>
          </div>
        ))
      ) : (
        <p className="muted">No correlation edge recorded.</p>
      )}
      <h3>Incident membership</h3>
      {memberships.length ? (
        memberships.map((incident) => (
          <button
            className="button secondary"
            key={incident.id}
            onClick={() => onIncident(incident.id)}
          >
            {shortId(incident.id)} · Risk {incident.risk}
            <ArrowUpRight size={16} />
          </button>
        ))
      ) : (
        <p className="muted">This event is not linked to an incident.</p>
      )}
    </Modal>
  );
}
export function IncidentsTable({
  incidents,
  onSelect,
  compact = false,
}: {
  incidents: Incident[];
  onSelect: (id: string) => void;
  compact?: boolean;
}) {
  if (!incidents.length)
    return (
      <Empty
        title="No incidents detected"
        text="New correlated threats appear here as logs arrive."
      />
    );
  return (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            <th>Incident</th>
            <th>Risk</th>
            <th>Source</th>
            {!compact && <th>Evidence</th>}
            <th>Status</th>
            <th>
              <span className="sr-only">Open</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {incidents.map((incident) => (
            <tr key={incident.id}>
              <td>
                <button
                  className="table-link"
                  onClick={() => onSelect(incident.id)}
                >
                  <strong>{label(incident.kind)}</strong>
                  <span className="mono muted">LS-{shortId(incident.id)}</span>
                </button>
              </td>
              <td>
                <span
                  className={`risk-value ${incident.risk >= 70 ? "text-danger" : ""}`}
                >
                  {incident.risk}
                  <small>/100</small>
                </span>
              </td>
              <td className="mono">{incident.source_ip || "—"}</td>
              {!compact && (
                <td>
                  {incident.events.length} events · {incident.edges.length}{" "}
                  links
                </td>
              )}
              <td>
                <Badge value={incident.status} />
              </td>
              <td>
                <button
                  className="icon-button"
                  aria-label={`Open incident ${shortId(incident.id)}`}
                  onClick={() => onSelect(incident.id)}
                >
                  <ArrowUpRight size={17} />
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
export function RequestResults({
  requests,
  raw,
}: {
  requests: HttpResult[];
  raw: unknown;
}) {
  return (
    <Card
      title="Request results"
      subtitle="Actual HTTP responses from the local gateway."
    >
      {requests.length > 0 && (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Operation</th>
                <th>Server</th>
                <th>HTTP result</th>
              </tr>
            </thead>
            <tbody>
              {requests.map((request, index) => (
                <tr key={`${request.request_id || index}`}>
                  <td>{label(request.action || "request")}</td>
                  <td className="mono">{request.body?.served_by || "—"}</td>
                  <td>
                    <span
                      className={`http-status ${request.status >= 400 ? "text-danger" : "text-success"}`}
                    >
                      HTTP {request.status}
                      {request.status === 403
                        ? " · Blocked"
                        : request.status === 401
                          ? " · Unauthorized"
                          : ""}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <RawJson value={raw} />
    </Card>
  );
}
export function EventName({ event }: { event: SecurityEvent }) {
  return (
    <span className={`event-name ${isFailure(event) ? "failure" : ""}`}>
      {label(event.event_type)}
    </span>
  );
}
