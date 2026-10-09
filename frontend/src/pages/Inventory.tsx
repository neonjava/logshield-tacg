import { useState } from "react";
import { Search, ArrowUpRight } from "lucide-react";
import { label, shortId, time } from "../api";
import { Badge, Card, Empty, Heading } from "../components/ui";
import type { SecurityStore } from "../hooks/useSecurity";
export function Entities({ store }: { store: SecurityStore }) {
  const [query, setQuery] = useState("");
  const entities = store.entities.filter((entity) =>
    `${entity.kind} ${entity.value}`
      .toLowerCase()
      .includes(query.toLowerCase()),
  );
  return (
    <>
      <Heading
        title="Entities"
        description="The hosts, accounts, and network identities observed in your logs."
      />
      <Card
        title="Entity inventory"
        action={<span className="muted">{entities.length} identities</span>}
      >
        <div className="toolbar">
          <label className="search-field">
            <Search size={17} />
            <input
              aria-label="Search entities"
              placeholder="Find a host, account, or address…"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
            />
          </label>
        </div>
        {entities.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Identity</th>
                  <th>Type</th>
                  <th>Events</th>
                  <th>First observed</th>
                  <th>Last observed</th>
                </tr>
              </thead>
              <tbody>
                {entities.map((entity) => (
                  <tr key={`${entity.kind}:${entity.value}`}>
                    <td className="mono bold">{entity.value}</td>
                    <td>{label(entity.kind)}</td>
                    <td>{entity.event_count}</td>
                    <td>{time(entity.first_seen)}</td>
                    <td>{time(entity.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty text="Entities are extracted automatically from ingested logs." />
        )}
      </Card>
    </>
  );
}
export function Responses({
  store,
  onIncident,
}: {
  store: SecurityStore;
  onIncident: (id: string) => void;
}) {
  const responses = store.incidents.filter((incident) => incident.response);
  return (
    <>
      <Heading
        title="Responses"
        description="Defensive actions and the verification evidence behind each result."
      />
      <div className="stat-strip">
        <div>
          <span>Verified contained</span>
          <strong className="text-success">
            {store.stats.contained_incidents}
          </strong>
        </div>
        <div>
          <span>Response failures</span>
          <strong className="text-danger">
            {store.stats.response_failures}
          </strong>
        </div>
        <div>
          <span>Recorded responses</span>
          <strong>{responses.length}</strong>
        </div>
      </div>
      <Card
        title="Response ledger"
        subtitle="Containment requires a verified gateway retry."
      >
        {responses.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Incident</th>
                  <th>Source</th>
                  <th>Status</th>
                  <th>Proof</th>
                  <th>Inspect</th>
                </tr>
              </thead>
              <tbody>
                {responses.map((incident) => (
                  <tr key={incident.id}>
                    <td className="mono">LS-{shortId(incident.id)}</td>
                    <td>{incident.source_ip}</td>
                    <td>
                      <Badge value={incident.status} />
                    </td>
                    <td>
                      {incident.response?.proof.some(
                        (step) => step.stage === "CONTAINMENT_VERIFIED",
                      )
                        ? "HTTP 403 · verified"
                        : "Verification needs review"}
                    </td>
                    <td>
                      <button
                        className="button small"
                        onClick={() => onIncident(incident.id)}
                      >
                        View evidence
                        <ArrowUpRight size={15} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty
            title="No response actions"
            text="Verified response records appear when the gateway acts on an eligible incident."
          />
        )}
      </Card>
    </>
  );
}
