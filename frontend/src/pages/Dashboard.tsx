import { ArrowUpRight, RefreshCw } from "lucide-react";
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  CartesianGrid,
  XAxis,
  YAxis,
  Tooltip,
} from "recharts";
import { isFailure, time } from "../api";
import { Card, Empty, Heading, IncidentsTable } from "../components/ui";
import type { SecurityStore } from "../hooks/useSecurity";

export function Dashboard({
  store,
  onIncident,
  onEvents,
}: {
  store: SecurityStore;
  onIncident: (id: string) => void;
  onEvents: () => void;
}) {
  const { health, stats, events, incidents } = store;
  const services = Math.max(0, Math.min(3, health?.services_online || 0));
  const checks = [
    ["Gateway", health?.gateway],
    ["Log sensor", health?.sensor],
    ["TACG engine", health?.tacg],
    ["Evidence database", health?.database],
  ] as const;
  const online = health
    ? checks.filter(([, value]) => value).length + services
    : 0;
  const percentage = Math.round((online / 7) * 100);
  const buckets = new Map<
    number,
    { timestamp: number; total: number; failures: number; normal: number }
  >();
  for (const event of events) {
    const timestamp =
      Math.floor(new Date(event.timestamp).getTime() / 1000) * 1000;
    if (!Number.isFinite(timestamp)) continue;
    const bucket = buckets.get(timestamp) || {
      timestamp,
      total: 0,
      failures: 0,
      normal: 0,
    };
    bucket.total++;
    if (isFailure(event)) bucket.failures++;
    else bucket.normal++;
    buckets.set(timestamp, bucket);
  }
  const chart = [...buckets.values()]
    .sort((a, b) => a.timestamp - b.timestamp)
    .slice(-18);
  return (
    <>
      <Heading
        title="Security overview"
        description="One view of your systems, activity, and correlated threats."
        action={
          <button className="button" onClick={() => void store.refresh()}>
            <RefreshCw size={15} />
            Refresh
          </button>
        }
      />
      <div className="dashboard-grid">
        <Card
          title="System health"
          subtitle="Live availability of seven monitored components."
          action={
            <span className={`status-dot ${health ? "online" : ""}`}>
              {health ? "Connected" : "Reconnecting"}
            </span>
          }
        >
          <div className="health-gauge">
            <svg
              viewBox="0 0 360 208"
              role="img"
              aria-label={`${online} of 7 components online`}
            >
              {Array.from({ length: 28 }, (_, index) => {
                const angle = Math.PI - (index / 27) * Math.PI;
                return (
                  <line
                    key={index}
                    x1={180 + Math.cos(angle) * 108}
                    y1={164 - Math.sin(angle) * 108}
                    x2={180 + Math.cos(angle) * 141}
                    y2={164 - Math.sin(angle) * 141}
                    stroke={
                      health && index < Math.round((28 * online) / 7)
                        ? "#a9dfb8"
                        : "#292b2e"
                    }
                    strokeWidth="9"
                    strokeLinecap="round"
                  />
                );
              })}
              <text x="180" y="139" textAnchor="middle" className="gauge-value">
                {health ? `${percentage}%` : "—"}
              </text>
              <text
                x="180"
                y="166"
                textAnchor="middle"
                className="gauge-caption"
              >
                {online} of 7 components online
              </text>
            </svg>
          </div>
          <div className="system-checks">
            {checks.map(([name, value]) => (
              <div key={name}>
                <span>{name}</span>
                <strong className={value ? "text-success" : "muted"}>
                  {health ? (value ? "Online" : "Offline") : "Unknown"}
                </strong>
              </div>
            ))}
            <div>
              <span>Lab services</span>
              <strong>{health ? `${services} / 3 online` : "Unknown"}</strong>
            </div>
            <div>
              <span>Last event</span>
              <strong className="mono">{time(health?.last_event)}</strong>
            </div>
          </div>
        </Card>
        <Card
          title="Event activity"
          subtitle="Recent log records, grouped by their recorded second."
          action={
            <button className="text-button" onClick={onEvents}>
              Explore logs <ArrowUpRight size={15} />
            </button>
          }
        >
          <div className="summary-metrics">
            <div>
              <span>Events ingested</span>
              <strong>{stats.events_processed.toLocaleString()}</strong>
            </div>
            <div>
              <span>Open incidents</span>
              <strong className={stats.active_incidents ? "text-danger" : ""}>
                {stats.active_incidents}
              </strong>
            </div>
            <div>
              <span>Verified contained</span>
              <strong className="text-success">
                {stats.contained_incidents}
              </strong>
            </div>
          </div>
          {chart.length ? (
            <div className="activity-chart">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={chart}>
                  <CartesianGrid stroke="#292b2e" vertical={false} />
                  <XAxis
                    dataKey="timestamp"
                    tickFormatter={(value) =>
                      time(new Date(value).toISOString())
                    }
                    tick={{ fill: "#91969e", fontSize: 11 }}
                    axisLine={false}
                    tickLine={false}
                    minTickGap={32}
                  />
                  <YAxis
                    allowDecimals={false}
                    width={28}
                    tick={{ fill: "#91969e", fontSize: 11 }}
                    axisLine={false}
                    tickLine={false}
                  />
                  <Tooltip
                    cursor={{ fill: "#202225" }}
                    contentStyle={{
                      background: "#181a1d",
                      border: "1px solid #404348",
                      borderRadius: 8,
                      color: "#fff",
                    }}
                    labelFormatter={(value) =>
                      time(new Date(Number(value)).toISOString())
                    }
                  />
                  <Bar
                    name="Other events"
                    dataKey="normal"
                    stackId="events"
                    fill="#a9dfb8"
                    maxBarSize={20}
                  />
                  <Bar
                    name="Failed / denied"
                    dataKey="failures"
                    stackId="events"
                    fill="#ef8d91"
                    maxBarSize={20}
                    radius={[3, 3, 0, 0]}
                  />
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <Empty
              title="Waiting for activity"
              text="Import a log file or send traffic from the local lab."
            />
          )}
          <div className="chart-footer">
            <span>
              <i className="legend-dot green" />
              Other events
            </span>
            <span>
              <i className="legend-dot red" />
              Failed / denied
            </span>
            <span className="push-right">
              {health?.events_per_second?.toFixed(2) || "0.00"} events/sec ·
              last minute
            </span>
          </div>
        </Card>
      </div>
      <Card
        title="Correlated incidents"
        subtitle="Open an incident to follow its evidence, risk, and response."
      >
        <IncidentsTable
          incidents={incidents.slice(0, 6)}
          onSelect={onIncident}
        />
      </Card>
    </>
  );
}
