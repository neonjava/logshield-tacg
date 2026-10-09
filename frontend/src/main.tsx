import { useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity,
  ArrowUpRight,
  Bell,
  Boxes,
  FlaskConical,
  Fingerprint,
  LayoutDashboard,
  Radio,
  ScrollText,
  Shield,
  ShieldAlert,
  X,
} from "lucide-react";
import { EventDetails } from "./components/ui";
import { useSecurity } from "./hooks/useSecurity";
import { Dashboard } from "./pages/Dashboard";
import { Events } from "./pages/Events";
import { Incidents } from "./pages/Incidents";
import { Entities, Responses } from "./pages/Inventory";
import { Infrastructure } from "./pages/Infrastructure";
import { Lab, SampleApp } from "./pages/Lab";
import { SdkLogs } from "./pages/SdkLogs";
import type { Page, SecurityEvent } from "./types";
import "./style.css";
const navigation = [
  { page: "dashboard", name: "Dashboard", icon: LayoutDashboard },
  { page: "incidents", name: "Incidents", icon: ShieldAlert },
  { page: "events", name: "Events", icon: Radio },
  { page: "sdk-logs", name: "SDK Live Logs", icon: ScrollText },
  { page: "entities", name: "Entities", icon: Fingerprint },
  { page: "responses", name: "Responses", icon: Activity },
  { page: "infrastructure", name: "Infrastructure", icon: Boxes },
  { page: "lab", name: "Local lab", icon: FlaskConical },
] as const;
function App() {
  const store = useSecurity();
  const [page, setPage] = useState<Page>(() => {
    const hash = location.hash.slice(1);
    return navigation.some((item) => item.page === hash)
      ? (hash as Page)
      : "dashboard";
  });
  const [selected, setSelected] = useState<string | null>(null);
  const [event, setEvent] = useState<SecurityEvent | null>(null);
  const navigate = (next: Page) => {
    setPage(next);
    setSelected(null);
    location.hash = next;
    window.scrollTo(0, 0);
  };
  const openIncident = (id: string | null) => {
    setPage("incidents");
    setSelected(id);
    location.hash = "incidents";
    window.scrollTo(0, 0);
  };
  return (
    <div className="shell">
      <aside className="sidebar">
        <a
          className="brand"
          href="#dashboard"
          onClick={() => navigate("dashboard")}
        >
          <span className="brand-icon">
            <Shield size={23} />
          </span>
          <span>
            <strong>LogShield</strong>
            <small>TEMPORAL ATTACK CORRELATION</small>
          </span>
        </a>
        <div className="nav-caption">WORKSPACE</div>
        <nav aria-label="Primary navigation">
          {navigation.map(({ page: key, name, icon: Icon }) => (
            <button
              key={key}
              className={`nav-link ${page === key ? "active" : ""}`}
              onClick={() => navigate(key)}
              aria-current={page === key ? "page" : undefined}
            >
              <Icon size={17} />
              <span>{name}</span>
              {key === "incidents" && store.stats.active_incidents > 0 && (
                <b className="nav-count">{store.stats.active_incidents}</b>
              )}
            </button>
          ))}
        </nav>
        <div className="sidebar-foot">
          <span
            className={`status-dot ${store.health?.sensor ? "online" : ""}`}
          >
            {store.health?.sensor ? "Sensor online" : "Sensor reconnecting"}
          </span>
          <small>AI26CY03 · Local security lab</small>
        </div>
      </aside>
      <div className="work-area">
        <header className="topbar">
          <div className="breadcrumb">
            <span>Workspace</span>
            <span>/</span>
            <strong>
              {navigation.find((item) => item.page === page)?.name}
            </strong>
          </div>
          <div className="topbar-right">
            <span className={`connection ${store.live ? "online" : ""}`}>
              <i />
              {store.live ? "Live stream" : "Reconnecting"}
            </span>
            <button
              className="topbar-alert"
              aria-label={`${store.stats.active_incidents} active incidents`}
              onClick={() => navigate("incidents")}
            >
              <Bell size={18} />
              {store.stats.active_incidents > 0 && (
                <b>{store.stats.active_incidents}</b>
              )}
            </button>
            <span className="avatar">LS</span>
          </div>
        </header>
        <main className="workspace-content">
          {!store.health && !store.loading && (
            <div className="connection-banner" role="status">
              Connecting to the Rust API. Existing evidence stays visible while
              the service restarts.
            </div>
          )}
          {page === "dashboard" && (
            <Dashboard
              store={store}
              onIncident={openIncident}
              onEvents={() => navigate("events")}
            />
          )}
          {page === "incidents" && (
            <Incidents
              store={store}
              selected={selected}
              onSelect={openIncident}
              onEvent={setEvent}
            />
          )}
          {page === "events" && <Events store={store} onEvent={setEvent} />}
          {page === "sdk-logs" && <SdkLogs store={store} onEvent={setEvent} />}
          {page === "entities" && <Entities store={store} />}
          {page === "responses" && (
            <Responses store={store} onIncident={openIncident} />
          )}
          {page === "infrastructure" && <Infrastructure store={store} />}
          {page === "lab" && <Lab store={store} />}
        </main>
        <footer className="site-footer">
          <span>LOGSHIELD TACG</span>
          <span>Rust correlation engine · Local gateway verification</span>
        </footer>
      </div>
      {store.notices.length > 0 && (
        <div className="notice-stack" aria-live="polite">
          {store.notices.map((notice) => (
            <div
              className={`notice ${notice.tone}`}
              key={notice.id}
              role="status"
            >
              <div>
                <strong>{notice.title}</strong>
                <p>{notice.message}</p>
                {notice.incidentId && (
                  <button
                    className="text-button"
                    onClick={() => openIncident(notice.incidentId!)}
                  >
                    View incident <ArrowUpRight size={14} />
                  </button>
                )}
              </div>
              <button
                className="icon-button"
                aria-label="Dismiss notification"
                onClick={() => store.dismiss(notice.id)}
              >
                <X size={17} />
              </button>
            </div>
          ))}
        </div>
      )}
      {event && (
        <EventDetails
          event={event}
          incidents={store.incidents}
          onClose={() => setEvent(null)}
          onIncident={(id) => {
            setEvent(null);
            openIncident(id);
          }}
        />
      )}
    </div>
  );
}
const sampleApp = /^\/lab\/(app-[abc])$/.exec(location.pathname)?.[1];
createRoot(document.getElementById("root")!).render(
  sampleApp ? <SampleApp app={sampleApp} /> : <App />,
);
