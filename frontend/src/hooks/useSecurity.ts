import { useCallback, useEffect, useRef, useState } from "react";
import { api, isFailure, shortId } from "../api";
import type {
  Entity,
  Health,
  Incident,
  Notice,
  SecurityEvent,
  Stats,
} from "../types";

const empty: Stats = {
  events_processed: 0,
  active_incidents: 0,
  critical_incidents: 0,
  contained_incidents: 0,
  response_failures: 0,
  risk_distribution: {},
  host_activity: {},
};
export function useSecurity() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [entities, setEntities] = useState<Entity[]>([]);
  const [stats, setStats] = useState(empty);
  const [health, setHealth] = useState<Health | null>(null);
  const [live, setLive] = useState(false);
  const [loading, setLoading] = useState(true);
  const [notices, setNotices] = useState<Notice[]>([]);
  const sequence = useRef(0);
  const mounted = useRef(true);
  const fetching = useRef(false);
  const prior = useRef<{
    events: Set<string>;
    incidents: Map<string, string>;
  } | null>(null);
  const notify = useCallback(
    (
      title: string,
      message: string,
      tone: Notice["tone"] = "neutral",
      incidentId?: string,
    ) => {
      if (!mounted.current) return;
      setNotices((current) =>
        [
          ...current,
          {
            id: ++sequence.current,
            title,
            message,
            tone,
            incidentId,
            expires: Date.now() + 9000,
          },
        ].slice(-3),
      );
    },
    [],
  );
  const dismiss = useCallback(
    (id: number) =>
      setNotices((current) => current.filter((item) => item.id !== id)),
    [],
  );
  const refresh = useCallback(async () => {
    if (fetching.current) return;
    fetching.current = true;
    try {
      const [nextEvents, nextIncidents, nextStats, nextHealth, nextEntities] =
        await Promise.all([
          api<SecurityEvent[]>("/events"),
          api<Incident[]>("/incidents"),
          api<Stats>("/stats"),
          api<Health>("/status"),
          api<Entity[]>("/entities"),
        ]);
      if (!mounted.current) return;
      if (prior.current) {
        const failures = nextEvents.filter(
          (event) =>
            !prior.current!.events.has(event.id) &&
            event.origin !== "manual_upload" &&
            isFailure(event) &&
            /login|mfa|auth|password/.test(event.event_type),
        );
        if (failures.length)
          notify(
            "Authentication failure",
            `${failures.length} new failed attempt${failures.length === 1 ? "" : "s"}. Inspect the Events page for evidence.`,
            "danger",
          );
        for (const incident of nextIncidents) {
          if (prior.current.incidents.get(incident.id) === incident.status)
            continue;
          if (incident.status === "CONTAINED")
            notify(
              "Containment verified",
              `${incident.source_ip || "Source"} blocked. A gateway retry returned HTTP 403.`,
              "success",
              incident.id,
            );
          else if (incident.status === "RESPONSE_FAILED")
            notify(
              "Response failed",
              `Incident ${shortId(incident.id)} needs human review. Containment was not verified.`,
              "danger",
              incident.id,
            );
        }
      }
      prior.current = {
        events: new Set(nextEvents.map((event) => event.id)),
        incidents: new Map(
          nextIncidents.map((incident) => [incident.id, incident.status]),
        ),
      };
      setEvents(nextEvents);
      setIncidents(nextIncidents);
      setStats(nextStats);
      setHealth(nextHealth);
      setEntities(nextEntities);
    } catch {
      if (mounted.current) setHealth(null);
    } finally {
      fetching.current = false;
      if (mounted.current) setLoading(false);
    }
  }, [notify]);
  useEffect(() => {
    mounted.current = true;
    void refresh();
    const polling = setInterval(() => void refresh(), 2500);
    const expiration = setInterval(
      () =>
        setNotices((current) =>
          current.filter((item) => item.expires > Date.now()),
        ),
      1000,
    );
    let socket: WebSocket | undefined;
    let retry: ReturnType<typeof setTimeout> | undefined;
    let stopped = false;
    let delay = 1000;
    const connect = () => {
      if (stopped) return;
      const connection = new WebSocket(
        `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws/events`,
      );
      socket = connection;
      connection.onopen = () => {
        if (!stopped) {
          setLive(true);
          delay = 1000;
          void refresh();
        }
      };
      connection.onmessage = () => void refresh();
      connection.onerror = () => connection.close();
      connection.onclose = () => {
        if (!stopped) {
          setLive(false);
          retry = setTimeout(connect, delay);
          delay = Math.min(delay * 2, 10000);
        }
      };
    };
    connect();
    return () => {
      stopped = true;
      mounted.current = false;
      clearInterval(polling);
      clearInterval(expiration);
      if (retry) clearTimeout(retry);
      socket?.close();
    };
  }, [refresh]);
  return {
    events,
    incidents,
    stats,
    health,
    entities,
    live,
    loading,
    notices,
    notify,
    dismiss,
    refresh,
  };
}
export type SecurityStore = ReturnType<typeof useSecurity>;
