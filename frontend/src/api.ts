export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api${path}`, init);
  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || `Request failed: HTTP ${response.status}`);
  }
  return response.json() as Promise<T>;
}
export function post<T>(path: string, body?: unknown): Promise<T> {
  return api<T>(path, {
    method: "POST",
    ...(body === undefined
      ? {}
      : {
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        }),
  });
}
export const time = (value?: string) =>
  value
    ? new Date(value).toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      })
    : "—";
export const label = (value: string) =>
  value
    .toLowerCase()
    .replaceAll("_", " ")
    .replace(/\b\w/g, (character) => character.toUpperCase());
export const shortId = (value: string) => value.slice(0, 8).toUpperCase();
export const isFailure = (event: { event_type: string; result?: string }) =>
  /fail|denied|unauthorized/.test(event.event_type.toLowerCase()) ||
  /fail|denied|reject/.test((event.result || "").toLowerCase());
export function safeJson(value: unknown): string {
  return (
    JSON.stringify(
      value,
      (key, item) =>
        /^(token|password|demo_code)$/i.test(key) ? "[redacted]" : item,
      2,
    ) ?? "No result"
  );
}
