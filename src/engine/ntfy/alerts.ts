import * as db from "../../shared/db.ts";
import { ntfyApp, ntfyUrl, ntfySettings, ntfyPreferences, ntfyCredentials, canReceiveNtfy, credentialSecret, getAppNtfy } from "../../shared/ntfy.ts";
export function enqueueNtfyIncident(incident: { key: string; incident_id: string; title: string; path: string }, recovered: boolean, now: number): void {
  const settings = ntfySettings();
  if (!settings?.enabled || !settings.alerts) return;
  for (const user of db.getUsers()) {
    if (!canReceiveNtfy(user.id, incident.key, recovered)) continue;
    const id = `${incident.incident_id}:${recovered ? "recovery" : "open"}:${user.id}`;
    db.default.query(`INSERT OR IGNORE INTO ntfy_outbox (id,user_id,incident_key,recovered,title,message,path,created_at,next_attempt) VALUES (?,?,?,?,?,?,?,?,?)`)
      .run(id, user.id, incident.key, Number(recovered), `[OCD] ${recovered ? "Recovered: " : ""}${incident.title}`, recovered ? "This condition has cleared." : "This condition needs attention. Open OCD to inspect details.", `/incidents/${incident.incident_id}`, now, now);
  }
}
export function enqueueNtfyTest(userId: string): string {
  const now = Date.now();
  const id = `test:${crypto.randomUUID()}`;
  db.default.query(`INSERT INTO ntfy_outbox (id,user_id,incident_key,recovered,title,message,path,created_at,next_attempt) VALUES (?,?,'test',0,'[OCD] Test notification','Your OCD notifications are configured.','/account',?,?)`).run(id, userId, now, now);
  return id;
}
type RelayedMessage = { id: string; time: number; event: string; title?: string; message?: string; tags?: string[]; priority?: number; click?: string };

/** Forwards new messages from app topics to the users who subscribed to that app in Account → Notifications.
 *  Each topic keeps a cursor, so users only receive messages published after the panel started following it. */
export async function relayAppNtfy(fetcher: typeof fetch = fetch, now = Date.now()): Promise<void> {
  const settings = ntfySettings();
  if (!settings?.enabled || !settings.alerts || !settings.apps || ntfyApp()?.status !== "running") return;
  const subscribers = new Map<number, string[]>();
  for (const user of db.getUsers()) {
    const prefs = ntfyPreferences(user.id);
    if (!prefs.enabled) continue;
    for (const appId of prefs.apps) subscribers.set(appId, [...subscribers.get(appId) ?? [], user.id]);
  }
  const credentials = ntfyCredentials();
  const publisher = credentials.find(c => c.owner_type === "system");
  if (!publisher || !subscribers.size) return;
  const token = (await credentialSecret(publisher)).token;
  for (const [appId, userIds] of subscribers) {
    const app = db.getApp(appId);
    if (!app) continue;
    const bindings = getAppNtfy(appId);
    const topics = credentials.filter(c => c.owner_type === "app" && c.owner_id === String(appId)
      && bindings[c.binding]?.generation === c.generation && bindings[c.binding]!.permissions.includes("publish"));
    for (const topic of topics) {
      const cursorKey = `ntfy_relay.${topic.id}`;
      const cursor = db.getSettings()[cursorKey];
      if (!cursor) { db.saveSetting(cursorKey, String(Math.floor(now / 1000))); continue; }
      let response: Response;
      try {
        response = await fetcher(`${ntfyUrl()}/${topic.topic}/json?poll=1&since=${encodeURIComponent(cursor)}`, {
          redirect: "error", signal: AbortSignal.timeout(10_000), headers: { authorization: `Bearer ${token}` },
        });
      } catch { continue; }
      if (!response.ok) continue;
      const messages = (await response.text()).split("\n").filter(Boolean)
        .map(line => JSON.parse(line) as RelayedMessage).filter(m => m.event === "message");
      if (!messages.length) continue;
      db.default.transaction(() => {
        for (const m of messages) for (const userId of userIds) {
          // The key carries the app's priority and tags; delivery restores them.
          const key = `relay:${appId}:${m.priority ?? 3}:${(m.tags ?? []).join(",")}`;
          db.default.query(`INSERT OR IGNORE INTO ntfy_outbox (id,user_id,incident_key,recovered,title,message,path,created_at,next_attempt) VALUES (?,?,?,0,?,?,?,?,?)`)
            .run(`relay:${m.id}:${userId}`, userId, key, m.title || app.name, m.message || "", m.click || "", now, now);
        }
        db.saveSetting(cursorKey, messages.at(-1)!.id);
      })();
    }
  }
}

type Delivery = { id: string; user_id: string; incident_key: string; recovered: number; title: string; message: string; path: string; attempts: number };
export async function deliverNtfy(fetcher: typeof fetch = fetch, now = Date.now()): Promise<void> {
  const settings = ntfySettings();
  if (!settings?.enabled || !settings.alerts || ntfyApp()?.status !== "running") return;
  const credentials = ntfyCredentials();
  const publisher = credentials.find(c => c.owner_type === "system");
  if (!publisher) return;
  const token = (await credentialSecret(publisher)).token;
  const pending = db.default.query("SELECT * FROM ntfy_outbox WHERE sent_at IS NULL AND attempts<12 AND next_attempt<=? ORDER BY created_at LIMIT 10").all(now) as Delivery[];
  for (const item of pending) {
    const allowed = item.incident_key === "test"
      ? !!db.getUserById(item.user_id) && ntfyPreferences(item.user_id).enabled
      : canReceiveNtfy(item.user_id, item.incident_key, !!item.recovered);
    if (!allowed) { db.default.query("DELETE FROM ntfy_outbox WHERE id=?").run(item.id); continue; }
    const recipient = credentials.find(c => c.owner_type === "user" && c.owner_id === item.user_id);
    if (!recipient) continue;
    try {
      const panel = db.getPanel();
      const relayed = item.incident_key.startsWith("relay:") ? item.incident_key.split(":") : null;
      const extras = relayed
        ? { tags: relayed[3] ? relayed[3].split(",") : [], priority: Number(relayed[2]) || 3, ...(item.path ? { click: item.path } : {}) }
        : { tags: [item.recovered ? "white_check_mark" : "warning"], priority: item.recovered ? 3 : 4,
          ...(panel ? { click: `https://${panel.domain}/#${item.path}` } : {}) };
      const response = await fetcher(ntfyUrl(), {
        method: "POST", redirect: "error", signal: AbortSignal.timeout(10_000),
        headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
        body: JSON.stringify({ topic: recipient.topic, title: item.title, message: item.message, ...extras }),
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      db.default.query("UPDATE ntfy_outbox SET sent_at=?,error='' WHERE id=?").run(now, item.id);
    } catch {
      db.default.query("UPDATE ntfy_outbox SET attempts=attempts+1,next_attempt=?,error='ntfy delivery failed; check service connectivity' WHERE id=?")
        .run(now + Math.min(3600_000, 30_000 * 2 ** item.attempts), item.id);
    }
  }
  db.default.query("DELETE FROM ntfy_outbox WHERE created_at<?").run(now - 30 * 86400_000);
}
