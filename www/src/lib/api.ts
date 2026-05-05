// Profile is per-device, not per-dashboard. The OAuth connect flow
// picks which profile a credential lands under via an explicit query
// param on /api/oauth/start; everything else is single-tenant.
const api = fetch;

export type Owner = {
  owner: string;
  connected: boolean;
  expires_at?: number;
  display_name?: string;
  avatar_url?: string;
};

export type SecretSlot = {
  name: string;
  label: string;
  multiline?: boolean;
  description?: string;
};

export type Integration = {
  id: string;
  name: string;
  type: string; // credential plugin type (e.g. "postgres_credential")
  has_oauth: boolean;
  slots?: SecretSlot[] | null;
  owners: Owner[] | null;
};

export async function setCredentialSlots(
  id: string,
  owner: string,
  slots: Record<string, string>,
): Promise<void> {
  const r = await fetch("/api/credentials/set", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ id, owner, slots }),
  });
  if (!r.ok) throw new Error(await r.text());
}

export async function clearCredential(id: string, owner: string): Promise<void> {
  const r = await fetch("/api/credentials/clear", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ id, owner }),
  });
  if (!r.ok) throw new Error(await r.text());
}

export type Session = {
  id: string;
  title?: string;
  type: string;
  model?: string;
  tokens_in?: number;
  tokens_out?: number;
  ctx_used?: number;
  ctx_max?: number;
  first_at: string;
  last_at: string;
  reqs: number;
  activity?: number[];
};

export type Agent = {
  ip: string;
  external_ipv4?: string;
  external_ipv6?: string;
  hostname: string;
  user: string;
  profile?: string;
  os: string;
  ua?: string;
  first_at: string;
  last_at: string;
  reqs: number;
  bytes_in: number;
  bytes_out: number;
  last_host: string;
  activity?: number[];
  integrations?: string[];
  sessions?: Session[];
};

export type RuleSummary = {
  // Rule's bare-name identifier (declared in HCL as
  // `rule "<type>" "<name>"`). Unique across the file.
  name: string;
  // "https" | "sql" | "k8s" — protocol family the rule's match
  // facets apply to. Determines which fields appear in `match`.
  family: string;
  // Endpoint this rule attaches to. Multi-endpoint rules emit one
  // RuleSummary per attachment site.
  endpoint: string;
  // Profile that includes the endpoint. Empty when the row came
  // back from a non-profile-scoped query.
  profile?: string;
  // Priority — higher wins. Negative values are catch-alls;
  // priority 0 is the default declaration-order tier.
  priority?: number;
  disabled?: boolean;
  // verdict: "allow" | "deny". Empty when approve = [...] is the
  // outcome instead.
  verdict?: string;
  reason?: string;
  // Approve chain stages. Each stage names an approver (LLM or
  // human); some stages additionally bind a policy + cache_ttl.
  approve?: Array<{
    name: string;
    policy?: string;
    cache_ttl?: number;
  }>;
  // Match facet map. Keys vary by family — http rules have
  // method / path / headers; sql rules have verb / tables / function;
  // k8s rules have resource / verb / namespace / name. Values are
  // either a string or a list of strings; "!prefix" entries negate.
  match?: Record<string, unknown>;
};

export async function getRules(): Promise<RuleSummary[]> {
  const r = await api("/api/rules");
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

// Rules API speaks JSON on the wire. The editor pretty-prints the
// rules array so an operator can see/edit each rule's fields directly.
// (HCL is the on-disk format; JSON is just the dashboard transport.)

export async function getRulesJSON(): Promise<string> {
  const r = await api("/api/rules");
  if (!r.ok) throw new Error(await r.text());
  const data = await r.json();
  return JSON.stringify(data ?? [], null, 2);
}

export async function putRulesJSON(json: string): Promise<{ ok: boolean; count: number }> {
  const r = await api("/api/rules", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: json,
  });
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

// HCL editor. /api/config returns the full gateway.hcl as raw text.

export async function getConfigHCL(): Promise<string> {
  const r = await api("/api/config");
  if (!r.ok) throw new Error(await r.text());
  return r.text();
}

export async function putConfigHCL(hcl: string): Promise<{ ok: boolean; bytes: number }> {
  const r = await api("/api/config", {
    method: "PUT",
    headers: { "Content-Type": "text/plain" },
    body: hcl,
  });
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

export async function getDeviceRulesHCL(ip: string): Promise<string> {
  const r = await api(`/api/rules/device?ip=${encodeURIComponent(ip)}&format=hcl`);
  if (!r.ok) throw new Error(await r.text());
  return r.text();
}

export async function listProfiles(): Promise<string[]> {
  const r = await api("/api/profiles");
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

export async function setDeviceProfile(ip: string, profile: string): Promise<void> {
  const r = await api(`/api/agents/profile?ip=${encodeURIComponent(ip)}&profile=${encodeURIComponent(profile)}`, {
    method: "POST",
  });
  if (!r.ok) throw new Error(await r.text());
}

export type HITLPending = {
  id: string;
  agent_ip: string;
  host: string;
  method: string;
  path: string;
  ua?: string;
  body_sample?: string;
  reason?: string;
  created_at: string;
  expires_at: string;
};

export async function getHITLPending(): Promise<HITLPending[]> {
  const r = await api("/api/hitl/pending");
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

export async function decideHITL(id: string, allow: boolean): Promise<void> {
  const r = await api("/api/hitl/decide", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ id, allow }),
  });
  if (!r.ok) throw new Error(await r.text());
}

export async function aiEditRules(
  prompt: string,
  currentYAML: string,
  scope: "global" | "device",
  agent?: string,
): Promise<{ yaml: string; refused?: string }> {
  const r = await api("/api/rules/ai", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ prompt, current_yaml: currentYAML, scope, agent: agent ?? "" }),
  });
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

export type Whoami = {
  user: string;
  device: string;
  host: string;
  public_url?: string;
};

export async function getStatus(profile?: string): Promise<Integration[]> {
  const url = profile ? `/api/status?profile=${encodeURIComponent(profile)}` : "/api/status";
  const r = await api(url);
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

export async function deleteAgent(ip: string): Promise<void> {
  const r = await api(`/api/agents/delete?ip=${encodeURIComponent(ip)}`, { method: "POST" });
  if (!r.ok) throw new Error(await r.text());
}

export async function getAgents(): Promise<Agent[]> {
  const r = await api("/api/agents");
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

export async function getWhoami(): Promise<Whoami> {
  const r = await api("/api/whoami");
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

export type OAuthStartResp =
  | { flow?: "auth_code"; auth_url: string; state: string; owner: string }
  | { flow: "device"; user_code: string; verification_uri: string; state: string; owner: string; interval: number; expires_in: number };

export async function oauthStart(id: string, profile?: string): Promise<OAuthStartResp> {
  const qs = `id=${encodeURIComponent(id)}` + (profile ? `&profile=${encodeURIComponent(profile)}` : "");
  const r = await api(`/api/oauth/start?${qs}`, { method: "POST" });
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

export async function oauthDevicePoll(state: string): Promise<{ connected?: boolean; owner?: string; error?: string; detail?: string; interval?: number }> {
  const r = await api(`/api/oauth/device-poll?state=${encodeURIComponent(state)}`, { method: "POST" });
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

export async function oauthRevoke(id: string, owner: string): Promise<void> {
  const r = await api("/api/oauth/revoke", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ id, owner }),
  });
  if (!r.ok) throw new Error(await r.text());
}

export async function oauthExchange(state: string, code: string): Promise<{ connected: boolean; owner: string; expires: number }> {
  const r = await api("/api/oauth/exchange", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ state, code }),
  });
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}
