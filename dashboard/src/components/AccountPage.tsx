import { logout, type Whoami } from "../lib/api";
import { Button } from "./Button";
import { Main } from "./Main";
import { PageTitle } from "./PageTitle";

// AccountPage shows the currently authenticated principal (moved
// here from the global Header) and the only account-level action
// the dashboard supports: logging out.
export function AccountPage({ whoami }: { whoami: Whoami | null }) {
  return (
    <Main>
      <PageTitle trail={[{ label: "Account" }]} />
      <section className="bg-canvas border-1.5 border-navy p-4 space-y-4">
        {whoami?.user ? <Identity whoami={whoami} /> : <NotLoggedIn />}
      </section>
    </Main>
  );
}

function Identity({ whoami }: { whoami: Whoami }) {
  const method =
    whoami.auth_method === "password"
      ? "password"
      : whoami.auth_method === "tailscale"
        ? "tailscale"
        : null;
  return (
    <div className="flex flex-wrap items-center justify-between gap-3">
      <p className="text-sm text-text">
        Logged in as <span className="font-bold">{whoami.user}</span>
        {method && (
          <>
            {" "}
            via <span className="font-bold">{method}</span>
          </>
        )}
        .
      </p>
      <LogoutControl whoami={whoami} />
    </div>
  );
}

function NotLoggedIn() {
  return <p className="text-sm text-text-muted">Not logged in.</p>;
}

// LogoutControl is enabled only when the active session is one the
// gateway can revoke — i.e. password auth. Tailnet allowlist hits
// have no server-side session to clear (the operator's tailnet
// identity is what's letting them in), so the button stays visible
// but disabled with a tooltip explaining why.
function LogoutControl({ whoami }: { whoami: Whoami }) {
  const method = whoami.auth_method;
  const enabled = method === "password";
  const title = enabled
    ? "Log out"
    : method === "tailscale"
      ? "Tailnet auth — disconnect from tailscale to revoke access"
      : "Log out";
  const handle = async () => {
    if (!enabled) return;
    try {
      await logout();
    } finally {
      // Even on a network error we reload — the cookie may have
      // been cleared client-side, in which case the gate will
      // redirect to /__login on the next request.
      window.location.href = "/__login";
    }
  };
  return (
    <Button
      size="sm"
      onClick={handle}
      disabled={!enabled}
      title={title}
      aria-label={enabled ? "Log out" : "Log out (disabled — tailnet auth)"}
    >
      Log out
    </Button>
  );
}
