import { useState } from "react";
import type { Agent, Integration, Whoami } from "../lib/api";
import { AddDeviceModal } from "./AddDeviceModal";
import { AgentsTable } from "./AgentsTable";
import { Button } from "./Button";
import { Main } from "./Main";
import { PageTitle } from "./PageTitle";

export function DevicesPage({
  agents,
  integrations,
  whoami,
  onSelect,
}: {
  agents: Agent[];
  integrations: Integration[];
  whoami: Whoami | null;
  onSelect: (ip: string) => void;
}) {
  const [showAdd, setShowAdd] = useState(false);
  return (
    <Main>
      <PageTitle
        trail={[{ label: "Devices" }]}
        actions={
          <Button variant="normal" size="sm" onClick={() => setShowAdd(true)}>
            Add device
          </Button>
        }
      />
      <section className="bg-canvas border-1.5 border-navy overflow-hidden">
        <div className="overflow-x-auto">
          <AgentsTable agents={agents} integrations={integrations} onSelect={onSelect} />
        </div>
      </section>
      {showAdd && (
        <AddDeviceModal publicURL={whoami?.public_url} onClose={() => setShowAdd(false)} />
      )}
    </Main>
  );
}
