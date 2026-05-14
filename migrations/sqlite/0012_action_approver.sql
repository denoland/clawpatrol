-- Carry the deciding approver's identity on each action row + collapse
-- the legacy `hitl_*` action labels to `approved` / `denied`. The
-- previous shape conflated llm-approver and human-approver decisions
-- under a single "hitl_" prefix; the dashboard now surfaces the
-- approver kind / id explicitly so operators see at a glance why
-- something was denied (rule, llm, human).

ALTER TABLE actions ADD COLUMN approver      TEXT;
ALTER TABLE actions ADD COLUMN approver_type TEXT;
ALTER TABLE actions ADD COLUMN approver_by   TEXT;

UPDATE actions SET action = 'denied'   WHERE action = 'hitl_deny';
UPDATE actions SET action = 'approved' WHERE action = 'hitl_allow';

INSERT INTO _schema (version) VALUES (12);
