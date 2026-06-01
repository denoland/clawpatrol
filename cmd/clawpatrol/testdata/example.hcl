// Sample config for `clawpatrol test` (see site/doc/clawpatrol-test.md). Pair
// with the *.json fixtures alongside it to verify the runner
// end-to-end:
//
//   ./clawpatrol test testdata/example.hcl testdata/
//
// Edit any rule below and re-run to see a mismatch.

gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"

  wireguard {
    subnet_cidr = "10.55.0.0/24"
  }
}

endpoint "https" "github" {
  hosts = ["api.github.com"]
}

credential "bearer_token" "github" {
  endpoint = https.github
}

rule "github-reads" {
  endpoint  = https.github
  condition = "http.method in ['GET', 'HEAD']"
  verdict   = "allow"
}

rule "github-writes" {
  endpoint  = https.github
  condition = "http.method in ['POST', 'PATCH', 'PUT', 'DELETE']"
  verdict   = "deny"
  reason    = "writes go through PR review"
}

endpoint "ssh" "build-host" {
  hosts = ["build.example.com:2222"]
}

credential "ssh_key" "build-host-key" {
  endpoint = ssh.build-host
}

// Block interactive shells but allow one-shot commands — the headline
// ssh use case. shell == interactive; exec == a command.
rule "ssh-no-interactive" {
  endpoint  = ssh.build-host
  condition = "ssh.verb == 'shell'"
  verdict   = "deny"
  reason    = "interactive sessions are not permitted; run a command instead"
}

rule "ssh-no-sftp" {
  endpoint  = ssh.build-host
  condition = "ssh.verb == 'subsystem' && ssh.subsystem == 'sftp'"
  verdict   = "deny"
  reason    = "file transfer is not permitted on the build host"
}

// Block git pushes (receive-pack) while leaving fetches (upload-pack)
// to the catch-all exec allow below. This blocks ALL pushes, not just
// force pushes — force-vs-normal isn't visible at the command level
// (see site/doc/rules.md, ssh family scope).
rule "ssh-no-push" {
  endpoint  = ssh.build-host
  condition = "ssh.verb == 'exec' && ssh.command.startsWith('git-receive-pack')"
  verdict   = "deny"
  reason    = "pushes go through CI, not direct git"
}

rule "ssh-no-db-forward" {
  endpoint  = ssh.build-host
  condition = "ssh.verb == 'forward' && ssh.forward_port == 5432"
  verdict   = "deny"
  reason    = "no direct database tunnels"
}

// Catch-all for commands not otherwise denied. Lower priority so the
// deny rules above win when they match.
rule "ssh-exec-allowed" {
  endpoint  = ssh.build-host
  priority  = -10
  condition = "ssh.verb == 'exec'"
  verdict   = "allow"
}

profile "default" {
  credentials = [bearer_token.github, ssh_key.build-host-key]
}
