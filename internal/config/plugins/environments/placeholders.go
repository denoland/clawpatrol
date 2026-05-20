package environments

// Per-provider env-var placeholders. Identical to the constants in
// internal/config/plugins/credentials/util.go; duplicated here to
// keep the environments package self-contained without re-exporting
// internal package symbols (the credentials package's `phClaude`
// etc. are package-private). When the legacy EnvVars() methods on
// the credential side are removed, those constants will move here
// for good.
const (
	phClaude  = "sk-ant-oat01-clawpatrol-placeholder-do-not-use"
	phOpenAI  = "sk-clawpatrol-placeholder-do-not-use"
	phGitHub  = "ghp_clawpatrol_placeholder_do_not_use"
	phGemini  = "AIzaClawpatrolPlaceholderDoNotUse00000000"
	phDiscord = "MTAwMDAwMDAwMDAwMDAwMDAwMA.clawpatrol-placeholder-do-not-use.xxxxxxxxxxxxxxxxxxxxxxxxxxx"
)
