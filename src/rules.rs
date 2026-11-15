//! Built-in detection rules.
//!
//! Every rule is a single regex. `group` selects which capture group holds the
//! secret itself (0 = the whole match). Rules marked `generic` match on context
//! (a suspicious variable name) rather than on a recognisable token format, so
//! they additionally go through an entropy gate and a placeholder filter, and
//! they give way to any specific rule that matches the same bytes.

#[derive(Debug)]
pub struct Rule {
    pub id: &'static str,
    pub description: &'static str,
    pub pattern: &'static str,
    pub group: usize,
    pub min_entropy: Option<f64>,
    pub generic: bool,
}

const fn specific(id: &'static str, description: &'static str, pattern: &'static str) -> Rule {
    Rule { id, description, pattern, group: 0, min_entropy: None, generic: false }
}

const fn generic(
    id: &'static str,
    description: &'static str,
    pattern: &'static str,
    min_entropy: f64,
) -> Rule {
    Rule { id, description, pattern, group: 1, min_entropy: Some(min_entropy), generic: true }
}

pub const RULES: &[Rule] = &[
    specific(
        "aws-access-key-id",
        "AWS access key ID",
        r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b",
    ),
    Rule {
        id: "aws-secret-access-key",
        description: "AWS secret access key",
        pattern: r#"(?i)aws.{0,20}?(?:secret|sk).{0,20}?["']([A-Za-z0-9/+=]{40})["']"#,
        group: 1,
        min_entropy: Some(3.8),
        generic: false,
    },
    specific(
        "github-token",
        "GitHub token",
        r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b",
    ),
    specific(
        "github-fine-grained-pat",
        "GitHub fine-grained personal access token",
        r"\bgithub_pat_[A-Za-z0-9_]{82}\b",
    ),
    specific(
        "gitlab-pat",
        "GitLab personal access token",
        r"\bglpat-[A-Za-z0-9_\-]{20,}\b",
    ),
    specific(
        "slack-token",
        "Slack token",
        r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
    ),
    specific(
        "slack-webhook",
        "Slack incoming webhook URL",
        r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+",
    ),
    specific(
        "discord-bot-token",
        "Discord bot token",
        r"\b[MNO][A-Za-z\d_-]{23,25}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,}\b",
    ),
    specific(
        "discord-webhook",
        "Discord webhook URL",
        r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+",
    ),
    specific(
        "stripe-live-key",
        "Stripe live secret key",
        r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b",
    ),
    specific(
        "google-api-key",
        "Google API key",
        r"\bAIza[0-9A-Za-z_\-]{35}\b",
    ),
    specific(
        "anthropic-api-key",
        "Anthropic API key",
        r"\bsk-ant-[A-Za-z0-9_\-]{80,}\b",
    ),
    specific(
        "openai-api-key",
        "OpenAI API key",
        r"\bsk-(?:(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}|[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})\b",
    ),
    specific(
        "npm-token",
        "npm access token",
        r"\bnpm_[A-Za-z0-9]{36}\b",
    ),
    specific(
        "sendgrid-api-key",
        "SendGrid API key",
        r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b",
    ),
    specific(
        "telegram-bot-token",
        "Telegram bot token",
        r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b",
    ),
    specific(
        "twilio-api-key",
        "Twilio API key",
        r"\bSK[0-9a-f]{32}\b",
    ),
    specific(
        "jwt",
        "JSON Web Token",
        r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
    ),
    specific(
        "private-key",
        "Private key block",
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----",
    ),
    generic(
        "database-url-password",
        "Password embedded in a database connection URL",
        r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqps?)://[^:@\s/]*:([^@\s/]{3,})@[^\s/]",
        3.0,
    ),
    generic(
        "generic-secret-assignment",
        "High-entropy string assigned to a secret-looking name",
        r#"(?i)(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|auth[_-]?key|private[_-]?key)[a-z0-9_]*["']?\s*(?:=>|:=|:|=)\s*["']([^"'\s]{12,120})["']"#,
        3.5,
    ),
    generic(
        "generic-env-secret",
        "High-entropy value in a secret-looking environment variable",
        r"(?m)^\s*(?:export\s+)?[A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY)[A-Z0-9_]*\s*=\s*([A-Za-z0-9_\-+/=~!@%^&*]{12,120})\s*$",
        3.5,
    ),
];

/// Values that look like documentation or templating rather than a real secret.
pub fn is_placeholder(value: &str) -> bool {
    const MARKERS: &[&str] = &[
        "example", "changeme", "placeholder", "your_", "your-", "xxxx", "dummy", "redacted",
        "****", "<", "${", "{{", "todo",
    ];
    let lower = value.to_ascii_lowercase();
    if MARKERS.iter().any(|m| lower.contains(m)) {
        return true;
    }
    let mut chars = value.chars();
    match chars.next() {
        Some(first) => chars.all(|c| c == first),
        None => true,
    }
}
