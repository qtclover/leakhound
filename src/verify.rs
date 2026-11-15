//! Ask the issuing service whether a found credential still works.
//!
//! Each check is a single read-only request to an endpoint that only reports
//! who the caller is. Nothing is created, changed or sent anywhere other than
//! the service that issued the credential.

use crate::Finding;
use rayon::prelude::*;
use serde::Serialize;
use std::collections::HashMap;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// The service accepted the credential. Revoke it.
    Active,
    /// The service rejected the credential.
    Inactive,
    /// No clear answer: network error, rate limit, or an unexpected response.
    Unknown,
}

pub struct Check {
    pub method: &'static str,
    pub url: String,
    pub headers: Vec<(&'static str, String)>,
    /// Statuses that mean "we do not know this credential".
    pub inactive: &'static [u16],
    /// Non-2xx statuses that still prove the credential is live, such as a
    /// 403 for a valid key that lacks permission for this endpoint.
    pub also_active: &'static [u16],
    /// When set, a 2xx only counts if the body contains this text. For APIs
    /// that answer 200 to everything and report failure in the body.
    pub body_must_contain: Option<&'static str>,
}

impl Check {
    fn get(url: impl Into<String>) -> Self {
        Check {
            method: "GET",
            url: url.into(),
            headers: Vec::new(),
            inactive: &[401],
            also_active: &[],
            body_must_contain: None,
        }
    }

    fn header(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.headers.push((name, value.into()));
        self
    }

    fn bearer(self, secret: &str) -> Self {
        self.header("Authorization", format!("Bearer {secret}"))
    }
}

/// The check for a rule, or `None` if that kind of secret cannot be verified
/// with a harmless request.
pub fn check_for(rule: &str, secret: &str) -> Option<Check> {
    Some(match rule {
        "github-token" | "github-fine-grained-pat" => {
            Check::get("https://api.github.com/user").bearer(secret)
        }
        "gitlab-pat" => {
            Check::get("https://gitlab.com/api/v4/user").header("PRIVATE-TOKEN", secret)
        }
        "slack-token" => Check {
            method: "POST",
            body_must_contain: Some("\"ok\":true"),
            ..Check::get("https://slack.com/api/auth.test").bearer(secret)
        },
        "stripe-live-key" => Check {
            also_active: &[403],
            ..Check::get("https://api.stripe.com/v1/balance").bearer(secret)
        },
        "openai-api-key" => Check::get("https://api.openai.com/v1/models").bearer(secret),
        "anthropic-api-key" => Check::get("https://api.anthropic.com/v1/models")
            .header("x-api-key", secret)
            .header("anthropic-version", "2023-06-01"),
        "discord-bot-token" => Check::get("https://discord.com/api/v10/users/@me")
            .header("Authorization", format!("Bot {secret}")),
        "discord-webhook" => Check {
            inactive: &[401, 404],
            ..Check::get(secret)
        },
        "telegram-bot-token" => Check {
            inactive: &[401, 404],
            ..Check::get(format!("https://api.telegram.org/bot{secret}/getMe"))
        },
        "sendgrid-api-key" => Check::get("https://api.sendgrid.com/v3/scopes").bearer(secret),
        "npm-token" => Check::get("https://registry.npmjs.org/-/whoami").bearer(secret),
        _ => return None,
    })
}

/// Rule ids that `check_for` knows how to verify.
pub const VERIFIABLE: &[&str] = &[
    "github-token",
    "github-fine-grained-pat",
    "gitlab-pat",
    "slack-token",
    "stripe-live-key",
    "openai-api-key",
    "anthropic-api-key",
    "discord-bot-token",
    "discord-webhook",
    "telegram-bot-token",
    "sendgrid-api-key",
    "npm-token",
];

pub fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(10))
        .redirects(0)
        .user_agent(concat!("leakhound/", env!("CARGO_PKG_VERSION")))
        .build()
}

pub fn run(agent: &ureq::Agent, check: &Check) -> Status {
    let mut request = agent.request(check.method, &check.url);
    for (name, value) in &check.headers {
        request = request.set(name, value);
    }
    let (status, response) = match request.call() {
        Ok(response) => (response.status(), Some(response)),
        Err(ureq::Error::Status(code, _)) => (code, None),
        Err(ureq::Error::Transport(_)) => return Status::Unknown,
    };

    if (200..300).contains(&status) {
        let Some(needle) = check.body_must_contain else {
            return Status::Active;
        };
        let body = response
            .and_then(|r| r.into_string().ok())
            .unwrap_or_default();
        // Tolerate either spacing of `"ok": true`.
        let compact: String = body.chars().filter(|c| !c.is_whitespace()).collect();
        return if compact.contains(needle) {
            Status::Active
        } else {
            Status::Inactive
        };
    }
    if check.also_active.contains(&status) {
        Status::Active
    } else if check.inactive.contains(&status) {
        Status::Inactive
    } else {
        Status::Unknown
    }
}

/// Verify every finding that can be verified, once per distinct secret, and
/// return how many are active. Must run before secrets are redacted.
pub fn verify_findings(findings: &mut [Finding]) -> usize {
    let mut unique: HashMap<(String, String), Check> = HashMap::new();
    for f in findings.iter() {
        if let Some(check) = check_for(&f.rule, &f.secret) {
            unique.insert((f.rule.clone(), f.secret.clone()), check);
        }
    }
    let agent = agent();
    let results: HashMap<(String, String), Status> = unique
        .into_par_iter()
        .map(|(key, check)| (key, run(&agent, &check)))
        .collect();

    let mut active = 0;
    for f in findings.iter_mut() {
        f.verification = results.get(&(f.rule.clone(), f.secret.clone())).copied();
        if f.verification == Some(Status::Active) {
            active += 1;
        }
    }
    active
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;

    /// A one-shot HTTP server on localhost. Returns its URL and a channel that
    /// yields the raw request it received.
    fn serve(status_line: &str, body: &str) -> (String, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let response = format!(
            "HTTP/1.1 {status_line}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buf = [0u8; 1024];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = stream.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..n]);
            }
            stream.write_all(response.as_bytes()).unwrap();
            let _ = tx.send(String::from_utf8_lossy(&request).into_owned());
        });
        (url, rx)
    }

    fn status_for(status_line: &str, body: &str, check: impl Fn(String) -> Check) -> Status {
        let (url, _request) = serve(status_line, body);
        run(&agent(), &check(url))
    }

    #[test]
    fn accepted_credential_is_active() {
        assert_eq!(status_for("200 OK", "{}", Check::get), Status::Active);
    }

    #[test]
    fn rejected_credential_is_inactive() {
        assert_eq!(
            status_for("401 Unauthorized", "", Check::get),
            Status::Inactive
        );
    }

    #[test]
    fn rate_limits_and_server_errors_are_unknown() {
        assert_eq!(
            status_for("429 Too Many Requests", "", Check::get),
            Status::Unknown
        );
        assert_eq!(
            status_for("500 Internal Server Error", "", Check::get),
            Status::Unknown
        );
        assert_eq!(status_for("403 Forbidden", "", Check::get), Status::Unknown);
    }

    #[test]
    fn permission_error_can_count_as_active() {
        let check = |url| Check {
            also_active: &[403],
            ..Check::get(url)
        };
        assert_eq!(status_for("403 Forbidden", "", check), Status::Active);
    }

    #[test]
    fn body_decides_for_apis_that_always_answer_200() {
        let check = |url| Check {
            body_must_contain: Some("\"ok\":true"),
            ..Check::get(url)
        };
        assert_eq!(
            status_for("200 OK", r#"{"ok": true}"#, check),
            Status::Active
        );
        assert_eq!(
            status_for("200 OK", r#"{"ok":false,"error":"invalid_auth"}"#, check),
            Status::Inactive
        );
    }

    #[test]
    fn unreachable_service_is_unknown() {
        // Bind then drop, so the port is known to be closed.
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let check = Check::get(format!("http://127.0.0.1:{port}/"));
        assert_eq!(run(&agent(), &check), Status::Unknown);
    }

    #[test]
    fn credential_is_sent_in_the_expected_header() {
        let (url, request) = serve("200 OK", "{}");
        run(&agent(), &Check::get(url).bearer("s3cr3t-value"));
        let request = request.recv().unwrap();
        assert!(request.starts_with("GET / HTTP/1.1"));
        assert!(request.contains("Authorization: Bearer s3cr3t-value"));
        assert!(request.contains("leakhound/"));
    }

    #[test]
    fn verifiable_list_matches_real_rules_and_check_for() {
        let builtin = crate::rules::builtin();
        for id in VERIFIABLE {
            assert!(
                builtin.iter().any(|r| &r.id == id),
                "{id} is not a built-in rule"
            );
            assert!(check_for(id, "x").is_some(), "{id} has no check");
        }
        for rule in &builtin {
            assert_eq!(
                check_for(&rule.id, "x").is_some(),
                VERIFIABLE.contains(&rule.id.as_str()),
                "{} disagrees between check_for and VERIFIABLE",
                rule.id
            );
        }
    }

    #[test]
    fn every_check_goes_to_the_issuing_service_over_https() {
        for id in VERIFIABLE {
            if *id == "discord-webhook" {
                continue; // the secret is itself the URL
            }
            let check = check_for(id, "x").unwrap();
            assert!(check.url.starts_with("https://"), "{id}: {}", check.url);
        }
    }
}
