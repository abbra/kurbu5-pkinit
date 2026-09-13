//! Desktop-notification prompter: presents the trust decision as an
//! actionable notification with a button per [`GRANT_PRESETS`] duration plus
//! an explicit deny button.
//!
//! This targets `org.freedesktop.Notifications` rather than a dedicated GUI
//! toolkit or an XDG desktop portal: essentially every Linux desktop
//! environment ships a notification daemon that implements it (GNOME, KDE
//! Plasma, XFCE, MATE, Cinnamon, LXQt, sway/wlroots via mako or dunst, ...),
//! whereas portal *backends* for interactive dialogs are not universally
//! deployed. No GUI toolkit dependency is pulled into the daemon.
//!
//! Some notification daemons render only the first couple of actions as
//! inline buttons and hide the rest behind an expand affordance (or, rarely,
//! ignore actions entirely). The full set of choices is always spelled out
//! in the notification body so the user isn't stuck with just what's
//! visible; `--ui tty` remains available for environments where this isn't
//! acceptable.

use notify_rust::{Notification, Urgency};

use pkinit_trust_brokerd::store::{GRANT_PRESETS, GrantTtl, Prompter, TrustRequest};

const DENY_ACTION: &str = "deny";

/// Prompts via a desktop notification. Falls back to `fallback` when no
/// notification daemon is reachable, or the reachable one can't render
/// actions (so a silent, un-actionable notification would otherwise strand
/// the request until the client-side timeout).
pub struct NotifyPrompter {
    pub fallback: Box<dyn Prompter>,
}

impl Prompter for NotifyPrompter {
    fn confirm(&self, req: &TrustRequest<'_>) -> Option<GrantTtl> {
        match self.ask(req) {
            Ok(grant) => grant,
            Err(e) => {
                eprintln!(
                    "[broker] desktop notification unavailable ({e}); falling back to terminal prompt"
                );
                self.fallback.confirm(req)
            }
        }
    }
}

impl NotifyPrompter {
    fn ask(&self, req: &TrustRequest<'_>) -> notify_rust::error::Result<Option<GrantTtl>> {
        let caps = notify_rust::get_capabilities()?;
        if !caps.iter().any(|c| c == "actions") {
            return Err("notification server does not support actions".into());
        }

        let choices = GRANT_PRESETS
            .iter()
            .map(|(label, _)| format!("  \u{2022} {label}"))
            .collect::<Vec<_>>()
            .join("\n");
        let body = format!(
            "KDC principal: {}\nCA subject: {}\nSHA-256: {}\n\n\
             This certificate authority is not yet trusted for this realm. \
             Choose how long to trust it:\n{choices}",
            req.kdc_principal, req.ca_subject, req.fingerprint,
        );

        let mut notification = Notification::new();
        notification
            .appname("pkinit-trust-brokerd")
            .summary(&format!(
                "Trust new certificate authority for {}?",
                req.realm
            ))
            .body(&body)
            .icon("dialog-password")
            .urgency(Urgency::Critical)
            .timeout(Timeout::Never);
        for (i, (label, _)) in GRANT_PRESETS.iter().enumerate() {
            notification.action(&format!("grant-{i}"), label);
        }
        notification.action(DENY_ACTION, "Deny");

        let handle = notification.show()?;
        let mut decision = None;
        handle.wait_for_action(|action| {
            if let Some(idx) = action
                .strip_prefix("grant-")
                .and_then(|s| s.parse::<usize>().ok())
            {
                decision = GRANT_PRESETS.get(idx).map(|(_, ttl)| *ttl);
            }
            // Any other action (the explicit "deny", the notification being
            // closed, an unrecognized id) leaves `decision` as `None`, i.e.
            // fails closed.
        });
        Ok(decision)
    }
}
