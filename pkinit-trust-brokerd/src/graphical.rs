//! Desktop-notification prompter: presents the trust decision as an
//! actionable notification with a small, fixed set of buttons.
//!
//! This targets `org.freedesktop.Notifications` rather than a dedicated GUI
//! toolkit or an XDG desktop portal: essentially every Linux desktop
//! environment ships a notification daemon that implements it (GNOME, KDE
//! Plasma, XFCE, MATE, Cinnamon, LXQt, sway/wlroots via mako or dunst, ...).
//! The XDG desktop portal `Access` dialog was considered instead (it can
//! show an unbounded list of choices in a combo box rather than one button
//! per choice), but isn't reliably there either — e.g. it's absent from
//! GNOME's own portal backend (`xdg-desktop-portal-gnome`) as of this
//! writing, verified against a real GNOME session, not just documentation.
//! No GUI toolkit dependency is pulled into the daemon either way.
//!
//! Notification *actions* (buttons) are a much more fragile UI surface than
//! that combo box would have been: the notification daemon/shell decides
//! how many to actually render, with no capability query to ask in advance,
//! and at least GNOME Shell silently drops whichever don't fit rather than
//! ever exposing them — there is no "..." or scroll affordance. Registering
//! one button per [`GRANT_PRESETS`] entry plus Deny (six actions) meant that
//! on a shell rendering only three, users saw 15 minutes / 1 hour / 1 day
//! and never Deny at all, which is a worse failure mode than not offering
//! every duration: a security prompt must never make "reject" the one
//! option that silently disappears. So [`GUI_CHOICES`] is a short, fixed
//! list — Deny first, so it's the one guaranteed to survive truncation in
//! an even more constrained environment than the one this was checked
//! against. Finer-grained duration control (15 minutes, 1 day, 1 week)
//! remains available via `--ui tty` or the client's own terminal.
//!
//! The body text has the same problem one level down: a banner notification
//! shows only the first few lines of it before cutting off, silently, with
//! no "..." either — so it carries just the two lines a person actually
//! needs to decide (the CA's subject and fingerprint), not the KDC
//! principal, an explanatory sentence, or the full duration list, all of
//! which used to push the fingerprint itself half out of view.

use std::time::Duration;

use notify_rust::{Notification, Urgency};

use pkinit_trust_brokerd::store::{GrantTtl, PROMPT_TIMEOUT, Prompter, TrustRequest};

const DENY_ACTION: &str = "deny";

/// Notification action buttons, in registration order (see module docs for
/// why this is short and Deny-first rather than one button per
/// [`GRANT_PRESETS`] entry).
const GUI_CHOICES: &[(&str, &str, GrantTtl)] = &[
    (
        "grant-1h",
        "Trust 1 hour",
        GrantTtl::For(Duration::from_secs(60 * 60)),
    ),
    ("grant-forever", "Trust always", GrantTtl::Forever),
];

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

/// Escapes the subset of markup some `org.freedesktop.Notifications` servers
/// interpret in notification body/summary text. `req.ca_subject`/`req.realm`
/// come from the unauthenticated KDC side of a TOFU exchange, so a malicious
/// KDC could otherwise inject e.g. `<a href=...>` into the trust prompt.
fn escape_markup(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

impl NotifyPrompter {
    fn ask(&self, req: &TrustRequest<'_>) -> notify_rust::error::Result<Option<GrantTtl>> {
        let caps = notify_rust::get_capabilities()?;
        if !caps.iter().any(|c| c == "actions") {
            return Err("notification server does not support actions".into());
        }

        let body = format!(
            "{}\nSHA-256: {}",
            escape_markup(req.ca_subject),
            req.fingerprint
        );

        let mut notification = Notification::new();
        notification
            .appname("pkinit-trust-brokerd")
            .summary(&format!(
                "Trust new certificate authority for {}?",
                escape_markup(req.realm)
            ))
            .body(&body)
            .icon("dialog-password")
            .urgency(Urgency::Critical)
            .timeout(PROMPT_TIMEOUT);
        // Deny first: the one action guaranteed to survive truncation on a
        // notification UI that renders only some of what we register (see
        // module docs) must be the one that fails closed, not a grant.
        notification.action(DENY_ACTION, "Deny");
        for (id, label, _) in GUI_CHOICES {
            notification.action(id, label);
        }

        let handle = notification.show()?;
        let mut decision = None;
        handle.wait_for_action(|action| {
            if let Some((_, _, ttl)) = GUI_CHOICES.iter().find(|(id, _, _)| *id == action) {
                decision = Some(*ttl);
            }
            // Any other action (the explicit "deny", the notification being
            // closed, an unrecognized id) leaves `decision` as `None`, i.e.
            // fails closed.
        });
        Ok(decision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_markup_escapes_html_entities() {
        // `&` must be escaped first so the entities it introduces
        // (`&lt;`/`&gt;`) aren't themselves re-escaped afterwards.
        assert_eq!(
            escape_markup("<a href=\"x\">&amp;</a>"),
            "&lt;a href=\"x\"&gt;&amp;amp;&lt;/a&gt;"
        );
    }
}
