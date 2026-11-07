//! `{{ harar://key }}` placeholders in config templates.

use crate::dotenv;
use anyhow::{Result, anyhow};

/// The vault keys a template refers to, in order of first use.
pub fn references(template: &str) -> Result<Vec<String>> {
    let mut keys = Vec::new();
    for part in placeholders(template)? {
        if let Part::Reference(key) = part
            && !keys.iter().any(|k| k == key)
        {
            keys.push(key.to_string());
        }
    }
    Ok(keys)
}

/// Fills every placeholder with `lookup(key)`.
pub fn fill(template: &str, lookup: impl Fn(&str) -> Option<String>) -> Result<String> {
    let mut out = String::with_capacity(template.len());
    for part in placeholders(template)? {
        match part {
            Part::Text(text) => out.push_str(text),
            Part::Reference(key) => {
                out.push_str(&lookup(key).ok_or_else(|| anyhow!("no value for harar://{key}"))?)
            }
        }
    }
    Ok(out)
}

enum Part<'a> {
    Text(&'a str),
    Reference(&'a str),
}

fn placeholders(template: &str) -> Result<Vec<Part<'_>>> {
    let mut parts = Vec::new();
    let mut rest = template;
    let mut line = 1;
    while let Some(open) = rest.find("{{") {
        let (text, after) = rest.split_at(open);
        let Some(close) = after.find("}}") else {
            return Err(anyhow!("line {}: `{{{{` is never closed", line + text.matches('\n').count()));
        };
        let inner = after[2..close].trim();
        line += text.matches('\n').count();
        let key = dotenv::reference(inner)
            .ok_or_else(|| anyhow!("line {line}: `{{{{ {inner} }}}}` is not a harar:// reference"))?;
        parts.push(Part::Text(text));
        parts.push(Part::Reference(key));
        line += after[..close + 2].matches('\n').count();
        rest = &after[close + 2..];
    }
    parts.push(Part::Text(rest));
    Ok(parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup(key: &str) -> Option<String> {
        match key {
            "dev/cf/token" => Some("cf-123".into()),
            "dev/cf/account" => Some("acct".into()),
            _ => None,
        }
    }

    #[test]
    fn fills_placeholders_and_keeps_everything_else() {
        let template = "account_id = \"{{harar://dev/cf/account}}\"\ntoken = \"{{ harar://dev/cf/token }}\" # {{ harar://dev/cf/token }}\n";
        assert_eq!(
            fill(template, lookup).unwrap(),
            "account_id = \"acct\"\ntoken = \"cf-123\" # cf-123\n"
        );
        assert_eq!(references(template).unwrap(), vec!["dev/cf/account", "dev/cf/token"]);
    }

    #[test]
    fn unknown_or_malformed_placeholders_are_errors() {
        assert!(fill("{{ harar://dev/missing }}", lookup).unwrap_err().to_string().contains("dev/missing"));
        assert!(fill("a\nb {{ $HOME }}", lookup).unwrap_err().to_string().starts_with("line 2:"));
        assert!(fill("a {{ harar://dev/cf/token", lookup).is_err());
    }

    #[test]
    fn text_without_placeholders_is_unchanged() {
        assert_eq!(fill("plain { braces }\n", lookup).unwrap(), "plain { braces }\n");
    }
}
