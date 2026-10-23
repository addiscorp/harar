//! `.env` files: read them, and rewrite their values as `harar://` references
//! while keeping every other line exactly as it was.

use anyhow::{Result, anyhow};

pub const REFERENCE_PREFIX: &str = "harar://";

/// The vault key a value refers to, if the whole value is a reference.
pub fn reference(value: &str) -> Option<&str> {
    value
        .strip_prefix(REFERENCE_PREFIX)
        .filter(|key| !key.is_empty() && !key.chars().any(char::is_whitespace))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line {
    /// Blank lines and comments, kept verbatim.
    Other(String),
    Entry(Entry),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub export: bool,
    pub name: String,
    pub value: String,
    /// The line as written; `render` keeps it unless `set_value` changed it.
    original: Option<String>,
}

impl Entry {
    pub fn set_value(&mut self, value: String) {
        self.value = value;
        self.original = None;
    }
}

pub fn parse(text: &str) -> Result<Vec<Line>> {
    text.lines()
        .enumerate()
        .map(|(index, line)| parse_line(line).map_err(|err| anyhow!("line {}: {err}", index + 1)))
        .collect()
}

pub fn entries(lines: &[Line]) -> impl Iterator<Item = &Entry> {
    lines.iter().filter_map(|line| match line {
        Line::Entry(entry) => Some(entry),
        Line::Other(_) => None,
    })
}

fn parse_line(line: &str) -> Result<Line> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Ok(Line::Other(line.to_string()));
    }
    let (export, rest) = match trimmed.strip_prefix("export ") {
        Some(rest) => (true, rest.trim_start()),
        None => (false, trimmed),
    };
    let (name, raw) = rest
        .split_once('=')
        .ok_or_else(|| anyhow!("expected NAME=value"))?;
    let name = name.trim();
    if name.is_empty()
        || name.starts_with(|c: char| c.is_ascii_digit())
        || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err(anyhow!("{name:?} is not a valid variable name"));
    }
    Ok(Line::Entry(Entry {
        export,
        name: name.to_string(),
        value: parse_value(raw.trim())?,
        original: Some(line.to_string()),
    }))
}

fn parse_value(raw: &str) -> Result<String> {
    if let Some(body) = raw.strip_prefix('\'') {
        let (value, after) = body
            .split_once('\'')
            .ok_or_else(|| anyhow!("unterminated single quote (multi-line values are not supported)"))?;
        ensure_only_comment(after)?;
        return Ok(value.to_string());
    }
    if let Some(body) = raw.strip_prefix('"') {
        let mut value = String::new();
        let mut chars = body.chars();
        loop {
            match chars.next() {
                None => return Err(anyhow!("unterminated double quote (multi-line values are not supported)")),
                Some('"') => break,
                Some('\\') => match chars.next() {
                    Some('n') => value.push('\n'),
                    Some('t') => value.push('\t'),
                    Some(other) => value.push(other),
                    None => return Err(anyhow!("unterminated double quote")),
                },
                Some(c) => value.push(c),
            }
        }
        ensure_only_comment(chars.as_str())?;
        return Ok(value);
    }
    // Unquoted: an inline comment starts at " #".
    let value = match raw.find(" #") {
        Some(at) => &raw[..at],
        None => raw,
    };
    Ok(value.trim_end().to_string())
}

fn ensure_only_comment(rest: &str) -> Result<()> {
    let rest = rest.trim();
    if rest.is_empty() || rest.starts_with('#') {
        Ok(())
    } else {
        Err(anyhow!("unexpected text after the closing quote"))
    }
}

/// Renders `lines` back to text. Lines nobody changed come back exactly as
/// written; changed entries become `NAME=value`, quoted only when needed.
pub fn render(lines: &[Line]) -> String {
    let mut out = String::new();
    for line in lines {
        match line {
            Line::Other(text) => out.push_str(text),
            Line::Entry(Entry { original: Some(text), .. }) => out.push_str(text),
            Line::Entry(entry) => {
                if entry.export {
                    out.push_str("export ");
                }
                out.push_str(&entry.name);
                out.push('=');
                out.push_str(&quote(&entry.value));
            }
        }
        out.push('\n');
    }
    out
}

fn quote(value: &str) -> String {
    let plain = !value.is_empty()
        && !value.contains(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '#' | '\\'));
    if plain {
        return value.to_string();
    }
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(text: &str) -> Vec<(String, String)> {
        entries(&parse(text).unwrap())
            .map(|e| (e.name.clone(), e.value.clone()))
            .collect()
    }

    #[test]
    fn reads_the_usual_shapes() {
        let text = "# db\nDATABASE_URL=postgres://u:p@h/db\nexport TOKEN='a b#c'\nMSG=\"line\\nnext \\\"q\\\"\" # note\nPLAIN=value # comment\nEMPTY=\n";
        assert_eq!(
            values(text),
            vec![
                ("DATABASE_URL".into(), "postgres://u:p@h/db".into()),
                ("TOKEN".into(), "a b#c".into()),
                ("MSG".into(), "line\nnext \"q\"".into()),
                ("PLAIN".into(), "value".into()),
                ("EMPTY".into(), "".into()),
            ]
        );
    }

    #[test]
    fn errors_name_the_line() {
        let err = parse("A=1\nB=\"open\n").unwrap_err().to_string();
        assert!(err.starts_with("line 2:"), "{err}");
        assert!(parse("1BAD=x\n").is_err());
        assert!(parse("NOEQUALS\n").is_err());
    }

    #[test]
    fn unchanged_lines_render_exactly_as_written() {
        let text = "# keep me\n\nexport A = \"x y\"  # why\nB='q\"uote'\nEMPTY=\n";
        assert_eq!(render(&parse(text).unwrap()), text);
    }

    #[test]
    fn changed_values_render_quoted_only_when_needed() {
        let mut lines = parse("export A=old\nB=old\nC=old\n").unwrap();
        let values = ["harar://dev/a", "has space \"q\"", "back\\slash\nnew"];
        for (line, value) in lines.iter_mut().zip(values) {
            if let Line::Entry(entry) = line {
                entry.set_value(value.to_string());
            }
        }
        let text = render(&lines);
        assert_eq!(text, "export A=harar://dev/a\nB=\"has space \\\"q\\\"\"\nC=\"back\\\\slash\\nnew\"\n");
        let again: Vec<String> = entries(&parse(&text).unwrap()).map(|e| e.value.clone()).collect();
        assert_eq!(again, values);
    }

    #[test]
    fn only_whole_values_are_references() {
        assert_eq!(reference("harar://dev/neon/url"), Some("dev/neon/url"));
        assert_eq!(reference("postgres://harar://x"), None);
        assert_eq!(reference("harar://"), None);
        assert_eq!(reference("harar://has space"), None);
    }
}
