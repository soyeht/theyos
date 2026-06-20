//! Minimal text-preserving helpers for `claws/manifest.yml`.
//!
//! These helpers deliberately avoid round-tripping the full manifest through
//! `serde_yaml`: the file is maintained by humans, and the CLI commands only
//! need targeted block/field edits.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MissingClaw {
    Noop,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InsertPosition {
    AfterHeader,
    EndOfBlock,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClawBlock {
    pub start: usize,
    pub end: usize,
    pub indent: String,
}

impl ClawBlock {
    #[must_use]
    pub fn field_indent(&self) -> String {
        format!("{}  ", self.indent)
    }
}

#[must_use]
pub(crate) fn yaml_quoted(s: &str) -> String {
    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

#[cfg(test)]
pub(crate) fn find_claw_block(content: &str, claw: &str) -> Option<ClawBlock> {
    let lines: Vec<&str> = content.lines().collect();
    find_claw_block_in_lines(&lines, claw)
}

pub(crate) fn read_scalar_field(
    content: &str,
    claw: &str,
    key: &str,
) -> Result<Option<String>, String> {
    let lines: Vec<&str> = content.lines().collect();
    let block = find_claw_block_in_lines(&lines, claw)
        .ok_or_else(|| format!("claw block {claw:?} not found in manifest"))?;
    let field_indent = block.field_indent();
    for line in &lines[block.start + 1..block.end] {
        let trimmed = line.trim_start();
        if trimmed.starts_with(&format!("{key}:")) && line.starts_with(field_indent.as_str()) {
            let Some((_, value)) = trimmed.split_once(':') else {
                continue;
            };
            return Ok(Some(value.trim().trim_matches('"').to_string()));
        }
    }
    Ok(None)
}

pub(crate) fn patch_quoted_field_noop_unknown(
    content: &str,
    claw: &str,
    key: &str,
    value: &str,
) -> String {
    patch_rendered_field(
        content,
        claw,
        key,
        &yaml_quoted(value),
        MissingClaw::Noop,
        InsertPosition::EndOfBlock,
    )
    .unwrap_or_else(|_| content.to_string())
}

pub(crate) fn patch_unquoted_field_after_header(
    content: &str,
    claw: &str,
    key: &str,
    value: &str,
) -> Result<String, String> {
    patch_rendered_field(
        content,
        claw,
        key,
        value,
        MissingClaw::Error,
        InsertPosition::AfterHeader,
    )
}

pub(crate) fn promote_available_to_builtin(content: &str, claw: &str) -> Result<String, String> {
    let lines: Vec<&str> = content.lines().collect();
    let block = find_claw_block_in_lines(&lines, claw)
        .ok_or_else(|| format!("claw block {claw:?} not found in manifest"))?;

    let mut out_block: Vec<String> = Vec::new();
    out_block.push(lines[block.start].to_string());

    let mut saw_install_plan_source = false;
    let mut i = block.start + 1;
    while i < block.end {
        let line = lines[i];

        if line.strip_prefix("    tier:").is_some() {
            out_block.push("    tier: supported".to_string());
            i += 1;
            continue;
        }

        if line.strip_prefix("    install_template:").is_some() {
            i += 1;
            continue;
        }

        if line.strip_prefix("    install_plan_source:").is_some() {
            out_block.push("    install_plan_source: \"builtin\"".to_string());
            saw_install_plan_source = true;
            i += 1;
            continue;
        }

        if line.trim_end() == "    install:" {
            i += 1;
            while i < block.end {
                let nested = lines[i];
                if nested.is_empty() || nested.starts_with("      ") {
                    i += 1;
                    continue;
                }
                break;
            }
            continue;
        }

        out_block.push(line.to_string());
        i += 1;
    }

    if !saw_install_plan_source {
        out_block.insert(1, "    install_plan_source: \"builtin\"".to_string());
    }

    Ok(replace_block(content, &lines, &block, out_block))
}

pub(crate) fn tmp_sibling(path: &std::path::Path) -> std::path::PathBuf {
    let mut tmp = path.to_path_buf();
    let name = format!(
        "{}.tmp.{}",
        path.file_name().and_then(|s| s.to_str()).unwrap_or("out"),
        std::process::id()
    );
    tmp.set_file_name(name);
    tmp
}

fn patch_rendered_field(
    content: &str,
    claw: &str,
    key: &str,
    rendered_value: &str,
    missing_claw: MissingClaw,
    insert_position: InsertPosition,
) -> Result<String, String> {
    let lines: Vec<&str> = content.lines().collect();
    let Some(block) = find_claw_block_in_lines(&lines, claw) else {
        return match missing_claw {
            MissingClaw::Noop => Ok(content.to_string()),
            MissingClaw::Error => Err(format!("claw block {claw:?} not found in manifest")),
        };
    };

    let field_indent = block.field_indent();
    let mut out_block: Vec<String> = Vec::with_capacity(block.end - block.start + 1);
    out_block.push(lines[block.start].to_string());

    let mut wrote = false;
    for line in &lines[block.start + 1..block.end] {
        let trimmed = line.trim_start();
        if trimmed.starts_with(&format!("{key}:")) && line.starts_with(field_indent.as_str()) {
            out_block.push(format!("{field_indent}{key}: {rendered_value}"));
            wrote = true;
        } else {
            out_block.push((*line).to_string());
        }
    }

    if !wrote {
        let new_line = format!("{field_indent}{key}: {rendered_value}");
        match insert_position {
            InsertPosition::AfterHeader => out_block.insert(1, new_line),
            InsertPosition::EndOfBlock => out_block.push(new_line),
        }
    }

    Ok(replace_block(content, &lines, &block, out_block))
}

fn replace_block(
    content: &str,
    lines: &[&str],
    block: &ClawBlock,
    out_block: Vec<String>,
) -> String {
    let mut out = Vec::with_capacity(lines.len() + 1);
    out.extend(lines[..block.start].iter().map(|s| (*s).to_string()));
    out.extend(out_block);
    out.extend(lines[block.end..].iter().map(|s| (*s).to_string()));
    let trailing_newline = content.ends_with('\n');
    let mut joined = out.join("\n");
    if trailing_newline {
        joined.push('\n');
    }
    joined
}

fn find_claw_block_in_lines(lines: &[&str], claw: &str) -> Option<ClawBlock> {
    for (i, raw) in lines.iter().enumerate() {
        let stripped = raw.trim_start();
        let indent_len = raw.len() - stripped.len();
        if indent_len >= 2 && stripped == format!("{claw}:") {
            let indent = " ".repeat(indent_len);
            return Some(ClawBlock {
                start: i,
                end: find_block_end(lines, i, indent_len),
                indent,
            });
        }
    }
    None
}

fn find_block_end(lines: &[&str], start: usize, indent_len: usize) -> usize {
    let mut end = lines.len();
    for (i, raw) in lines.iter().enumerate().skip(start + 1) {
        if raw.trim().is_empty() {
            continue;
        }
        let stripped = raw.trim_start();
        let this_indent = raw.len() - stripped.len();
        if this_indent <= indent_len {
            end = i;
            break;
        }
    }
    end
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yaml_quoted_escapes_quotes_and_backslashes() {
        assert_eq!(yaml_quoted("a \"b\" c"), "\"a \\\"b\\\" c\"");
        assert_eq!(yaml_quoted("a\\b"), "\"a\\\\b\"");
    }

    #[test]
    fn find_claw_block_locates_header() {
        let src = "claws:\n  foo:\n    a: 1\n  bar:\n    b: 2\n";
        let block = find_claw_block(src, "bar").unwrap();
        assert_eq!(block.start, 3);
        assert_eq!(block.end, 5);
        assert_eq!(block.indent, "  ");
    }

    #[test]
    fn read_scalar_field_reads_quoted_or_plain_value() {
        let src = "claws:\n  foo:\n    tier: detected\n    source: \"https://example.invalid/x\"\n";
        assert_eq!(
            read_scalar_field(src, "foo", "tier").unwrap(),
            Some("detected".into())
        );
        assert_eq!(
            read_scalar_field(src, "foo", "source").unwrap(),
            Some("https://example.invalid/x".into())
        );
    }

    #[test]
    fn patch_quoted_field_replaces_existing_value() {
        let src = "claws:\n  foo:\n    latest_upstream_commit: old\n    other: keep\n";
        let out = patch_quoted_field_noop_unknown(src, "foo", "latest_upstream_commit", "new");
        assert!(out.contains("latest_upstream_commit: \"new\""));
        assert!(out.contains("other: keep"));
        assert!(!out.contains(": old"));
    }

    #[test]
    fn patch_quoted_field_appends_when_key_missing() {
        let src = "claws:\n  foo:\n    source: https://x\n    other: keep\n";
        let out = patch_quoted_field_noop_unknown(src, "foo", "latest_upstream_commit", "abc");
        assert!(out.contains("source: https://x"));
        assert!(out.contains("other: keep"));
        assert!(out.contains("latest_upstream_commit: \"abc\""));
    }

    #[test]
    fn patch_field_noops_for_unknown_claw_when_requested() {
        let src = "claws:\n  foo:\n    other: keep\n";
        let out = patch_quoted_field_noop_unknown(src, "bar", "latest_upstream_commit", "abc");
        assert_eq!(out, src);
    }

    #[test]
    fn patch_unquoted_field_inserts_after_header() {
        let src = "claws:\n  foo:\n    description: x\n";
        let out = patch_unquoted_field_after_header(src, "foo", "tier", "available").unwrap();
        assert!(out.contains("  foo:\n    tier: available\n    description: x"));
    }

    #[test]
    fn promote_available_to_builtin_rewrites_supported_shape() {
        let src = concat!(
            "claws:\n",
            "  picoclaw:\n",
            "    description: \"x\"\n",
            "    tier: available\n",
            "    install_template: node-basic\n",
            "    install:\n",
            "      system_deps:\n",
            "        - curl\n",
            "      run_cmd: \"node foo\"\n",
            "    binary_size_mb: 30\n",
        );
        let out = promote_available_to_builtin(src, "picoclaw").unwrap();
        assert!(out.contains("    tier: supported"));
        assert!(out.contains("    install_plan_source: \"builtin\""));
        assert!(!out.contains("install_template:"));
        assert!(!out.contains("    install:"));
        assert!(!out.contains("      run_cmd"));
        assert!(out.contains("    binary_size_mb: 30"));
    }

    #[test]
    fn helpers_preserve_trailing_newline() {
        let src = "claws:\n  foo:\n    description: x\n";
        let out = patch_unquoted_field_after_header(src, "foo", "tier", "available").unwrap();
        assert!(out.ends_with('\n'));
    }
}
