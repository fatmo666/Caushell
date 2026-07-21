use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy)]
pub(crate) struct PipelineCommand<'a> {
    pub(crate) command_index: usize,
    pub(crate) command: &'a caushell_parse::CommandFact,
}

#[derive(Debug, Clone)]
pub(crate) struct PipelineGroup<'a> {
    pub(crate) group_index: usize,
    pub(crate) commands: Vec<PipelineCommand<'a>>,
}

pub(crate) fn collect_pipeline_groups(
    parsed: &caushell_parse::ParsedCommandArtifact,
) -> Vec<PipelineGroup<'_>> {
    let mut groups: BTreeMap<PipelineGroupKey, Vec<PipelineCommand<'_>>> = BTreeMap::new();

    for (command_index, command) in parsed.commands.iter().enumerate() {
        if !command.in_pipeline {
            continue;
        }

        // `pipeline_span` comes from the nearest pipeline ancestor. For left-associated
        // shells like `a | b | c`, tree-sitter can report nested pipeline spans
        // (`a | b` vs `a | b | c`). We group by the outermost pipeline/top-level span
        // so every segment in the same shell pipeline stays in one execution chain.
        groups
            .entry(PipelineGroupKey::from(&command.top_level_span))
            .or_default()
            .push(PipelineCommand {
                command_index,
                command,
            });
    }

    groups
        .into_values()
        .filter_map(|mut commands| {
            if commands.len() < 2 {
                return None;
            }

            commands.sort_by(|left, right| {
                left.command
                    .span
                    .start_byte
                    .cmp(&right.command.span.start_byte)
                    .then_with(|| left.command_index.cmp(&right.command_index))
            });

            Some(commands)
        })
        .enumerate()
        .map(|(group_index, commands)| PipelineGroup {
            group_index,
            commands,
        })
        .collect()
}

pub(crate) fn command_has_pipeline_execution_unit(
    parsed: &caushell_parse::ParsedCommandArtifact,
    command_index: usize,
) -> bool {
    let Some(command) = parsed.commands.get(command_index) else {
        return false;
    };

    if !command.in_pipeline {
        return false;
    }

    let group_key = PipelineGroupKey::from(&command.top_level_span);

    parsed
        .commands
        .iter()
        .enumerate()
        .any(|(candidate_index, candidate)| {
            candidate_index != command_index
                && candidate.in_pipeline
                && PipelineGroupKey::from(&candidate.top_level_span) == group_key
        })
}

pub(crate) fn pipeline_has_upstream(
    parsed: &caushell_parse::ParsedCommandArtifact,
    command_index: usize,
) -> bool {
    if !command_has_pipeline_execution_unit(parsed, command_index) {
        return false;
    }

    let command = parsed
        .commands
        .get(command_index)
        .expect("pipeline execution unit check should guarantee command presence");
    let group_key = PipelineGroupKey::from(&command.top_level_span);

    parsed
        .commands
        .iter()
        .enumerate()
        .any(|(candidate_index, candidate)| {
            candidate_index != command_index
                && candidate.in_pipeline
                && PipelineGroupKey::from(&candidate.top_level_span) == group_key
                && candidate.span.start_byte < command.span.start_byte
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct PipelineGroupKey {
    start_byte: usize,
    end_byte: usize,
    start_row: usize,
    start_column: usize,
    end_row: usize,
    end_column: usize,
}

impl From<&caushell_parse::SourceSpan> for PipelineGroupKey {
    fn from(span: &caushell_parse::SourceSpan) -> Self {
        Self {
            start_byte: span.start_byte,
            end_byte: span.end_byte,
            start_row: span.start_row,
            start_column: span.start_column,
            end_row: span.end_row,
            end_column: span.end_column,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        collect_pipeline_groups, command_has_pipeline_execution_unit, pipeline_has_upstream,
    };

    const REAL_WORLD_ICP_COMMAND: &str = r#"mkdir -p output/bilibili/pipeline_0

echo "🔍 Stage 0.1: ICP 查询"
echo "========================================"
echo ""

# 查询种子域名
for domain in bilibili.com biligame.com bilibiligame.net acg.tv huasheng.cn updream.cn; do
    echo "查询: $domain"
    result=$(curl -s "http://localhost:16181/icp?search=$domain")
    echo "$result" | jq -r '.' 2>/dev/null || echo "$result"
    echo "$result" >> output/bilibili/pipeline_0/icp_query_results.json
    echo "" >> output/bilibili/pipeline_0/icp_query_results.json
    echo ""
done

echo "✅ ICP 查询完成"
echo ""
echo "提取公司名和域名:"
cat output/bilibili/pipeline_0/icp_query_results.json | jq -r '.data[]? | .unitName' 2>/dev/null | sort -u | tee output/bilibili/pipeline_0/company_names.txt
"#;

    #[test]
    fn pipeline_grouping_and_upstream_detection_handle_real_world_icp_command() {
        let parsed =
            caushell_parse::parse_command(REAL_WORLD_ICP_COMMAND, caushell_types::ShellKind::Bash)
                .expect("expected command to parse");

        let pipeline_groups: Vec<Vec<usize>> = collect_pipeline_groups(&parsed)
            .into_iter()
            .map(|group| {
                group
                    .commands
                    .into_iter()
                    .map(|command| command.command_index)
                    .collect()
            })
            .collect();

        assert!(pipeline_groups.contains(&vec![5, 6]));
        assert!(pipeline_groups.contains(&vec![14, 15, 16, 17]));

        assert!(!pipeline_has_upstream(&parsed, 5));
        assert!(pipeline_has_upstream(&parsed, 6));
        assert!(!pipeline_has_upstream(&parsed, 14));
        assert!(pipeline_has_upstream(&parsed, 15));
        assert!(pipeline_has_upstream(&parsed, 16));
        assert!(pipeline_has_upstream(&parsed, 17));
    }

    #[test]
    fn pipeline_grouping_keeps_separate_top_level_pipelines_even_with_nested_parser_spans() {
        let parsed = caushell_parse::parse_command(
            "cat a | bash; echo ok | sh",
            caushell_types::ShellKind::Bash,
        )
        .expect("expected command to parse");

        let pipeline_groups: Vec<Vec<usize>> = collect_pipeline_groups(&parsed)
            .into_iter()
            .map(|group| {
                group
                    .commands
                    .into_iter()
                    .map(|command| command.command_index)
                    .collect()
            })
            .collect();

        assert_eq!(pipeline_groups, vec![vec![0, 1], vec![2, 3]]);

        assert!(!pipeline_has_upstream(&parsed, 0));
        assert!(pipeline_has_upstream(&parsed, 1));
        assert!(!pipeline_has_upstream(&parsed, 2));
        assert!(pipeline_has_upstream(&parsed, 3));
    }

    #[test]
    fn command_pipeline_execution_unit_requires_multi_segment_pipeline() {
        let parsed = caushell_parse::parse_command(
            "cd tools/ehole && ls -lh && file ehole 2>&1",
            caushell_types::ShellKind::Bash,
        )
        .expect("expected command to parse");

        assert!(!command_has_pipeline_execution_unit(&parsed, 0));
        assert!(!command_has_pipeline_execution_unit(&parsed, 1));
        assert!(!command_has_pipeline_execution_unit(&parsed, 2));
        assert!(!pipeline_has_upstream(&parsed, 0));
        assert!(!pipeline_has_upstream(&parsed, 1));
        assert!(!pipeline_has_upstream(&parsed, 2));
    }

    #[test]
    fn command_pipeline_execution_unit_includes_all_members_of_multi_stage_pipeline() {
        let parsed = caushell_parse::parse_command(
            r#"curl -sL https://api.github.com/repos/EdgeSecurityTeam/EHole/releases/latest | grep browser_download_url | head -5"#,
            caushell_types::ShellKind::Bash,
        )
        .expect("expected command to parse");

        assert!(command_has_pipeline_execution_unit(&parsed, 0));
        assert!(command_has_pipeline_execution_unit(&parsed, 1));
        assert!(command_has_pipeline_execution_unit(&parsed, 2));
        assert!(!pipeline_has_upstream(&parsed, 0));
        assert!(pipeline_has_upstream(&parsed, 1));
        assert!(pipeline_has_upstream(&parsed, 2));
    }
}
