use super::expression::{
    PathExpression, classify_path_operand_expression, shell_pattern_is_bare_star_segment,
    shell_pattern_matches_path,
};
use super::normalize::normalize_shell_path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TargetMatch {
    pub(crate) target: String,
    pub(crate) confidence: TargetMatchConfidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TargetMatchConfidence {
    Exact,
    Possible,
}

pub(crate) fn match_path_expression_against_exact_targets(
    expression: &PathExpression,
    targets: &[&str],
) -> Option<TargetMatch> {
    match expression {
        PathExpression::Exact(path) => targets.iter().find_map(|target| {
            (normalize_shell_path(path) == normalize_shell_path(target)).then(|| TargetMatch {
                target: normalize_shell_path(path),
                confidence: TargetMatchConfidence::Exact,
            })
        }),
        PathExpression::OneOf(expressions) => expressions.iter().find_map(|expression| {
            match_path_expression_against_exact_targets(expression, targets)
        }),
        PathExpression::Pattern(pattern) => targets.iter().find_map(|target| {
            shell_pattern_matches_path(pattern.as_str(), target).then(|| TargetMatch {
                target: normalize_shell_path(target),
                confidence: TargetMatchConfidence::Possible,
            })
        }),
        PathExpression::Dynamic | PathExpression::Unsupported => None,
    }
}

pub(crate) fn match_path_expression_against_target_or_direct_children(
    expression: &PathExpression,
    targets: &[&str],
) -> Option<TargetMatch> {
    if let Some(target_match) = match_path_expression_against_exact_targets(expression, targets) {
        return Some(target_match);
    }

    match expression {
        PathExpression::OneOf(expressions) => expressions.iter().find_map(|expression| {
            match_path_expression_against_target_or_direct_children(expression, targets)
        }),
        PathExpression::Pattern(pattern) => targets.iter().find_map(|target| {
            pattern_matches_direct_children_of_target(pattern.as_str(), target)
                .or_else(|| pattern_parent_matches_target(pattern.as_str(), target))
                .map(|target| TargetMatch {
                    target,
                    confidence: TargetMatchConfidence::Possible,
                })
        }),
        PathExpression::Exact(_) | PathExpression::Dynamic | PathExpression::Unsupported => None,
    }
}

fn pattern_matches_direct_children_of_target(pattern: &str, target: &str) -> Option<String> {
    let normalized_pattern = normalize_shell_path(pattern);
    let normalized_target = normalize_shell_path(target);

    let Some(parent) = parent_path(&normalized_pattern) else {
        return None;
    };
    if parent != normalized_target {
        return None;
    }

    normalized_pattern
        .rsplit('/')
        .next()
        .is_some_and(shell_pattern_is_bare_star_segment)
        .then(|| child_glob_target(target))
}

fn pattern_parent_matches_target(pattern: &str, target: &str) -> Option<String> {
    let normalized_pattern = normalize_shell_path(pattern);
    let child = normalized_pattern.rsplit('/').next()?;
    if !shell_pattern_is_bare_star_segment(child) {
        return None;
    }

    let parent = parent_path(&normalized_pattern)?;
    let parent_expression =
        classify_path_operand_expression(&parent, false, "word", Some("/"), None);
    match_path_expression_against_exact_targets(&parent_expression, &[target])
        .map(|target_match| child_glob_target(&target_match.target))
}

fn parent_path(path: &str) -> Option<String> {
    let normalized = normalize_shell_path(path);
    let (parent, child) = normalized.rsplit_once('/')?;
    if child.is_empty() {
        return None;
    }

    if parent.is_empty() {
        Some("/".to_string())
    } else {
        Some(parent.to_string())
    }
}

fn child_glob_target(target: &str) -> String {
    let normalized = normalize_shell_path(target);
    if normalized == "/" {
        "/*".to_string()
    } else {
        format!("{normalized}/*")
    }
}

#[cfg(test)]
mod tests {
    use super::{
        TargetMatchConfidence, match_path_expression_against_exact_targets,
        match_path_expression_against_target_or_direct_children,
    };
    use crate::path::classify_path_operand_expression;

    #[test]
    fn target_match_matches_exact_roots() {
        let expression =
            classify_path_operand_expression("/usr/../etc", false, "word", Some("/tmp"), None);

        let result = match_path_expression_against_exact_targets(&expression, &["/etc"])
            .expect("expected target match");

        assert_eq!(result.target, "/etc");
        assert_eq!(result.confidence, TargetMatchConfidence::Exact);
    }

    #[test]
    fn target_match_matches_root_name_glob_roots() {
        let expression = classify_path_operand_expression("/u*", false, "word", Some("/tmp"), None);

        let result = match_path_expression_against_exact_targets(&expression, &["/usr"])
            .expect("expected target match");

        assert_eq!(result.target, "/usr");
        assert_eq!(result.confidence, TargetMatchConfidence::Possible);
    }

    #[test]
    fn target_match_matches_brace_roots() {
        let expression =
            classify_path_operand_expression("/{etc,usr}", false, "word", Some("/tmp"), None);

        let result = match_path_expression_against_exact_targets(&expression, &["/usr"])
            .expect("expected target match");

        assert_eq!(result.target, "/usr");
    }

    #[test]
    fn target_match_matches_direct_child_globs() {
        let expression =
            classify_path_operand_expression("/etc/*", false, "word", Some("/tmp"), None);

        let result =
            match_path_expression_against_target_or_direct_children(&expression, &["/etc"])
                .expect("expected target match");

        assert_eq!(result.target, "/etc/*");
        assert_eq!(result.confidence, TargetMatchConfidence::Possible);
    }

    #[test]
    fn target_match_matches_pattern_parent_child_globs() {
        let root_glob =
            classify_path_operand_expression("/u*/*", false, "word", Some("/tmp"), None);
        let brace =
            classify_path_operand_expression("/{etc,usr}/*", false, "word", Some("/tmp"), None);

        let root_glob_result =
            match_path_expression_against_target_or_direct_children(&root_glob, &["/usr"])
                .expect("expected target match");
        let brace_result =
            match_path_expression_against_target_or_direct_children(&brace, &["/etc"])
                .expect("expected target match");

        assert_eq!(root_glob_result.target, "/usr/*");
        assert_eq!(brace_result.target, "/etc/*");
    }

    #[test]
    fn target_match_does_not_treat_deep_or_partial_globs_as_direct_child_globs() {
        let deep =
            classify_path_operand_expression("/etc/*/passwd", false, "word", Some("/tmp"), None);
        let partial =
            classify_path_operand_expression("/etc/p*", false, "word", Some("/tmp"), None);

        assert!(
            match_path_expression_against_target_or_direct_children(&deep, &["/etc"]).is_none()
        );
        assert!(
            match_path_expression_against_target_or_direct_children(&partial, &["/etc"]).is_none()
        );
    }
}
