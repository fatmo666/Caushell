use crate::path::{
    PathExpression, classify_path_operand_expression,
    match_path_expression_against_target_or_direct_children, normalize_shell_path,
    shell_pattern_matches_path,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum HostTargetKind {
    CatastrophicDeleteRoot,
    BlockDevice,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HostTargetOperand<'a> {
    pub(crate) text: &'a str,
    pub(crate) quoted: bool,
    pub(crate) node_kind: &'a str,
}

impl<'a> HostTargetOperand<'a> {
    pub(crate) fn unquoted_word(text: &'a str) -> Self {
        Self {
            text,
            quoted: false,
            node_kind: "word",
        }
    }
}

const BLOCK_DEVICE_PREFIXES: &[&str] = &[
    "/dev/sd",
    "/dev/md",
    "/dev/nvme",
    "/dev/mmcblk",
    "/dev/dm-",
    "/dev/vd",
    "/dev/xvd",
    "/dev/mapper/",
    "/dev/disk/",
];

const BLOCK_DEVICE_PATTERN_SENTINELS: &[&str] = &[
    "/dev/sda",
    "/dev/sda1",
    "/dev/md0",
    "/dev/nvme0n1",
    "/dev/nvme0n1p1",
    "/dev/mmcblk0",
    "/dev/mmcblk0p1",
    "/dev/dm-0",
    "/dev/vda",
    "/dev/vda1",
    "/dev/xvda",
    "/dev/xvda1",
    "/dev/mapper/root",
    "/dev/disk/by-id/ata-example",
    "/dev/disk/by-path/pci-example",
    "/dev/disk/by-uuid/00000000-0000-0000-0000-000000000000",
    "/dev/disk/by-label/root",
];

const CATASTROPHIC_DELETE_ROOTS: &[&str] = &["/", "/usr", "/etc", "/var", "/boot"];

pub(super) fn classify_host_target_with_optional_cwd(
    operand: HostTargetOperand<'_>,
    cwd: Option<&str>,
    home: Option<&str>,
) -> Option<HostTargetKind> {
    if block_device_path_for_operand(operand, cwd, home).is_some() {
        return Some(HostTargetKind::BlockDevice);
    }

    if catastrophic_delete_target_for_operand(operand, cwd, home).is_some() {
        return Some(HostTargetKind::CatastrophicDeleteRoot);
    }

    None
}

pub(crate) fn block_device_write_reason_for_redirection_with_optional_cwd(
    target: HostTargetOperand<'_>,
    cwd: Option<&str>,
    home: Option<&str>,
) -> Option<String> {
    matches!(
        classify_host_target_with_optional_cwd(target, cwd, home),
        Some(HostTargetKind::BlockDevice)
    )
    .then(|| {
        format!(
            "raw block-device overwrite target {} via shell redirection",
            target.text
        )
    })
}

pub(crate) fn block_device_path_for_arg_with_optional_cwd(
    args: &[&str],
    cwd: Option<&str>,
    home: Option<&str>,
) -> Option<String> {
    args.iter().find_map(|arg| {
        block_device_path_for_operand(HostTargetOperand::unquoted_word(arg), cwd, home)
    })
}

pub(crate) fn catastrophic_delete_target_for_arg(
    operand: HostTargetOperand<'_>,
    cwd: &str,
    home: Option<&str>,
) -> Option<String> {
    catastrophic_delete_target_for_operand(operand, Some(cwd), home)
}

fn block_device_path_for_operand(
    operand: HostTargetOperand<'_>,
    cwd: Option<&str>,
    home: Option<&str>,
) -> Option<String> {
    let expression = classify_path_operand_expression(
        operand.text,
        operand.quoted,
        operand.node_kind,
        cwd,
        home,
    );

    block_device_path_for_expression(&expression)
}

fn block_device_path_for_expression(expression: &PathExpression) -> Option<String> {
    match expression {
        PathExpression::Exact(path) => is_block_device_path(path).then_some(path.clone()),
        PathExpression::OneOf(expressions) => expressions
            .iter()
            .find_map(block_device_path_for_expression),
        PathExpression::Pattern(pattern) => block_device_pattern_target(pattern.as_str()),
        PathExpression::Dynamic | PathExpression::Unsupported => None,
    }
}

fn is_block_device_path(path: &str) -> bool {
    BLOCK_DEVICE_PREFIXES
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

fn block_device_pattern_target(pattern: &str) -> Option<String> {
    let normalized = normalize_shell_path(pattern);

    BLOCK_DEVICE_PATTERN_SENTINELS
        .iter()
        .any(|sentinel| shell_pattern_matches_path(&normalized, sentinel))
        .then_some(normalized)
}

fn catastrophic_delete_target_for_operand(
    operand: HostTargetOperand<'_>,
    cwd: Option<&str>,
    home: Option<&str>,
) -> Option<String> {
    let expression = classify_path_operand_expression(
        operand.text,
        operand.quoted,
        operand.node_kind,
        cwd,
        home,
    );

    match_path_expression_against_target_or_direct_children(&expression, CATASTROPHIC_DELETE_ROOTS)
        .map(|target_match| target_match.target)
}
