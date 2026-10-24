#[cfg(unix)]
pub fn plan_execution_frame_unix_socket(
    socket_path: &std::path::Path,
    request: &caushell_types::ExecutionFramePlanRequest,
) -> Result<caushell_types::ExecutionFramePlan, crate::CliError> {
    use caushell_types::{RuntimeTransportRequest as Q, RuntimeTransportResponse as R};
    crate::require_execution_frame_protocol(&crate::ping_unix_socket(socket_path)?)?;
    match crate::send_runtime_transport_unix_socket(
        socket_path,
        &Q::ExecutionFramePlan(request.clone()),
    )? {
        R::ExecutionFramePlan(plan) => Ok(plan),
        _ => Err(crate::CliError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "runtime did not return an execution frame plan",
        ))),
    }
}
