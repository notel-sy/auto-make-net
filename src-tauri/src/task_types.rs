#[derive(Debug)]
pub struct RunServerSuccess {
    pub urls: Vec<String>,
    pub raw_log: String,
    pub final_phase: String,
}

#[derive(Debug)]
pub struct RunServerFailure {
    pub phase: String,
    pub code: String,
    pub message: String,
    pub raw_log: String,
}

#[derive(Debug)]
pub enum RunServerOutcome {
    Success(RunServerSuccess),
    Failure(RunServerFailure),
    Skipped,
}

#[derive(Debug, Clone)]
pub struct TrustCheckResult {
    pub is_trusted: bool,
    pub is_mismatch: bool,
}

#[derive(Debug, Clone)]
pub struct KnownHostEntry {
    pub fingerprint: Option<String>,
}
