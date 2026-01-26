use serde::{Deserialize, Serialize};

/// 응답도 스키마는 동일한데 직렬화 버전
#[derive(Debug, Deserialize)]
pub struct Request<TestGroup> {
    #[serde(rename = "vsId")]
    pub vs_id: u64,
    pub algorithm: String,
    pub mode: String,
    pub revision: String,
    #[serde(rename = "isSample")]
    pub is_sample: bool,
    #[serde(rename = "testGroups")]
    pub test_groups: Vec<TestGroup>,
}

#[derive(Debug, Serialize)]
pub struct Response<TestGroup> {
    #[serde(rename = "vsId")]
    pub vs_id: u64,
    pub algorithm: String,
    pub mode: String,
    pub revision: String,
    #[serde(rename = "isSample")]
    pub is_sample: bool,
    #[serde(rename = "testGroups")]
    pub test_groups: Vec<TestGroup>,
}