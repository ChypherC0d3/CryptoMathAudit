use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct TestVector {
    pub id: String,
    pub hypothesis: String,
    pub description: String,
    pub pubkey: String,
    pub signature: String,
    pub message: String,
    #[serde(default)]
    pub expected_firedancer: String,
    #[serde(default)]
    pub expected_dalek_strict: String,
    #[serde(default)]
    pub expected_dalek_loose: String,
    /// Filled in after running
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_dalek_strict: Option<String>,
    /// Filled in after running
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_dalek_loose: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TestVectorFile {
    pub vectors: Vec<TestVector>,
}
