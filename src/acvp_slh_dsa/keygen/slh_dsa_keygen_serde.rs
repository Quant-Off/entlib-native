use serde::{Deserialize, Serialize};

//
// prompt.json - start
//

#[derive(Debug, Deserialize)]
pub struct SLHDSAKEYGENTestGroup {
    #[serde(rename = "tgId")]
    pub tg_id: u64,
    #[serde(rename = "testType")]
    pub test_type: String,
    #[serde(rename = "parameterSet")]
    pub parameter_set: String,
    pub tests: Vec<SLHDSAKEYGENTestCase>,
}

#[derive(Debug, Deserialize)]
pub struct SLHDSAKEYGENTestCase {
    #[serde(rename = "tcId")]
    pub tc_id: u64,
    #[serde(rename = "skSeed")]
    pub sk_seed: String,
    #[serde(rename = "skPrf")]
    pub sk_prf: String,
    #[serde(rename = "pkSeed")]
    pub pk_seed: String,
}

//
// prompt.json - end
//

//
// expectedResults.json - start
//

#[derive(Debug, Deserialize)]
pub struct SLHDSAKEYGENERTestGroup {
    #[serde(rename = "tgId")]
    pub tg_id: u64,
    pub tests: Vec<SLHDSAKEYGENERTestCase>,
}

#[derive(Debug, Deserialize)]
pub struct SLHDSAKEYGENERTestCase {
    #[serde(rename = "tcId")]
    pub tc_id: u64,
    pub sk: String,
    pub pk: String,
}

//
// prompt.json - end
//

//
// Response - start
//

#[derive(Debug, Serialize)]
pub struct SLHDSAKEYGENResponseTestGroup {
    #[serde(rename = "tgId")]
    pub tg_id: u64,
    pub tests: Vec<SLHDSAKEYGENResponseTestCase>,
}

#[derive(Debug, Serialize)]
pub struct SLHDSAKEYGENResponseTestCase {
    #[serde(rename = "tcId")]
    pub tc_id: u64,
    pub sk: String,
    pub pk: String,
}

//
// Response - end
//