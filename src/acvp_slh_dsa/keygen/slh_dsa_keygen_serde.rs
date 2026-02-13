/*
 * Copyright (c) 2025-2026 Quant
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the “Software”),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

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
