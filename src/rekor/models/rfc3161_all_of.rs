/*
 * Rekor
 *
 * Rekor is a cryptographically secure, immutable transparency log for signed software releases.
 *
 * The version of the OpenAPI document: 0.0.1
 *
 * Generated by: https://openapi-generator.tech
 */

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Default, Serialize, Deserialize)]
pub struct Rfc3161AllOf {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    #[serde(rename = "spec")]
    pub spec: serde_json::Value,
}

impl Rfc3161AllOf {
    pub fn new(api_version: String, spec: serde_json::Value) -> Rfc3161AllOf {
        Rfc3161AllOf { api_version, spec }
    }
}
