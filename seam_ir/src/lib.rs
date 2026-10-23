use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub const FORMAT: &str = "seam.contract@1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeamContract {
    pub format: String,
    pub name: String,
    pub version: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub boundaries: Vec<SeamBoundary>,
    pub definitions: Vec<SeamDefinition>,
}

impl SeamContract {
    pub fn new(name: impl Into<String>, version: u32) -> Self {
        Self {
            format: FORMAT.to_string(),
            name: name.into(),
            version,
            boundaries: Vec::new(),
            definitions: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeamBoundary {
    pub function: String,
    pub request: String,
    pub response: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum SeamDefinition {
    Record(SeamRecord),
    Enum(SeamEnum),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeamRecord {
    pub name: String,
    pub fields: BTreeMap<String, SeamType>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeamEnum {
    pub name: String,
    pub variants: Vec<SeamEnumVariant>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeamEnumVariant {
    pub name: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, SeamType>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum SeamType {
    Primitive {
        name: SeamPrimitive,
    },
    Named {
        name: String,
    },
    Option {
        item: Box<SeamType>,
    },
    List {
        item: Box<SeamType>,
    },
    Map {
        key: Box<SeamType>,
        value: Box<SeamType>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SeamPrimitive {
    String,
    Int,
    Bool,
    Bytes,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seam_contract_round_trips_json() {
        let mut contract = SeamContract::new("handle", 1);
        contract.boundaries.push(SeamBoundary {
            function: "handle".to_string(),
            request: "Request".to_string(),
            response: "Response".to_string(),
        });

        let mut fields = BTreeMap::new();
        fields.insert(
            "body".to_string(),
            SeamType::Option {
                item: Box::new(SeamType::Primitive {
                    name: SeamPrimitive::String,
                }),
            },
        );
        contract
            .definitions
            .push(SeamDefinition::Record(SeamRecord {
                name: "Request".to_string(),
                fields,
            }));

        let json = serde_json::to_string_pretty(&contract).unwrap();
        let decoded: SeamContract = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, contract);
    }
}
