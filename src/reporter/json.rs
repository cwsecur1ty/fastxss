use anyhow::Result;
use std::path::Path;

use crate::reporter::finding::FindingCollection;

pub fn write_json_report(collection: &FindingCollection, output_path: &Path) -> Result<()> {
    let json = serde_json::to_string_pretty(collection.as_slice())?;
    std::fs::write(output_path, json)?;
    Ok(())
}

pub fn to_json_string(collection: &FindingCollection) -> Result<String> {
    Ok(serde_json::to_string_pretty(collection.as_slice())?)
}
