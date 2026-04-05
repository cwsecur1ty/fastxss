use crate::scanner::traits::Finding;

pub struct FindingCollection {
    findings: Vec<Finding>,
}

impl FindingCollection {
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
        }
    }

    pub fn add(&mut self, finding: Finding) {
        // Deduplicate by URL + injection point name + scanner type
        let exists = self.findings.iter().any(|f| {
            f.url == finding.url
                && f.injection_point.name == finding.injection_point.name
                && f.scanner_type == finding.scanner_type
        });

        if !exists {
            self.findings.push(finding);
        }
    }

    pub fn sorted(&self) -> Vec<&Finding> {
        let mut sorted: Vec<&Finding> = self.findings.iter().collect();
        sorted.sort_by(|a, b| b.severity.cmp(&a.severity));
        sorted
    }

    pub fn count(&self) -> usize {
        self.findings.len()
    }

    pub fn as_slice(&self) -> &[Finding] {
        &self.findings
    }

    pub fn count_by_severity(&self) -> SeverityCounts {
        let mut counts = SeverityCounts::default();
        for f in &self.findings {
            match f.severity {
                crate::scanner::traits::Severity::Critical => counts.critical += 1,
                crate::scanner::traits::Severity::High => counts.high += 1,
                crate::scanner::traits::Severity::Medium => counts.medium += 1,
                crate::scanner::traits::Severity::Low => counts.low += 1,
                crate::scanner::traits::Severity::Info => counts.info += 1,
            }
        }
        counts
    }
}

#[derive(Default)]
pub struct SeverityCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}
