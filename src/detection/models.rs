use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Safe,
    Malicious,
    Ambiguous,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackType {
    PromptInjection,
    IndirectPromptInjection,
    Jailbreak,
    DataPoisoning,
    SystemLeakage,
    PIILeakage,
    EncodingObfuscation,
    None,
}

impl AttackType {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "promptinjection" | "prompt_injection" => AttackType::PromptInjection,
            "indirectpromptinjection" | "indirect_prompt_injection" => AttackType::IndirectPromptInjection,
            "jailbreak" => AttackType::Jailbreak,
            "datapoisoning" | "data_poisoning" => AttackType::DataPoisoning,
            "systemleakage" | "system_leakage" => AttackType::SystemLeakage,
            "piileakage" | "pii_leakage" => AttackType::PIILeakage,
            "encodingobfuscation" | "encoding_obfuscation" => AttackType::EncodingObfuscation,
            _ => AttackType::None,
        }
    }

    pub fn to_str(&self) -> &'static str {
        match self {
            AttackType::PromptInjection => "prompt_injection",
            AttackType::IndirectPromptInjection => "indirect_prompt_injection",
            AttackType::Jailbreak => "jailbreak",
            AttackType::DataPoisoning => "data_poisoning",
            AttackType::SystemLeakage => "system_leakage",
            AttackType::PIILeakage => "pii_leakage",
            AttackType::EncodingObfuscation => "encoding_obfuscation",
            AttackType::None => "none",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "low" => Severity::Low,
            "medium" => Severity::Medium,
            "high" => Severity::High,
            "critical" => Severity::Critical,
            _ => Severity::Low,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DetectionLayer {
    Heuristic,
    AIJudge,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    pub verdict: Verdict,
    pub attack_type: AttackType,
    pub confidence: f64,
    pub reasoning: String,
    pub layer: DetectionLayer,
    pub matched_rules: Vec<String>,
    pub severity: Severity,
}

impl DetectionResult {
    pub fn safe(layer: DetectionLayer) -> Self {
        Self {
            verdict: Verdict::Safe,
            attack_type: AttackType::None,
            confidence: 1.0,
            reasoning: "No malicious patterns detected".to_string(),
            layer,
            matched_rules: vec![],
            severity: Severity::Low,
        }
    }

    pub fn malicious(
        attack_type: AttackType,
        confidence: f64,
        reasoning: String,
        layer: DetectionLayer,
        matched_rules: Vec<String>,
        severity: Severity,
    ) -> Self {
        Self {
            verdict: Verdict::Malicious,
            attack_type,
            confidence,
            reasoning,
            layer,
            matched_rules,
            severity,
        }
    }

    pub fn ambiguous(reasoning: String, layer: DetectionLayer) -> Self {
        Self {
            verdict: Verdict::Ambiguous,
            attack_type: AttackType::None,
            confidence: 0.5,
            reasoning,
            layer,
            matched_rules: vec![],
            severity: Severity::Low,
        }
    }
}
