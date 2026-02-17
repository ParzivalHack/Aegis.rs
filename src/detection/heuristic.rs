use crate::config::{RulesConfig, DetectionConfig};
use crate::detection::models::{DetectionResult, AttackType, Severity, DetectionLayer};
use crate::errors::AegisError;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs;
use std::sync::Arc;
use parking_lot::RwLock as ParkingLotRwLock;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Rule {
    pub name: String,
    pub category: String,
    pub severity: String,
    pub detection_method: String,
    pub pattern: String,
    #[serde(default)]
    pub context_check: Option<String>,
    pub enabled: bool,
}

pub struct HeuristicEngine {
    rules: Arc<ParkingLotRwLock<Vec<CompiledRule>>>,
    rules_path: String,
    config: ParkingLotRwLock<DetectionConfig>,
}

struct CompiledRule {
    rule: Rule,
    regex: Option<Regex>,
}

impl HeuristicEngine {
    pub fn new(rules_config: &RulesConfig, detection_config: &DetectionConfig) -> Result<Self, AegisError> {
        let rules = Self::load_rules(&rules_config.rules_file_path)?;
        
        Ok(Self {
            rules: Arc::new(ParkingLotRwLock::new(rules)),
            rules_path: rules_config.rules_file_path.clone(),
            config: ParkingLotRwLock::new(detection_config.clone()),
        })
    }

    pub fn refresh_configuration(&self, detection_config: &DetectionConfig) {
        let mut config = self.config.write();
        *config = detection_config.clone();
    }

    pub fn get_all_rules(&self) -> Vec<Rule> {
        self.rules.read().iter().map(|cr| cr.rule.clone()).collect()
    }

    pub fn upsert_rule(&self, rule: Rule) -> Result<(), AegisError> {
        let mut compiled_rules = self.rules.write();
        
        let regex = if rule.detection_method.to_lowercase().contains("regex") && rule.enabled {
            let pattern = if rule.pattern.starts_with("(?i)") {
                rule.pattern.clone()
            } else {
                format!("(?i){}", rule.pattern)
            };
            
            Some(Regex::new(&pattern)
                .map_err(|e| AegisError::ConfigError(format!("Invalid regex in rule '{}': {}", rule.name, e)))?)
        } else {
            None
        };

        let new_cr = CompiledRule { rule: rule.clone(), regex };

        if let Some(pos) = compiled_rules.iter().position(|r| r.rule.name == rule.name) {
            compiled_rules[pos] = new_cr;
        } else {
            compiled_rules.push(new_cr);
        }

        self.save_rules(&compiled_rules)
    }

    pub fn delete_rule(&self, name: &str) -> Result<(), AegisError> {
        let mut rules = self.rules.write();
        let len_before = rules.len();
        rules.retain(|r| r.rule.name != name);
        if rules.len() == len_before {
            return Err(AegisError::ConfigError(format!("Rule not found: {}", name)));
        }
        self.save_rules(&rules)
    }

    fn save_rules(&self, compiled_rules: &[CompiledRule]) -> Result<(), AegisError> {
        let rules: Vec<Rule> = compiled_rules.iter().map(|cr| cr.rule.clone()).collect();
        let content = toml::to_string(&serde_json::json!({ "rules": rules }))
            .map_err(|e| AegisError::ConfigError(format!("Failed to serialize rules: {}", e)))?;
        
        fs::write(&self.rules_path, content)
            .map_err(|e| AegisError::ConfigError(format!("Failed to write rules file: {}", e)))?;
        
        Ok(())
    }

    fn load_rules(path: &str) -> Result<Vec<CompiledRule>, AegisError> {
        let content = fs::read_to_string(path)
            .map_err(|e| AegisError::RuleLoadError(format!("Failed to read rules file: {}", e)))?;
        
        #[derive(Deserialize)]
        struct RulesFile {
            rules: Vec<Rule>,
        }
        
        let rules_file: RulesFile = toml::from_str(&content)
            .map_err(|e| AegisError::RuleLoadError(format!("Failed to parse rules file: {}", e)))?;
        
        let mut compiled_rules = Vec::new();
        for rule in rules_file.rules {
            let regex = if rule.detection_method.to_lowercase().contains("regex") && rule.enabled {
                let pattern = if rule.pattern.starts_with("(?i)") {
                    rule.pattern.clone()
                } else {
                    format!("(?i){}", rule.pattern)
                };
                
                Some(Regex::new(&pattern)
                    .map_err(|e| AegisError::RuleLoadError(format!("Invalid regex in rule '{}': {}", rule.name, e)))?)
            } else {
                None
            };
            
            compiled_rules.push(CompiledRule { rule, regex });
        }
        
        Ok(compiled_rules)
    }

    pub fn analyze(&self, payload: &str) -> Result<DetectionResult, AegisError> {
        let rules = self.rules.read();
        let mut matched_rules = Vec::new();
        let mut highest_severity = Severity::Low;
        let mut attack_type = AttackType::None;

        let normalized_payload = if self.config.read().normalize_unicode {
            self.normalize_unicode(payload)
        } else {
            payload.to_string()
        };

        for prefix in &self.config.read().safe_prefixes {
            if normalized_payload.starts_with(prefix) {
                return Ok(DetectionResult::safe(DetectionLayer::Heuristic));
            }
        }

        for compiled_rule in rules.iter() {
            let rule = &compiled_rule.rule;
            if !rule.enabled { continue; }

            let is_match = if let Some(ref regex) = compiled_rule.regex {
                regex.is_match(&normalized_payload)
            } else {
                let pattern = if self.config.read().case_insensitive {
                    rule.pattern.to_lowercase()
                } else {
                    rule.pattern.clone()
                };
                
                let search_text = if self.config.read().case_insensitive {
                    normalized_payload.to_lowercase()
                } else {
                    normalized_payload.clone()
                };
                
                search_text.contains(&pattern)
            };

            if is_match {
                if let Some(ref context) = rule.context_check {
                    let context_lower = context.to_lowercase();
                    if !normalized_payload.to_lowercase().contains(&context_lower) {
                        continue;
                    }
                }

                matched_rules.push(rule.name.clone());
                let severity = Severity::from_str(&rule.severity);
                
                if matches!(severity, Severity::Critical) || 
                   (matches!(severity, Severity::High) && !matches!(highest_severity, Severity::Critical)) ||
                   (matches!(severity, Severity::Medium) && matches!(highest_severity, Severity::Low)) {
                    highest_severity = severity;
                    attack_type = AttackType::from_str(&rule.category);
                }
            }
        }

        if !matched_rules.is_empty() {
            let min_severity = Severity::from_str(&self.config.read().min_block_severity);
            let should_block = match (highest_severity, min_severity) {
                (Severity::Critical, _) => true,
                (Severity::High, Severity::Critical) => false,
                (Severity::High, _) => true,
                (Severity::Medium, Severity::Critical | Severity::High) => false,
                (Severity::Medium, _) => true,
                (Severity::Low, Severity::Low) => true,
                (Severity::Low, _) => false,
            };

            let always_block = self.config.read().always_block_categories.iter()
                .any(|cat| cat.to_lowercase() == attack_type.to_str());

            if should_block || always_block {
                Ok(DetectionResult::malicious(
                    attack_type,
                    0.9,
                    format!("Matched {} rule(s): {}", matched_rules.len(), matched_rules.join(", ")),
                    DetectionLayer::Heuristic,
                    matched_rules,
                    highest_severity,
                ))
            } else {
                Ok(DetectionResult::ambiguous(
                    format!("Low-severity matches: {}", matched_rules.join(", ")),
                    DetectionLayer::Heuristic,
                ))
            }
        } else {
            Ok(DetectionResult::safe(DetectionLayer::Heuristic))
        }
    }

    fn normalize_unicode(&self, text: &str) -> String {
        text.chars()
            .map(|c| match c {
                'а' | 'А' => 'a',
                'е' | 'Е' => 'e',
                'о' | 'О' => 'o',
                'р' | 'Р' => 'p',
                'с' | 'С' => 'c',
                _ => c,
            })
            .collect()
    }

    pub fn reload_rules(&self) -> Result<(), AegisError> {
        let new_rules = Self::load_rules(&self.rules_path)?;
        let mut rules = self.rules.write();
        *rules = new_rules;
        log::info!("Rules reloaded successfully");
        Ok(())
    }
}
