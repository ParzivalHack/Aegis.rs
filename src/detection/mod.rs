pub mod models;
pub mod heuristic;
pub mod ai_judge;
pub mod decoder;

use crate::config::{Config, DetectionConfig};
use crate::errors::AegisError;
use models::{AttackType, DetectionLayer, DetectionResult, Severity, Verdict};
use std::sync::Arc;

pub struct DetectionPipeline {
    config: DetectionConfig,
    pub heuristic_engine: Arc<heuristic::HeuristicEngine>,
    ai_judge_client: Option<ai_judge::AIJudgeClient>,
}

impl DetectionPipeline {
    pub fn new(config: &Config) -> Result<Self, AegisError> {
        let heuristic_engine = Arc::new(heuristic::HeuristicEngine::new(&config.rules, &config.detection)?);
        
        let ai_judge_client = if !config.ai_judge.api_key.is_empty() && !config.detection.heuristic_only_mode {
            Some(ai_judge::AIJudgeClient::new(&config.ai_judge))
        } else {
            None
        };

        Ok(Self {
            config: config.detection.clone(),
            heuristic_engine,
            ai_judge_client,
        })
    }

    pub async fn analyze(&self, payload: &str) -> Result<DetectionResult, AegisError> {
        // Run heuristic engine first on raw payload
        let heuristic_result = self.heuristic_engine.analyze(payload)?;
        let heuristic_result = self.inspect_decoded_variants(payload, heuristic_result)?;

        // Extract clean prompt for AI analysis
        let clean_prompt = self.extract_prompt(payload);

        match heuristic_result.verdict {
            Verdict::Safe => {
                // If all_requests_ai_judge is enabled, route even safe requests through AI Judge
                if self.config.all_requests_ai_judge {
                    if let Some(ref ai_judge) = self.ai_judge_client {
                        match ai_judge.analyze(&clean_prompt).await {
                            Ok(ai_result) => {
                                if ai_result.confidence >= self.config.ai_judge_confidence_threshold {
                                    self.resolve_ambiguous_result(ai_result)
                                } else {
                                    Ok(heuristic_result)
                                }
                            }
                            Err(e) => {
                                log::warn!("AI Judge failed on safe request: {}, applying default ambiguous policy", e);
                                self.apply_default_policy(DetectionResult::ambiguous(
                                    format!("AI Judge unavailable while evaluating safe request: {}", e),
                                    models::DetectionLayer::AIJudge,
                                ))
                            }
                        }
                    } else {
                        Ok(heuristic_result)
                    }
                } else {
                    Ok(heuristic_result)
                }
            }
            Verdict::Malicious | Verdict::Ambiguous => {
                // If malicious or ambiguous, check if AI Judge is available for deeper analysis
                if let Some(ref ai_judge) = self.ai_judge_client {
                    match ai_judge.analyze(&clean_prompt).await {
                        Ok(ai_result) => {
                            // If heuristic said malicious, we might still want to stick with it 
                            // but use AI reasoning. If AI says safe but heuristic said malicious,
                            // we follow AI if confidence is high, or stick with heuristic if not.
                            
                            if matches!(heuristic_result.verdict, Verdict::Malicious) {
                                // If heuristic caught it, we keep it malicious but use richer AI reasoning if high confidence
                                if ai_result.confidence >= self.config.ai_judge_confidence_threshold {
                                    let mut final_result = ai_result;
                                    // Merge matched rules from heuristic
                                    final_result.matched_rules = heuristic_result.matched_rules;
                                    self.resolve_ambiguous_result(final_result)
                                } else {
                                    Ok(heuristic_result)
                                }
                            } else {
                                // Original ambiguous logic
                                if ai_result.confidence >= self.config.ai_judge_confidence_threshold {
                                    self.resolve_ambiguous_result(ai_result)
                                } else {
                                    self.apply_default_policy(heuristic_result)
                                }
                            }
                        }
                        Err(e) => {
                            log::warn!("AI Judge failed: {}, sticking with heuristic verdict", e);
                            // If heuristic said malicious, keep it. If ambiguous, apply policy.
                            if matches!(heuristic_result.verdict, Verdict::Malicious) {
                                Ok(heuristic_result)
                            } else {
                                self.apply_default_policy(heuristic_result)
                            }
                        }
                    }
                } else {
                    // No AI Judge configured, if it was malicious keep it, if ambiguous apply policy
                    if matches!(heuristic_result.verdict, Verdict::Malicious) {
                        Ok(heuristic_result)
                    } else {
                        self.apply_default_policy(heuristic_result)
                    }
                }
            }
        }
    }

    /// Extracted message contents from JSON payloads for cleaner AI analysis
    fn extract_prompt(&self, payload: &str) -> String {
        // Try to parse as common LLM request formats
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(payload) {
            // OpenAI/Groq format: { "messages": [ { "role": "user", "content": "..." } ] }
            if let Some(messages) = json.get("messages").and_then(|m| m.as_array()) {
                let mut full_prompt = String::new();
                for msg in messages {
                    if let Some(content) = msg.get("content").and_then(|c| c.as_str()) {
                        full_prompt.push_str(content);
                        full_prompt.push(' ');
                    }
                }
                if !full_prompt.is_empty() {
                    return full_prompt.trim().to_string();
                }
            }

            // Simple format: { "prompt": "..." }
            if let Some(prompt) = json.get("prompt").and_then(|p| p.as_str()) {
                return prompt.to_string();
            }

            // Simple format: { "input": "..." }
            if let Some(input) = json.get("input").and_then(|i| i.as_str()) {
                return input.to_string();
            }
        }

        // If not JSON or no recognized format, return raw payload
        payload.to_string()
    }

    fn apply_default_policy(&self, mut result: DetectionResult) -> Result<DetectionResult, AegisError> {
        match self.config.default_ambiguous_policy.as_str() {
            "block" => {
                result.verdict = Verdict::Malicious;
                result.reasoning = format!("Ambiguous request blocked by default policy: {}", result.reasoning);
            }
            "allow" => {
                result.verdict = Verdict::Safe;
                result.reasoning = format!("Ambiguous request allowed by default policy: {}", result.reasoning);
            }
            _ => {
                result.verdict = Verdict::Malicious;
            }
        }
        Ok(result)
    }

    fn resolve_ambiguous_result(&self, result: DetectionResult) -> Result<DetectionResult, AegisError> {
        if matches!(result.verdict, Verdict::Ambiguous) {
            self.apply_default_policy(result)
        } else {
            Ok(result)
        }
    }

    fn inspect_decoded_variants(
        &self,
        payload: &str,
        base_result: DetectionResult,
    ) -> Result<DetectionResult, AegisError> {
        if matches!(base_result.verdict, Verdict::Malicious) {
            return Ok(base_result);
        }

        let decoded_variants = decoder::Decoder::detect_and_decode(payload, 2);
        if decoded_variants.is_empty() {
            return Ok(base_result);
        }

        for (method, decoded_text) in decoded_variants {
            let decoded_result = self.heuristic_engine.analyze(&decoded_text)?;
            if matches!(decoded_result.verdict, Verdict::Malicious) {
                let mut matched_rules = decoded_result.matched_rules.clone();
                matched_rules.push(format!("decoded_via_{}", method));
                return Ok(DetectionResult::malicious(
                    AttackType::EncodingObfuscation,
                    decoded_result.confidence.max(0.92),
                    format!(
                        "Detected malicious content after {} decode: {}",
                        method, decoded_result.reasoning
                    ),
                    DetectionLayer::Heuristic,
                    matched_rules,
                    Severity::High,
                ));
            }
        }

        Ok(base_result)
    }

    pub fn reload_rules(&mut self) -> Result<(), AegisError> {
        self.heuristic_engine.reload_rules()
    }

    pub fn refresh_configuration(&mut self, config: &Config) {
        self.config = config.detection.clone();
        
        // Refresh heuristic engine
        self.heuristic_engine.refresh_configuration(&config.detection);
        
        // Re-initialize AI Judge client if key is now present
        self.ai_judge_client = if !config.ai_judge.api_key.is_empty() && !config.detection.heuristic_only_mode {
            Some(ai_judge::AIJudgeClient::new(&config.ai_judge))
        } else {
            None
        };
        
        log::info!("Detection pipeline configuration refreshed. Semantic active: {}", self.ai_judge_client.is_some());
    }

    pub fn is_semantic_active(&self) -> bool {
        self.ai_judge_client.is_some()
    }
}
