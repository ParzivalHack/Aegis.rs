use crate::config::AIJudgeConfig;
use crate::detection::models::{DetectionResult, AttackType, Verdict, DetectionLayer, Severity};
use crate::errors::AegisError;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Serialize)]
struct AIJudgeRequest {
    model: String,
    messages: Vec<Message>,
    max_tokens: u32,
    temperature: f32,
}

#[derive(Debug, Serialize, Deserialize)]
struct Message {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct AIJudgeResponse {
    choices: Vec<Choice>,
}

#[derive(Debug, Deserialize)]
struct Choice {
    message: Message,
}

#[derive(Debug, Deserialize)]
struct JudgeVerdict {
    verdict: String,
    attack_type: String,
    confidence: f64,
    #[serde(alias = "reason")]
    reasoning: String,
}

pub struct AIJudgeClient {
    config: AIJudgeConfig,
    client: reqwest::Client,
}

impl AIJudgeClient {
    pub fn new(config: &AIJudgeConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms))
            .build()
            .unwrap();

        Self {
            config: config.clone(),
            client,
        }
    }

    pub async fn analyze(&self, payload: &str) -> Result<DetectionResult, AegisError> {
        let mut retries = 0;
        let mut last_error = None;

        while retries <= self.config.max_retries {
            match self.try_analyze(payload).await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    last_error = Some(e);
                    if retries < self.config.max_retries {
                        let delay = self.config.base_retry_delay_ms * 2_u64.pow(retries);
                        tokio::time::sleep(Duration::from_millis(delay)).await;
                    }
                    retries += 1;
                }
            }
        }

        Err(last_error.unwrap_or_else(|| AegisError::AIJudgeError("Unknown error".to_string())))
    }

    async fn try_analyze(&self, payload: &str) -> Result<DetectionResult, AegisError> {
        let request = AIJudgeRequest {
            model: self.config.model.clone(),
            messages: vec![
                Message {
                    role: "system".to_string(),
                    content: self.config.system_prompt.clone(),
                },
                Message {
                    role: "user".to_string(),
                    content: payload.to_string(),
                },
            ],
            max_tokens: self.config.max_tokens,
            temperature: self.config.temperature,
        };

        let response = self.client
            .post(&self.config.endpoint)
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .map_err(|e| AegisError::AIJudgeError(format!("Request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(AegisError::AIJudgeError(format!(
                "API returned status {}: {}",
                response.status(),
                response.text().await.unwrap_or_default()
            )));
        }

        let ai_response: AIJudgeResponse = response
            .json()
            .await
            .map_err(|e| AegisError::AIJudgeError(format!("Failed to parse response: {}", e)))?;

        let content = ai_response
            .choices
            .first()
            .ok_or_else(|| AegisError::AIJudgeError("No choices in response".to_string()))?
            .message
            .content
            .clone();

        log::debug!("AI Judge raw response: {}", content);

        // Attempt to find JSON block in the response if it's wrapped in markdown
        let json_str = if let Some(start) = content.find('{') {
            if let Some(end) = content.rfind('}') {
                &content[start..=end]
            } else {
                &content
            }
        } else {
            &content
        };

        // Parse the JSON verdict. Fallback to JSON5 for slightly non-strict model outputs
        // (single quotes, trailing commas, etc.).
        let verdict: JudgeVerdict = match serde_json::from_str(json_str) {
            Ok(v) => v,
            Err(json_err) => json5::from_str(json_str).map_err(|json5_err| {
                log::error!(
                    "Failed to parse verdict JSON (strict: {}; json5: {}). Raw content: {}",
                    json_err,
                    json5_err,
                    content
                );
                AegisError::AIJudgeError(format!(
                    "Failed to parse verdict JSON (strict: {}; json5: {})",
                    json_err, json5_err
                ))
            })?,
        };

        let result_verdict = match verdict.verdict.to_lowercase().as_str() {
            "safe" => Verdict::Safe,
            "malicious" => Verdict::Malicious,
            "ambiguous" => Verdict::Ambiguous,
            _ => Verdict::Ambiguous,
        };

        let attack_type = AttackType::from_str(&verdict.attack_type);
        
        log::info!("AI Judge result: {:?} (Confidence: {:.2})", result_verdict, verdict.confidence);

        Ok(DetectionResult {
            verdict: result_verdict,
            attack_type,
            confidence: verdict.confidence,
            reasoning: verdict.reasoning,
            layer: DetectionLayer::AIJudge,
            matched_rules: vec![],
            severity: if matches!(result_verdict, Verdict::Malicious) {
                Severity::High
            } else {
                Severity::Low
            },
        })
    }
}
