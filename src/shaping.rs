//! Generic RPC-response compression: the bounty's own "trap #3" — *"Do not
//! flood the context window... Judges will call `execute` and count
//! tokens."* Works on any [`serde_json::Value`] tree, not just one RPC
//! method's shape, truncating strings/arrays until it fits a token budget.

use serde_json::{json, Value};

/// Rough token estimate (~4 bytes/token), not exact billing.
pub fn estimate_tokens(s: &str) -> usize {
    s.len().div_ceil(4).max(1)
}

/// Presets tried least-to-most aggressive: `(max_array_items,
/// max_string_chars)`. Fixed set, not a search, so shaping stays bounded.
const AGGRESSIVENESS_LEVELS: &[(usize, usize)] = &[(20, 500), (10, 200), (5, 80), (3, 40), (1, 20)];

/// Shrinks `value` to fit `budget_tokens`, trying presets until one fits.
/// Falls back to the most aggressive preset if none do.
pub fn shape_for_budget(value: &Value, budget_tokens: usize) -> Value {
    let mut most_aggressive = value.clone();
    for &(max_items, max_chars) in AGGRESSIVENESS_LEVELS {
        let shaped = shape_json(value, max_items, max_chars);
        if estimate_tokens(&shaped.to_string()) <= budget_tokens {
            return shaped;
        }
        most_aggressive = shaped;
    }
    most_aggressive
}

/// Recursively truncates strings and arrays past the given limits;
/// truncated arrays append a `{"_truncated": true, "omitted_items": N}` marker.
pub fn shape_json(value: &Value, max_array_items: usize, max_string_chars: usize) -> Value {
    match value {
        Value::String(s) => Value::String(truncate_string(s, max_string_chars)),
        Value::Array(items) => {
            let mut shaped: Vec<Value> = items
                .iter()
                .take(max_array_items)
                .map(|v| shape_json(v, max_array_items, max_string_chars))
                .collect();
            if items.len() > max_array_items {
                shaped.push(json!({
                    "_truncated": true,
                    "omitted_items": items.len() - max_array_items,
                }));
            }
            Value::Array(shaped)
        }
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), shape_json(v, max_array_items, max_string_chars)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn truncate_string(s: &str, max_chars: usize) -> String {
    let total_chars = s.chars().count();
    if total_chars <= max_chars {
        return s.to_string();
    }
    let truncated: String = s.chars().take(max_chars).collect();
    format!("{truncated}…({total_chars} chars total)")
}

/// Formats lamports as a human/LLM-readable SOL amount, e.g.
/// `"1.234567891 SOL"` — the shape a channel message or tool-result should
/// carry instead of a bare `u64` the model has to mentally divide by 1e9.
pub fn format_sol(lamports: u64) -> String {
    format!("{:.9} SOL", lamports as f64 / 1_000_000_000.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_values_pass_through_unchanged() {
        let value = json!({"a": 1, "b": "short", "c": [1, 2, 3]});
        assert_eq!(shape_json(&value, 20, 500), value);
    }

    #[test]
    fn long_string_is_truncated_with_length_marker() {
        let long = "x".repeat(1000);
        let shaped = shape_json(&json!(long), 20, 100);
        let shaped_str = shaped.as_str().unwrap();
        assert!(shaped_str.starts_with(&"x".repeat(100)));
        assert!(shaped_str.contains("1000 chars total"));
    }

    #[test]
    fn long_array_keeps_prefix_and_marks_omitted_count() {
        let items: Vec<Value> = (0..50).map(Value::from).collect();
        let shaped = shape_json(&json!(items), 5, 500);
        let array = shaped.as_array().unwrap();
        assert_eq!(array.len(), 6); // 5 kept + 1 marker
        assert_eq!(array[0], json!(0));
        assert_eq!(array[4], json!(4));
        assert_eq!(array[5]["_truncated"], json!(true));
        assert_eq!(array[5]["omitted_items"], json!(45));
    }

    #[test]
    fn truncation_recurses_into_nested_objects_and_arrays() {
        let long = "y".repeat(1000);
        let value = json!({"nested": {"deep": [long]}});
        let shaped = shape_json(&value, 20, 50);
        let inner = shaped["nested"]["deep"][0].as_str().unwrap();
        assert!(inner.len() < 1000);
        assert!(inner.contains("1000 chars total"));
    }

    #[test]
    fn shape_for_budget_picks_the_least_aggressive_preset_that_fits() {
        let value = json!({"logs": ["line one", "line two"], "unitsConsumed": 150});
        let shaped = shape_for_budget(&value, 1000);
        assert_eq!(shaped, value);
    }

    #[test]
    fn shape_for_budget_shrinks_a_huge_array_to_fit() {
        // Simulates a raw getProgramAccounts-style dump too big for any budget.
        let entries: Vec<Value> = (0..5000)
            .map(|i| json!({"pubkey": format!("Address{i}"), "data": "x".repeat(200)}))
            .collect();
        let raw = json!(entries);
        assert!(estimate_tokens(&raw.to_string()) > 50_000);

        let shaped = shape_for_budget(&raw, 500);
        assert!(estimate_tokens(&shaped.to_string()) <= 500);
        // Still useful, not empty.
        let array = shaped.as_array().unwrap();
        assert!(!array.is_empty());
    }

    #[test]
    fn format_sol_divides_lamports_correctly() {
        assert_eq!(format_sol(1_000_000_000), "1.000000000 SOL");
        assert_eq!(format_sol(1_500_000), "0.001500000 SOL");
        assert_eq!(format_sol(0), "0.000000000 SOL");
    }

    #[test]
    fn estimate_tokens_has_a_floor_of_one_even_for_empty_input() {
        assert_eq!(estimate_tokens(""), 1);
        assert_eq!(estimate_tokens("a"), 1);
    }
}
