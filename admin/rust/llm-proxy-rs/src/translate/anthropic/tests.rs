#![cfg(test)]

use super::*;
use serde_json::json;

// ── Request translation tests ──────────────────────────────────────

#[test]
fn system_messages_extracted_to_top_level_and_concatenated() {
    let body = json!({
        "model": "claude-sonnet-4-7",
        "messages": [
            {"role": "system", "content": "be terse"},
            {"role": "system", "content": "no markdown"},
            {"role": "user", "content": "hi"}
        ]
    });
    let out = to_anthropic_request(&body);
    assert_eq!(out["system"], "be terse\n\nno markdown");
    assert_eq!(out["messages"].as_array().unwrap().len(), 1);
    assert_eq!(out["messages"][0]["role"], "user");
    assert_eq!(out["messages"][0]["content"], "hi");
}

#[test]
fn max_tokens_required_field_defaulted_when_omitted() {
    let body = json!({"model": "x", "messages": [{"role": "user", "content": "hi"}]});
    let out = to_anthropic_request(&body);
    assert_eq!(out["max_tokens"], DEFAULT_MAX_TOKENS);
}

#[test]
fn max_tokens_preserved_from_openai_request() {
    let body = json!({
        "model": "x",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 250
    });
    let out = to_anthropic_request(&body);
    assert_eq!(out["max_tokens"], 250);
}

#[test]
fn max_completion_tokens_is_an_accepted_alias() {
    // OpenAI's newer "max_completion_tokens" alias should be picked
    // up too. (Many clients use one or the other interchangeably.)
    let body = json!({
        "model": "x",
        "messages": [{"role": "user", "content": "hi"}],
        "max_completion_tokens": 999
    });
    let out = to_anthropic_request(&body);
    assert_eq!(out["max_tokens"], 999);
}

#[test]
fn stop_string_becomes_array_in_anthropic() {
    let body = json!({
        "model": "x",
        "messages": [{"role": "user", "content": "hi"}],
        "stop": "\n\n"
    });
    let out = to_anthropic_request(&body);
    assert_eq!(out["stop_sequences"], json!(["\n\n"]));
}

#[test]
fn stop_array_passes_through() {
    let body = json!({
        "model": "x",
        "messages": [{"role": "user", "content": "hi"}],
        "stop": ["a", "b"]
    });
    let out = to_anthropic_request(&body);
    assert_eq!(out["stop_sequences"], json!(["a", "b"]));
}

#[test]
fn openai_only_fields_dropped() {
    let body = json!({
        "model": "x",
        "messages": [{"role": "user", "content": "hi"}],
        "presence_penalty": 0.5,
        "frequency_penalty": 0.2,
        "n": 2,
        "service_tier": "priority"
    });
    let out = to_anthropic_request(&body);
    assert!(out.get("presence_penalty").is_none());
    assert!(out.get("frequency_penalty").is_none());
    assert!(out.get("n").is_none());
    assert!(out.get("service_tier").is_none());
}

#[test]
fn tool_role_message_becomes_user_with_tool_result_block() {
    let body = json!({
        "model": "x",
        "messages": [
            {"role": "user", "content": "use a tool"},
            {"role": "assistant", "content": null, "tool_calls": [{
                "id": "call_abc",
                "type": "function",
                "function": {"name": "get_weather", "arguments": "{\"loc\":\"SF\"}"}
            }]},
            {"role": "tool", "tool_call_id": "call_abc", "content": "sunny"}
        ]
    });
    let out = to_anthropic_request(&body);
    let messages = out["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 3);

    // Assistant message has the tool_use content block.
    assert_eq!(messages[1]["role"], "assistant");
    let asst_content = messages[1]["content"].as_array().unwrap();
    let tool_use = asst_content
        .iter()
        .find(|b| b["type"] == "tool_use")
        .unwrap();
    assert_eq!(tool_use["id"], "call_abc");
    assert_eq!(tool_use["name"], "get_weather");
    // Arguments string parsed back into a JSON object (Anthropic wants object).
    assert_eq!(tool_use["input"], json!({"loc": "SF"}));

    // Tool result becomes a user message with a tool_result block.
    assert_eq!(messages[2]["role"], "user");
    let res_content = messages[2]["content"].as_array().unwrap();
    assert_eq!(res_content[0]["type"], "tool_result");
    assert_eq!(res_content[0]["tool_use_id"], "call_abc");
    assert_eq!(res_content[0]["content"], "sunny");
}

#[test]
fn tools_array_translated_function_to_anthropic_shape() {
    let body = json!({
        "model": "x",
        "messages": [{"role": "user", "content": "hi"}],
        "tools": [{
            "type": "function",
            "function": {
                "name": "lookup",
                "description": "look something up",
                "parameters": {"type": "object", "properties": {"q": {"type": "string"}}}
            }
        }]
    });
    let out = to_anthropic_request(&body);
    let tools = out["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0]["name"], "lookup");
    assert_eq!(tools[0]["description"], "look something up");
    // Note: input_schema (Anthropic) vs parameters (OpenAI).
    assert_eq!(tools[0]["input_schema"]["type"], "object");
    assert!(tools[0].get("parameters").is_none());
    assert!(tools[0].get("function").is_none());
}

#[test]
fn tool_choice_string_translates_to_anthropic_object() {
    let mut body = json!({
        "model": "x",
        "messages": [{"role": "user", "content": "hi"}],
        "tool_choice": "auto"
    });
    let out = to_anthropic_request(&body);
    assert_eq!(out["tool_choice"], json!({"type": "auto"}));

    body["tool_choice"] = json!("required");
    let out = to_anthropic_request(&body);
    assert_eq!(out["tool_choice"], json!({"type": "any"}));

    // "none" → no tool_choice field at all.
    body["tool_choice"] = json!("none");
    let out = to_anthropic_request(&body);
    assert!(out.get("tool_choice").is_none());
}

#[test]
fn tool_choice_function_specifier_becomes_named_tool() {
    let body = json!({
        "model": "x",
        "messages": [{"role": "user", "content": "hi"}],
        "tool_choice": {"type": "function", "function": {"name": "lookup"}}
    });
    let out = to_anthropic_request(&body);
    assert_eq!(
        out["tool_choice"],
        json!({"type": "tool", "name": "lookup"})
    );
}

#[test]
fn user_content_parts_array_passes_through_as_anthropic_blocks() {
    // OpenAI sends content as array of {type:text, text:...} parts.
    // Anthropic also accepts an array of blocks; pass through verbatim
    // so vision/multimodal works (image blocks etc.).
    let body = json!({
        "model": "x",
        "messages": [{
            "role": "user",
            "content": [
                {"type": "text", "text": "describe this"},
                {"type": "image_url", "image_url": {"url": "data:..."}}
            ]
        }]
    });
    let out = to_anthropic_request(&body);
    let msg = &out["messages"][0];
    assert_eq!(msg["role"], "user");
    // We pass content through unchanged for user role — Anthropic
    // parses its own array form.
    assert!(msg["content"].is_array());
}

// ── Response translation tests ─────────────────────────────────────

#[test]
fn text_only_response_becomes_string_content_choice() {
    let resp = json!({
        "id": "msg_abc",
        "type": "message",
        "model": "claude-sonnet-4-7",
        "content": [{"type": "text", "text": "hello"}],
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 12, "output_tokens": 7}
    });
    let out = from_anthropic_response(&resp, "claude-sonnet-4-7");
    assert_eq!(out["object"], "chat.completion");
    assert_eq!(out["choices"][0]["message"]["role"], "assistant");
    assert_eq!(out["choices"][0]["message"]["content"], "hello");
    assert_eq!(out["choices"][0]["finish_reason"], "stop");
    assert_eq!(out["usage"]["prompt_tokens"], 12);
    assert_eq!(out["usage"]["completion_tokens"], 7);
    assert_eq!(out["usage"]["total_tokens"], 19);
    // id contains chatcmpl- prefix (from msg_ prefix substitution).
    assert!(
        out["id"].as_str().unwrap().starts_with("chatcmpl-"),
        "id = {}",
        out["id"]
    );
}

#[test]
fn tool_use_response_becomes_tool_calls_with_arguments_serialised() {
    let resp = json!({
        "id": "msg_xyz",
        "model": "claude-opus-4-7",
        "content": [{
            "type": "tool_use",
            "id": "toolu_1",
            "name": "lookup",
            "input": {"q": "weather", "limit": 5}
        }],
        "stop_reason": "tool_use",
        "usage": {"input_tokens": 30, "output_tokens": 18}
    });
    let out = from_anthropic_response(&resp, "claude-opus-4-7");
    let msg = &out["choices"][0]["message"];
    assert_eq!(msg["role"], "assistant");
    assert_eq!(
        msg["content"],
        Value::Null,
        "content should be null when only tool calls"
    );
    let tcs = msg["tool_calls"].as_array().unwrap();
    assert_eq!(tcs.len(), 1);
    assert_eq!(tcs[0]["id"], "toolu_1");
    assert_eq!(tcs[0]["type"], "function");
    assert_eq!(tcs[0]["function"]["name"], "lookup");
    // OpenAI requires arguments as a STRING (JSON-encoded), not an object.
    let args = tcs[0]["function"]["arguments"].as_str().unwrap();
    let parsed: Value = serde_json::from_str(args).unwrap();
    assert_eq!(parsed, json!({"q": "weather", "limit": 5}));

    assert_eq!(out["choices"][0]["finish_reason"], "tool_calls");
}

#[test]
fn mixed_text_and_tool_use_keeps_both() {
    let resp = json!({
        "id": "msg_mixed",
        "model": "claude-opus-4-7",
        "content": [
            {"type": "text", "text": "Let me look that up. "},
            {"type": "tool_use", "id": "t1", "name": "lookup", "input": {}}
        ],
        "stop_reason": "tool_use",
        "usage": {"input_tokens": 1, "output_tokens": 1}
    });
    let out = from_anthropic_response(&resp, "claude-opus-4-7");
    let msg = &out["choices"][0]["message"];
    assert_eq!(msg["content"], "Let me look that up. ");
    assert_eq!(msg["tool_calls"].as_array().unwrap().len(), 1);
}

#[test]
fn stop_reason_mapping_covers_all_variants() {
    assert_eq!(map_stop_reason(Some("end_turn")), "stop");
    assert_eq!(map_stop_reason(Some("stop_sequence")), "stop");
    assert_eq!(map_stop_reason(Some("max_tokens")), "length");
    assert_eq!(map_stop_reason(Some("tool_use")), "tool_calls");
    assert_eq!(map_stop_reason(None), "stop");
    // Unknown future reasons fall back to "stop" rather than failing.
    assert_eq!(map_stop_reason(Some("future_reason")), "stop");
}

#[test]
fn usage_missing_yields_zero_counts_not_a_panic() {
    let resp = json!({"id": "msg_x", "model": "m", "content": []});
    let out = from_anthropic_response(&resp, "m");
    assert_eq!(out["usage"]["prompt_tokens"], 0);
    assert_eq!(out["usage"]["completion_tokens"], 0);
    assert_eq!(out["usage"]["total_tokens"], 0);
}

// ── Streaming translator tests ─────────────────────────────────────

fn parse_data_frame(frame: &str) -> Value {
    let stripped = frame.trim_start_matches("data: ").trim_end_matches("\n\n");
    if stripped == "[DONE]" {
        return json!("[DONE]");
    }
    serde_json::from_str(stripped).unwrap()
}

#[test]
fn streaming_text_only_emits_role_then_content_deltas_then_stop() {
    let mut t = SseTranslator::new("claude-sonnet-4-7");
    let mut out = Vec::new();
    out.extend(t.translate_event(&json!({"type": "message_start", "message": {}})));
    out.extend(t.translate_event(
        &json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text"}}),
    ));
    out.extend(t.translate_event(&json!({
        "type": "content_block_delta", "index": 0,
        "delta": {"type": "text_delta", "text": "hi "}
    })));
    out.extend(t.translate_event(&json!({
        "type": "content_block_delta", "index": 0,
        "delta": {"type": "text_delta", "text": "there"}
    })));
    out.extend(t.translate_event(&json!({"type": "content_block_stop", "index": 0})));
    out.extend(t.translate_event(&json!({
        "type": "message_delta", "delta": {"stop_reason": "end_turn"}
    })));
    out.extend(t.translate_event(&json!({"type": "message_stop"})));

    // Frames: role + 2 content deltas + stop chunk + [DONE]
    assert_eq!(out.len(), 5, "got frames: {out:?}");
    let role = parse_data_frame(&out[0]);
    assert_eq!(role["choices"][0]["delta"]["role"], "assistant");
    let d0 = parse_data_frame(&out[1]);
    assert_eq!(d0["choices"][0]["delta"]["content"], "hi ");
    let d1 = parse_data_frame(&out[2]);
    assert_eq!(d1["choices"][0]["delta"]["content"], "there");
    let stop = parse_data_frame(&out[3]);
    assert_eq!(stop["choices"][0]["finish_reason"], "stop");
    assert_eq!(out[4], "data: [DONE]\n\n");
}

#[test]
fn streaming_tool_use_emits_function_args_incrementally() {
    let mut t = SseTranslator::new("claude-opus-4-7");
    let mut out = Vec::new();
    out.extend(t.translate_event(&json!({"type": "message_start", "message": {}})));
    // Content block 0: tool_use.
    out.extend(t.translate_event(&json!({
        "type": "content_block_start", "index": 0,
        "content_block": {"type": "tool_use", "id": "toolu_1", "name": "lookup", "input": {}}
    })));
    // Incremental JSON.
    out.extend(t.translate_event(&json!({
        "type": "content_block_delta", "index": 0,
        "delta": {"type": "input_json_delta", "partial_json": "{\"q\":\"weath"}
    })));
    out.extend(t.translate_event(&json!({
        "type": "content_block_delta", "index": 0,
        "delta": {"type": "input_json_delta", "partial_json": "er\"}"}
    })));
    out.extend(t.translate_event(&json!({"type": "content_block_stop", "index": 0})));
    out.extend(t.translate_event(&json!({
        "type": "message_delta", "delta": {"stop_reason": "tool_use"}
    })));
    out.extend(t.translate_event(&json!({"type": "message_stop"})));

    // Frames: role, tool_call start (id/name), 2 args deltas, stop, [DONE]
    assert_eq!(out.len(), 6, "got frames: {out:?}");
    let role = parse_data_frame(&out[0]);
    assert_eq!(role["choices"][0]["delta"]["role"], "assistant");

    let call_start = parse_data_frame(&out[1]);
    let tc = &call_start["choices"][0]["delta"]["tool_calls"][0];
    assert_eq!(tc["index"], 0);
    assert_eq!(tc["id"], "toolu_1");
    assert_eq!(tc["type"], "function");
    assert_eq!(tc["function"]["name"], "lookup");
    assert_eq!(tc["function"]["arguments"], "");

    let args_a = parse_data_frame(&out[2]);
    assert_eq!(
        args_a["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"],
        "{\"q\":\"weath"
    );
    let args_b = parse_data_frame(&out[3]);
    assert_eq!(
        args_b["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"],
        "er\"}"
    );

    let stop = parse_data_frame(&out[4]);
    assert_eq!(stop["choices"][0]["finish_reason"], "tool_calls");
    assert_eq!(out[5], "data: [DONE]\n\n");
}

#[test]
fn streaming_finish_synthesises_done_when_upstream_cuts_off() {
    let mut t = SseTranslator::new("m");
    // Start a stream but never get to message_stop.
    let _ = t.translate_event(&json!({"type": "message_start", "message": {}}));
    let _ = t.translate_event(&json!({
        "type": "content_block_start", "index": 0, "content_block": {"type": "text"}
    }));
    let _ = t.translate_event(&json!({
        "type": "content_block_delta", "index": 0,
        "delta": {"type": "text_delta", "text": "partial"}
    }));
    let trailing = t.finish();
    // The translator must produce a terminal chunk + [DONE] so clients
    // don't hang waiting for end-of-stream.
    let last = parse_data_frame(trailing.last().unwrap());
    assert_eq!(last, json!("[DONE]"));
    let stop = parse_data_frame(&trailing[trailing.len() - 2]);
    assert_eq!(stop["choices"][0]["finish_reason"], "stop");
}

#[test]
fn streaming_translator_is_idempotent_after_done() {
    let mut t = SseTranslator::new("m");
    let _ = t.translate_event(&json!({"type": "message_start"}));
    let _ = t.translate_event(&json!({"type": "message_stop"}));
    // Further events after [DONE] are silently ignored — no extra
    // frames, no panic.
    let more = t.translate_event(&json!({"type": "content_block_delta"}));
    assert!(more.is_empty());
    let more = t.finish();
    assert!(more.is_empty());
}
