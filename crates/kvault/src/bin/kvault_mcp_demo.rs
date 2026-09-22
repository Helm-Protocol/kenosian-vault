use std::collections::HashSet;
use std::io::{self, BufRead, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use kvault::tttps_bridge::{admit_with, PoTRecordV2, SystemState, POT_V2_LEN};
use serde_json::{json, Value};

const PROTOCOL_VERSION: &str = "2025-06-18";
const SERVER_NAME: &str = "kvault-tttps-demo";
const DISPERSION_US: u32 = 5_000_000;

struct DemoGate {
    state: SystemState,
    consumed_nonces: HashSet<[u8; 16]>,
    sequence: u64,
}

impl DemoGate {
    fn new() -> Self {
        Self {
            state: SystemState::default(),
            consumed_nonces: HashSet::new(),
            sequence: 0,
        }
    }

    fn issue_frame(&mut self) -> [u8; POT_V2_LEN] {
        self.sequence = self.sequence.wrapping_add(1);
        let now = now_us();
        let mut frame = [0u8; POT_V2_LEN];
        frame[0] = 0x02;
        frame[1] = 0x01;
        frame[2..4].copy_from_slice(&1u16.to_be_bytes());
        frame[4..12].copy_from_slice(&now.to_be_bytes());
        frame[12..16].copy_from_slice(&DISPERSION_US.to_be_bytes());
        frame[32..40].copy_from_slice(&self.sequence.to_be_bytes());
        frame[40..48].copy_from_slice(&now.to_be_bytes());
        frame
    }

    fn admit(&mut self, frame: &[u8]) -> Result<(), &'static str> {
        let now = now_us();
        let record = PoTRecordV2::try_from(frame).map_err(|_| "invalid_frame_size")?;
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&record.nonce);
        let result = admit_with(&mut self.state, frame, |r| {
            r.version == 0x02
                && r.alg_id_u16() == 1
                && r.ts_u64() <= now
                && now.saturating_sub(r.ts_u64()) <= u64::from(u32::from_be_bytes(r.dispersion))
                && !self.consumed_nonces.contains(&r.nonce)
        });
        match result {
            Ok(()) => {
                self.consumed_nonces.insert(nonce);
                Ok(())
            }
            Err(_) if self.consumed_nonces.contains(&nonce) => Err("replay_detected"),
            Err(_)
                if record.ts_u64() > now
                    || now.saturating_sub(record.ts_u64())
                        > u64::from(u32::from_be_bytes(record.dispersion)) =>
            {
                Err("stale_or_future_timestamp")
            }
            Err(_) if record.version != 0x02 => Err("unsupported_version"),
            Err(_) if record.alg_id_u16() != 1 => Err("unsupported_algorithm"),
            Err(_) => Err("verification_failed"),
        }
    }
}

fn now_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64
}

fn response(id: &Value, result: Value) -> Value {
    json!({"jsonrpc":"2.0", "id":id, "result":result})
}

fn error(id: &Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc":"2.0", "id":id, "error":{"code":code,"message":message}})
}

fn main() {
    let stdin = io::stdin();
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    let mut gate = DemoGate::new();

    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let Ok(message): Result<Value, _> = serde_json::from_str(&line) else {
            let _ = writeln!(stdout, "{}", error(&Value::Null, -32700, "invalid_json"));
            let _ = stdout.flush();
            continue;
        };
        let id = message.get("id").cloned().unwrap_or(Value::Null);
        let method = message.get("method").and_then(Value::as_str).unwrap_or("");
        let result = match method {
            "initialize" => response(
                &id,
                json!({
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {"listChanged": false}},
                    "serverInfo": {"name": SERVER_NAME, "version": env!("CARGO_PKG_VERSION")}
                }),
            ),
            "notifications/initialized" => continue,
            "tools/list" => response(
                &id,
                json!({"tools":[
                    {"name":"issue_demo_frame","description":"Issue one fresh 180-octet demo frame. The frame is single-use.","inputSchema":{"type":"object","properties":{}}},
                    {"name":"execute_agent_action","description":"Run a state-changing demo action only after the KVault TTTPS ingress gate accepts the frame.","inputSchema":{"type":"object","properties":{"agent_id":{"type":"string"},"action":{"type":"string"},"ttttps_frame_hex":{"type":"string"}},"required":["action","ttttps_frame_hex"]}},
                    {"name":"inspect_gate_state","description":"Return demo gate counters and the public formal-evidence reference.","inputSchema":{"type":"object","properties":{}}}
                ]}),
            ),
            "tools/call" => handle_call(
                &mut gate,
                &id,
                message.get("params").unwrap_or(&Value::Null),
            ),
            _ if id.is_null() => continue,
            _ => error(&id, -32601, "method_not_found"),
        };
        let _ = writeln!(stdout, "{}", result);
        let _ = stdout.flush();
    }
}

fn handle_call(gate: &mut DemoGate, id: &Value, params: &Value) -> Value {
    let name = params.get("name").and_then(Value::as_str).unwrap_or("");
    let args = params.get("arguments").unwrap_or(&Value::Null);
    match name {
        "issue_demo_frame" => {
            let frame = gate.issue_frame();
            response(
                id,
                json!({"content":[{"type":"text","text":format!("BOB_FRAME_HEX={}", hex(&frame))}]}),
            )
        }
        "execute_agent_action" => {
            let agent = args
                .get("agent_id")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let action = args.get("action").and_then(Value::as_str).unwrap_or("");
            let raw = args
                .get("ttttps_frame_hex")
                .and_then(Value::as_str)
                .unwrap_or("");
            let bytes = decode_hex(raw);
            let outcome = bytes.as_deref().ok().and_then(|b| gate.admit(b).err());
            match outcome {
                None => response(
                    id,
                    json!({"content":[{"type":"text","text":format!(
                        "PASS agent={} action={} state_mutation=1 commit_marker={}",
                        agent, action, gate.state.commit_marker
                    )}]}),
                ),
                Some(reason) => response(
                    id,
                    json!({"content":[{"type":"text","text":format!(
                        "REJECT agent={} reason={} state_mutation=0 commit_marker={}",
                        agent, reason, gate.state.commit_marker
                    )}]}),
                ),
            }
        }
        "inspect_gate_state" => response(
            id,
            json!({"content":[{"type":"text","text":format!(
                "app_state={} commit_marker={} consumed_nonces={} formal_verify=https://kpp.kenosian.com/v1/verify?receipt_id=33108706ed730e5296ae1b06",
                gate.state.app_state, gate.state.commit_marker, gate.consumed_nonces.len()
            )}]}),
        ),
        _ => error(id, -32602, "unknown_tool"),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode_hex(input: &str) -> Result<Vec<u8>, &'static str> {
    if input.len() % 2 != 0 {
        return Err("odd_hex_length");
    }
    (0..input.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&input[i..i + 2], 16).map_err(|_| "invalid_hex"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issued_frame_passes_once_and_replay_is_rejected_without_mutation() {
        let mut gate = DemoGate::new();
        let frame = gate.issue_frame();
        assert_eq!(gate.admit(&frame), Ok(()));
        assert_eq!(
            gate.state,
            SystemState {
                app_state: 1,
                commit_marker: 1
            }
        );
        assert_eq!(gate.admit(&frame), Err("replay_detected"));
        assert_eq!(
            gate.state,
            SystemState {
                app_state: 1,
                commit_marker: 1
            }
        );
    }

    #[test]
    fn malformed_frame_does_not_mutate() {
        let mut gate = DemoGate::new();
        assert_eq!(gate.admit(&[0; POT_V2_LEN - 1]), Err("invalid_frame_size"));
        assert_eq!(gate.state, SystemState::default());
    }
}
