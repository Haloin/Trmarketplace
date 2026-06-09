//! WebSocket subscription for payment notifications (blind pub/sub broker).

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, State,
    },
    response::IntoResponse,
    Extension,
};
use crate::gateway::auth_common::AuthPubkey;
use crate::gateway::state::AppState;

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Extension(AuthPubkey(_pubkey_hash)): Extension<AuthPubkey>,
    Path(order_id): Path<String>,
) -> Result<impl IntoResponse, &'static str> {
    // Hex-shaped order_id only; no DB lookup (worker publishes funded orders).
    if hex::decode(&order_id).is_err() {
        return Err("invalid order_id");
    }

    let rx = state.payment_tx.subscribe();
    Ok(ws.on_upgrade(move |socket| handle_socket(socket, rx, order_id)))
}

async fn handle_socket(
    mut socket: WebSocket,
    mut rx: tokio::sync::broadcast::Receiver<String>,
    order_id: String,
) {
    use tokio::select;
    loop {
        select! {
            msg = rx.recv() => {
                match msg {
                    Ok(funded_id) if funded_id == order_id => {
                        let payload = serde_json::json!({
                            "type": "funded",
                            "order_id": order_id,
                        });
                        if socket.send(Message::Text(payload.to_string())).await.is_err() {
                            break;
                        }
                        break;
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(skipped = n, "Payment notification lag");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
            _ = socket.recv() => break,
        }
    }
}
