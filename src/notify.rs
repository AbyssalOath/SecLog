use crate::db::DbPool;
use crate::models::{
    DiscordConfig, EmailConfig, GenericWebhookConfig, NotificationChannel, NtfyConfig,
    SlackConfig, TelegramConfig,
};
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

// Fetches every channel that should hear about an event of this severity,
// and dispatches to each one CONCURRENTLY via tokio::spawn -- one slow or
// unreachable webhook (e.g. a dead Discord URL) must never delay, or
// block, delivery to the others. Never returns an error to the caller;
// this is fire-and-forget by design, called from create_log without
// blocking the HTTP response to the shipper.
pub async fn trigger_alert(pool: &DbPool, severity: &str, message: &str, host: &str) {
    let channels = match crate::db::get_enabled_channels_for_severity(pool, severity).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("notify: failed to load channels: {}", e);
            return;
        }
    };

    for channel in channels {
        let severity = severity.to_string();
        let message = message.to_string();
        let host = host.to_string();

        tokio::spawn(async move {
            if let Err(e) = dispatch(&channel, &severity, &message, &host).await {
                eprintln!(
                    "notify: failed to send to channel '{}' (kind={}): {}",
                    channel.name, channel.kind, e
                );
            }
        });
    }
}

// Shared by trigger_alert and the "Test" button (test_notification_channel
// in main.rs) -- both ultimately need "build the right payload for this
// channel's kind and send it," just with a synthetic message for the
// latter.
pub async fn dispatch(
    channel: &NotificationChannel,
    severity: &str,
    message: &str,
    host: &str,
) -> Result<(), String> {
    match channel.kind.as_str() {
        "email" => send_email(&channel.config, severity, message, host).await,
        "slack" => send_slack(&channel.config, severity, message, host).await,
        "discord" => send_discord(&channel.config, severity, message, host).await,
        "telegram" => send_telegram(&channel.config, severity, message, host).await,
        "ntfy" => send_ntfy(&channel.config, severity, message, host).await,
        "webhook" => send_generic_webhook(&channel.config, severity, message, host).await,
        other => Err(format!("unknown channel kind: {}", other)),
    }
}

fn format_body(severity: &str, message: &str, host: &str) -> String {
    format!("[{}] {} — {}", severity, host, message)
}

async fn send_email(config_json: &str, severity: &str, message: &str, host: &str) -> Result<(), String> {
    let config: EmailConfig = serde_json::from_str(config_json).map_err(|e| e.to_string())?;
    let body = format_body(severity, message, host);

    let email = Message::builder()
        .from(config.from.parse::<Mailbox>().map_err(|e| e.to_string())?)
        .to(config.to.parse::<Mailbox>().map_err(|e| e.to_string())?)
        .subject(format!("SecLog alert [{}] on {}", severity, host))
        .body(body)
        .map_err(|e| e.to_string())?;

    let creds = Credentials::new(config.username, config.password);

    let mailer: AsyncSmtpTransport<Tokio1Executor> =
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.smtp_host)
            .map_err(|e| e.to_string())?
            .port(config.smtp_port)
            .credentials(creds)
            .build();

    mailer.send(email).await.map_err(|e| e.to_string())?;
    Ok(())
}

async fn send_slack(config_json: &str, severity: &str, message: &str, host: &str) -> Result<(), String> {
    let config: SlackConfig = serde_json::from_str(config_json).map_err(|e| e.to_string())?;
    let body = serde_json::json!({ "text": format_body(severity, message, host) });

    let client = reqwest::Client::new();
    let resp = client.post(&config.webhook_url).json(&body).send().await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("Slack webhook returned {}", resp.status()));
    }
    Ok(())
}

async fn send_discord(config_json: &str, severity: &str, message: &str, host: &str) -> Result<(), String> {
    let config: DiscordConfig = serde_json::from_str(config_json).map_err(|e| e.to_string())?;
    let body = serde_json::json!({ "content": format_body(severity, message, host) });

    let client = reqwest::Client::new();
    let resp = client.post(&config.webhook_url).json(&body).send().await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("Discord webhook returned {}", resp.status()));
    }
    Ok(())
}

async fn send_telegram(config_json: &str, severity: &str, message: &str, host: &str) -> Result<(), String> {
    let config: TelegramConfig = serde_json::from_str(config_json).map_err(|e| e.to_string())?;
    let url = format!("https://api.telegram.org/bot{}/sendMessage", config.bot_token);
    let body = serde_json::json!({
        "chat_id": config.chat_id,
        "text": format_body(severity, message, host),
    });

    let client = reqwest::Client::new();
    let resp = client.post(&url).json(&body).send().await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("Telegram API returned {}", resp.status()));
    }
    Ok(())
}

async fn send_ntfy(config_json: &str, severity: &str, message: &str, host: &str) -> Result<(), String> {
    let config: NtfyConfig = serde_json::from_str(config_json).map_err(|e| e.to_string())?;
    let url = format!(
        "{}/{}",
        config.server_url.trim_end_matches('/'),
        config.topic
    );

    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .header("Title", format!("SecLog [{}]", severity))
        .body(format_body(severity, message, host))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("ntfy returned {}", resp.status()));
    }
    Ok(())
}

async fn send_generic_webhook(config_json: &str, severity: &str, message: &str, host: &str) -> Result<(), String> {
    let config: GenericWebhookConfig = serde_json::from_str(config_json).map_err(|e| e.to_string())?;
    let body = serde_json::json!({
        "severity": severity,
        "message": message,
        "host": host,
    });

    let client = reqwest::Client::new();
    let mut req = client.post(&config.url).json(&body);
    for (key, value) in &config.headers {
        req = req.header(key, value);
    }
    let resp = req.send().await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("Webhook returned {}", resp.status()));
    }
    Ok(())
}
