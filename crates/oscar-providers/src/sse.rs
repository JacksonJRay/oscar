//! SSE (Server-Sent Events) parsing for provider streams.
//!
//! Pattern aligned with Grok Build's sampler client and OpenCode's `parseSSE`:
//! - raw HTTP body → UTF-8 BOM strip → `eventsource-stream` → data payloads
//! - multi-line `data:` fields joined correctly
//! - `[DONE]` terminates cleanly
//! - first transport error is surfaced, then the stream ends (no busy-loop)

use bytes::Bytes;
use eventsource_stream::Eventsource;
use futures::Stream;
use futures::StreamExt;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Accumulate SSE `data:` payloads from a byte stream of HTTP body chunks.
///
/// Yields one complete event payload (the joined `data:` field) per item.
/// `[DONE]` ends the stream without yielding.
pub struct SseDataStream<S> {
    inner: Pin<Box<dyn Stream<Item = Result<String, String>> + Send>>,
    _marker: std::marker::PhantomData<S>,
}

impl<S> SseDataStream<S>
where
    S: Stream<Item = Result<Bytes, reqwest::Error>> + Unpin + Send + 'static,
{
    pub fn new(inner: S) -> Self {
        // Strip UTF-8 BOM if present: eventsource-stream 0.2.x can mishandle BOM
        // (Grok Build documents the same workaround).
        const UTF8_BOM: &[u8] = &[0xEF, 0xBB, 0xBF];
        let mut is_first = true;
        let byte_stream = inner.map(move |result| {
            result.map(|bytes| {
                if is_first {
                    is_first = false;
                    if bytes.starts_with(UTF8_BOM) {
                        return bytes.slice(UTF8_BOM.len()..);
                    }
                }
                bytes
            })
        });

        // eventsource() requires Stream<Item = Result<Bytes, E>> where E: Error
        let event_stream = byte_stream.eventsource();

        // Map SSE events → data strings; terminate on [DONE] or first transport error.
        let mapped = futures::stream::unfold(
            (event_stream, false),
            |(mut events, mut dead)| async move {
                if dead {
                    return None;
                }
                loop {
                    match events.next().await {
                        None => return None,
                        Some(Ok(event)) => {
                            let data = event.data;
                            if data == "[DONE]" {
                                return None;
                            }
                            // Empty data frames (keepalive comments only) skip.
                            if data.is_empty() {
                                continue;
                            }
                            return Some((Ok(data), (events, false)));
                        }
                        Some(Err(e)) => {
                            dead = true;
                            return Some((
                                Err(format!("sse transport: {e}")),
                                (events, dead),
                            ));
                        }
                    }
                }
            },
        );

        Self {
            inner: Box::pin(mapped),
            _marker: std::marker::PhantomData,
        }
    }
}

impl<S> Stream for SseDataStream<S>
where
    S: Stream<Item = Result<Bytes, reqwest::Error>> + Unpin + Send + 'static,
{
    type Item = Result<String, String>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(cx)
    }
}

/// Parse a raw SSE document (for tests / offline fixtures) into data payloads.
/// Mirrors OpenCode `parseSSE` multi-line join rules.
#[allow(dead_code)] // public helper for fixtures / future server SSE
pub fn parse_sse_document(raw: &str) -> Vec<String> {
    let normalized = raw.replace("\r\n", "\n").replace('\r', "\n");
    let mut out = Vec::new();
    for chunk in normalized.split("\n\n") {
        let mut data_lines: Vec<String> = Vec::new();
        for line in chunk.lines() {
            if let Some(rest) = line.strip_prefix("data:") {
                data_lines.push(rest.strip_prefix(' ').unwrap_or(rest).to_string());
            }
            // ignore event:, id:, retry:, comments
        }
        if data_lines.is_empty() {
            continue;
        }
        let data = data_lines.join("\n");
        if data == "[DONE]" {
            break;
        }
        if !data.is_empty() {
            out.push(data);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::stream;

    #[test]
    fn parse_sse_document_basic() {
        let raw = "data: {\"a\":1}\n\ndata: {\"b\":2}\n\ndata: [DONE]\n\n";
        let items = parse_sse_document(raw);
        assert_eq!(items, vec![r#"{"a":1}"#, r#"{"b":2}"#]);
    }

    #[test]
    fn parse_sse_document_multiline_data() {
        // Spec: consecutive data: lines in one event are joined with \n.
        let raw = "data: {\"text\":\ndata: \"hello\"}\n\n";
        let items = parse_sse_document(raw);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0], "{\"text\":\n\"hello\"}");
    }

    #[test]
    fn parse_sse_document_ignores_comments_and_event_names() {
        let raw = ": keepalive\nevent: message\ndata: hi\nid: 1\n\n";
        let items = parse_sse_document(raw);
        assert_eq!(items, vec!["hi"]);
    }

    #[tokio::test]
    async fn sse_stream_from_bytes_handles_done_and_chunks() {
        let body = "data: {\"n\":1}\n\ndata: {\"n\":2}\n\ndata: [DONE]\n\n";
        let chunks = stream::iter(vec![Ok::<Bytes, reqwest::Error>(Bytes::from(body))]);
        let mut sse = SseDataStream::new(chunks);
        let mut got = Vec::new();
        while let Some(item) = sse.next().await {
            got.push(item.unwrap());
        }
        assert_eq!(got, vec![r#"{"n":1}"#, r#"{"n":2}"#]);
    }

    #[tokio::test]
    async fn sse_stream_strips_utf8_bom() {
        let mut body = vec![0xEF, 0xBB, 0xBF];
        body.extend_from_slice(b"data: {\"ok\":true}\n\ndata: [DONE]\n\n");
        let chunks = stream::iter(vec![Ok::<Bytes, reqwest::Error>(Bytes::from(body))]);
        let mut sse = SseDataStream::new(chunks);
        let first = sse.next().await.unwrap().unwrap();
        assert_eq!(first, r#"{"ok":true}"#);
        assert!(sse.next().await.is_none());
    }

    #[tokio::test]
    async fn sse_stream_split_across_tcp_chunks() {
        // Real networks split mid-line — parser must reassemble.
        let parts = vec![
            Bytes::from_static(b"data: {\"par"),
            Bytes::from_static(b"tial\":1}\n\ndata: {\"p"),
            Bytes::from_static(b"artial\":2}\n\ndata: [DONE]\n\n"),
        ];
        let chunks = stream::iter(parts.into_iter().map(Ok::<Bytes, reqwest::Error>));
        let mut sse = SseDataStream::new(chunks);
        let mut got = Vec::new();
        while let Some(item) = sse.next().await {
            got.push(item.unwrap());
        }
        assert_eq!(got, vec![r#"{"partial":1}"#, r#"{"partial":2}"#]);
    }
}
