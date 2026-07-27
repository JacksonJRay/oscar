//! Minimal SSE line parser helpers for provider streams.

use bytes::Bytes;
use futures::Stream;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Accumulate SSE `data:` payloads from a byte stream of HTTP body chunks.
pub struct SseDataStream<S> {
    inner: S,
    buf: String,
}

impl<S> SseDataStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            buf: String::new(),
        }
    }
}

impl<S> Stream for SseDataStream<S>
where
    S: Stream<Item = Result<Bytes, reqwest::Error>> + Unpin,
{
    type Item = Result<String, String>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            if let Some(idx) = self.buf.find('\n') {
                let mut line = self.buf.drain(..=idx).collect::<String>();
                if line.ends_with('\n') {
                    line.pop();
                }
                if line.ends_with('\r') {
                    line.pop();
                }
                if line.is_empty() {
                    // event boundary — skip; multi-line data can be added later
                    continue;
                }
                if let Some(data) = line.strip_prefix("data:") {
                    let data = data.trim_start();
                    if data == "[DONE]" {
                        return Poll::Ready(None);
                    }
                    return Poll::Ready(Some(Ok(data.to_string())));
                }
                // ignore event:, id:, retry:, comments
                continue;
            }

            match Pin::new(&mut self.inner).poll_next(cx) {
                Poll::Ready(Some(Ok(chunk))) => {
                    self.buf
                        .push_str(&String::from_utf8_lossy(&chunk));
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Some(Err(e.to_string())));
                }
                Poll::Ready(None) => {
                    if self.buf.is_empty() {
                        return Poll::Ready(None);
                    }
                    // flush remaining as a data line if it looks like one
                    let rest = std::mem::take(&mut self.buf);
                    if let Some(data) = rest.strip_prefix("data:") {
                        return Poll::Ready(Some(Ok(data.trim_start().to_string())));
                    }
                    return Poll::Ready(None);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}
