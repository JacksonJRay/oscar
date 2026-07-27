use crate::context::ContextManager;
use oscar_core::{ExecutionMode, Message, ThinkingConfig};

pub struct Session {
    /// Persistent chat id (saved under ~/.config/oscar/sessions/).
    pub id: String,
    pub title: String,
    pub messages: Vec<Message>,
    pub mode: ExecutionMode,
    pub thinking: ThinkingConfig,
    pub context: ContextManager,
}

impl Session {
    pub fn new(
        mode: ExecutionMode,
        thinking: ThinkingConfig,
        context: ContextManager,
        system: Message,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            title: "New chat".into(),
            messages: vec![system],
            mode,
            thinking,
            context,
        }
    }

    pub fn push_user(&mut self, text: impl Into<String>) {
        let t = text.into();
        if self.title == "New chat" {
            let mut title: String = t.trim().chars().take(72).collect();
            if t.trim().chars().count() > 72 {
                title.push('…');
            }
            if !title.is_empty() {
                self.title = title;
            }
        }
        self.messages.push(Message::user(t));
    }
}
