//! Replaces secret values in a byte stream as it passes through.
//!
//! A secret can arrive split across two reads, so the masker holds back the
//! end of a chunk only while that end could be the start of a secret. Output
//! that can't be (a finished line, say) goes out at once, so a quiet dev server
//! never has its last line stuck in the buffer.

pub const CONCEALED: &[u8] = b"<concealed by harar>";

pub struct Masker {
    /// Longest first, so a secret that contains another is masked whole.
    secrets: Vec<Vec<u8>>,
    pending: Vec<u8>,
}

impl Masker {
    pub fn new<I: IntoIterator<Item = Vec<u8>>>(secrets: I) -> Self {
        let mut secrets: Vec<Vec<u8>> = secrets.into_iter().filter(|s| !s.is_empty()).collect();
        secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
        secrets.dedup();
        Self { secrets, pending: Vec::new() }
    }

    /// Feeds bytes in; returns what is safe to write out now.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.pending.extend_from_slice(chunk);
        let (out, consumed) = self.scan(false);
        self.pending.drain(..consumed);
        out
    }

    /// Everything still held back, masked. Call once the stream ends.
    pub fn finish(&mut self) -> Vec<u8> {
        let (out, _) = self.scan(true);
        self.pending.clear();
        out
    }

    /// Masks `pending`. Unless `all`, stops where a secret could still be
    /// starting, and returns how many input bytes it consumed.
    fn scan(&self, all: bool) -> (Vec<u8>, usize) {
        let data = &self.pending;
        let safe_end = if all { data.len() } else { data.len() - self.unfinished_tail(data) };
        let mut out = Vec::with_capacity(data.len());
        let mut at = 0;
        while at < safe_end {
            if let Some(secret) = self.secrets.iter().find(|s| data[at..].starts_with(s)) {
                out.extend_from_slice(CONCEALED);
                at += secret.len();
            } else {
                out.push(data[at]);
                at += 1;
            }
        }
        (out, at)
    }

    /// Length of the longest end of `data` that is the start of a secret but
    /// not the whole secret.
    fn unfinished_tail(&self, data: &[u8]) -> usize {
        self.secrets
            .iter()
            .filter_map(|secret| {
                (1..secret.len().min(data.len() + 1))
                    .rev()
                    .find(|&n| data.ends_with(&secret[..n]))
            })
            .max()
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(secrets: &[&str], chunks: &[&str]) -> String {
        let mut masker = Masker::new(secrets.iter().map(|s| s.as_bytes().to_vec()));
        let mut out = Vec::new();
        for chunk in chunks {
            out.extend(masker.push(chunk.as_bytes()));
        }
        out.extend(masker.finish());
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn masks_a_secret_in_one_chunk() {
        assert_eq!(run(&["hunter2"], &["pw=hunter2!"]), "pw=<concealed by harar>!");
    }

    #[test]
    fn masks_a_secret_split_across_chunks() {
        assert_eq!(run(&["hunter2"], &["pw=hun", "te", "r2 done"]), "pw=<concealed by harar> done");
        assert_eq!(run(&["hunter2"], &["h", "u", "n", "t", "e", "r", "2"]), "<concealed by harar>");
    }

    #[test]
    fn longer_secret_wins_over_its_prefix() {
        assert_eq!(run(&["abc", "abcdef"], &["xabcdefx abc"]), "x<concealed by harar>x <concealed by harar>");
    }

    #[test]
    fn near_misses_pass_through_untouched() {
        assert_eq!(run(&["hunter2"], &["hunter", "3 hunte"]), "hunter3 hunte");
        assert_eq!(run(&[], &["nothing to hide"]), "nothing to hide");
    }

    #[test]
    fn finished_output_is_released_at_once() {
        let mut masker = Masker::new([b"secret".to_vec()]);
        assert_eq!(masker.push(b"listening on :3000\n"), b"listening on :3000\n");
    }

    #[test]
    fn only_a_possible_secret_start_is_held_back() {
        let mut masker = Masker::new([b"secret".to_vec()]);
        assert_eq!(masker.push(b"token: sec"), b"token: ");
        assert_eq!(masker.push(b"ond"), b"second");
    }
}
