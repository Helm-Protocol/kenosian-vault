//! Lean 소스에서 주석을 벗기고, 코드에 남은 `sorry` 와 줄머리 `axiom` 을 센다.
//!
//! ★로직은 `src/kenosian_vault/local.py` 의 `_strip_comments` 를 그대로 옮긴 것이다.
//!   새로 발명한 것이 아니라 언어만 Rust 로 바꿨다 — 두 구현이 갈리면 그때부터
//!   같은 파일을 두고 파이썬은 통과, Rust 는 반려 같은 일이 생긴다.

/// 블록주석 깊이를 세어 코드만 남긴다.
///
/// ⛔`/-.*?-/` 정규식을 쓰면 안 된다. Lean 블록주석은 **중첩된다** —
///   2026-08-08 에 그 정규식이 문서 안 코드펜스의 `sorry` 예시를 코드로 세어
///   금고 전체를 오염됐다고 오판했다. 2026-08-09 에는 간이 grep 이 279파일에서
///   헤더 주석의 "ZERO sorry" 문구를 세어 345건으로 부풀었다(정본 0).
///
/// 바이트 단위로 훑는다. 찾는 표식(`/-` `-/` `--`)이 전부 ASCII 라서
/// UTF-8 연속바이트(0x80 이상)와 절대 겹치지 않는다 — 멀티바이트 문자는
/// 바이트 그대로 실려 나가므로 결과는 여전히 올바른 UTF-8 이다.
pub fn strip_comments(src: &str) -> String {
    let b = src.as_bytes();
    let n = b.len();
    let mut out: Vec<u8> = Vec::with_capacity(n);
    let mut depth: usize = 0;
    let mut i: usize = 0;

    while i < n {
        if starts_with(b, i, b"/-") {
            depth += 1;
            i += 2;
            continue;
        }
        if starts_with(b, i, b"-/") && depth > 0 {
            depth -= 1;
            i += 2;
            continue;
        }
        if depth == 0 && starts_with(b, i, b"--") {
            i = match find_from(b, i, b'\n') {
                Some(j) => j,
                None => n,
            };
            continue;
        }
        if depth == 0 {
            out.push(b[i]);
        }
        i += 1;
    }

    String::from_utf8_lossy(&out).into_owned()
}

fn starts_with(b: &[u8], i: usize, pat: &[u8]) -> bool {
    b.len() >= i + pat.len() && &b[i..i + pat.len()] == pat
}

fn find_from(b: &[u8], from: usize, needle: u8) -> Option<usize> {
    b.iter().skip(from).position(|&c| c == needle).map(|p| p + from)
}

/// ASCII 낱말 문자. 파이썬 `\b` 가 쓰는 `[A-Za-z0-9_]` 와 같은 집합이다.
fn is_word(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// `\bsorry\b` 의 건수. 코드에 남은 것만 센다(주석은 이미 벗겨져 들어온다).
pub fn count_sorry(body: &str) -> usize {
    count_word(body, "sorry")
}

fn count_word(hay: &str, word: &str) -> usize {
    let b = hay.as_bytes();
    let w = word.as_bytes();
    let mut n = 0usize;
    let mut i = 0usize;
    while i + w.len() <= b.len() {
        if &b[i..i + w.len()] == w {
            let left_ok = i == 0 || !is_word(b[i - 1]);
            let right_ok = i + w.len() == b.len() || !is_word(b[i + w.len()]);
            if left_ok && right_ok {
                n += 1;
                i += w.len();
                continue;
            }
        }
        i += 1;
    }
    n
}

/// `(?m)^\s*axiom\s+` 의 건수. 줄머리 `axiom` 선언만 센다.
pub fn count_axiom_decl(body: &str) -> usize {
    body.lines()
        .filter(|line| {
            let t = line.trim_start();
            match t.strip_prefix("axiom") {
                Some(rest) => rest.starts_with(|c: char| c.is_whitespace()),
                None => false,
            }
        })
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_comment_is_stripped() {
        let s = "theorem a : True := trivial -- sorry here\n";
        let body = strip_comments(s);
        assert_eq!(count_sorry(&body), 0, "줄주석 안의 sorry 를 세면 안 된다");
    }

    #[test]
    fn nested_block_comment_is_stripped_whole() {
        // ★중첩. 안쪽 `-/` 에서 끝났다고 보면 뒤의 sorry 가 코드로 새어 나온다.
        let s = "\
/- 바깥 주석 시작
   /- 안쪽 주석 -/
   여기 sorry 가 있지만 주석이다
-/
theorem a : True := trivial
";
        let body = strip_comments(s);
        assert_eq!(count_sorry(&body), 0, "중첩 블록주석 안의 sorry 를 세면 안 된다");
        assert!(body.contains("theorem a"), "주석 뒤 코드는 남아야 한다");
    }

    #[test]
    fn naive_regex_would_have_been_wrong() {
        // `/-.*?-/` 라면 안쪽 `-/` 에서 멈춰 뒤가 코드로 노출됐을 자리.
        let s = "/- /- x -/ sorry -/\ntheorem a : True := trivial\n";
        assert_eq!(count_sorry(&strip_comments(s)), 0);
    }

    #[test]
    fn real_sorry_in_code_is_counted() {
        let s = "theorem a : True := by\n  sorry\n";
        assert_eq!(count_sorry(&strip_comments(s)), 1);
    }

    #[test]
    fn word_boundary_holds() {
        let s = "def sorryFree : Nat := 0\ndef no_sorry_here : Nat := 1\n";
        assert_eq!(count_sorry(&strip_comments(s)), 0, "sorryFree · no_sorry_here 는 sorry 가 아니다");
    }

    #[test]
    fn axiom_declaration_is_counted_only_at_line_head() {
        let s = "axiom foo : True\n  axiom bar : True\n-- axiom baz : True\ndef axiomatic : Nat := 0\n";
        let body = strip_comments(s);
        assert_eq!(count_axiom_decl(&body), 2);
    }

    #[test]
    fn multibyte_survives() {
        let s = "/- 한글 주석 -/\ntheorem 정리 : True := trivial\n";
        let body = strip_comments(s);
        assert!(body.contains("정리"), "멀티바이트 문자가 깨지면 안 된다: {body:?}");
        assert!(!body.contains("한글"));
    }

    #[test]
    fn unterminated_block_comment_swallows_rest() {
        // 파이썬 원본과 같은 거동. 닫히지 않은 주석은 끝까지 주석이다.
        let s = "/- 안 닫힘\ntheorem a : True := by sorry\n";
        assert_eq!(count_sorry(&strip_comments(s)), 0);
    }
}
