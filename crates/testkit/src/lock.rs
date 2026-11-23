//! 파일 잠금(flock) 시험 도구.

use std::time::Duration;

/// 놓은 flock 이 풀렸는지 잠깐 다시 본다(10ms 씩 최대 2초). 풀려 보이면 `true`.
///
/// 같은 시험 바이너리의 다른 시험이 자식 프로세스를 띄우면 fork~exec 사이 자식이 열린 잠금 fd 사본을 쥐어, 놓은 뒤에도 잠깐
/// 쥐여 보인다(실측: 다른 스레드가 자식을 띄우는 동안 놓은 직후 다시 잡기 3000번 중 12~18번 실패, 안 띄우면 0). 한 번 풀려
/// 보이면 그 뒤로는 다시 쥐이지 않는다 — 놓은 뒤 띄운 자식은 이 fd 를 받지 않는다. 놓은 직후 「풀렸다」를 보는 시험은 바로
/// 단정하지 말고 이것으로 본다.
pub fn after_unlock(mut released: impl FnMut() -> bool) -> bool {
    (0..200).any(|_| {
        released() || {
            std::thread::sleep(Duration::from_millis(10));
            false
        }
    })
}

#[cfg(test)]
mod tests {
    use super::after_unlock;

    #[test]
    fn 풀려_보일_때까지_다시_본다() {
        let mut n = 0;
        assert!(after_unlock(|| {
            n += 1;
            n == 3
        }));
        assert_eq!(n, 3);
    }

    #[test]
    fn 끝내_안_풀리면_거짓() {
        assert!(!after_unlock(|| false));
    }
}
