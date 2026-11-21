//! 프로세스의 **첫** sqlite 열기가 여러 스레드에서 겹쳐도 죽지 않는다.
//!
//! rusqlite 는 열 때마다 SQLite 전역 초기화를 건드려, 첫 열기가 겹치면 뮤텍스 메서드 설치가 경합해 NULL 함수 포인터로
//! 뛸 수 있다(SIGSEGV). 이 파일은 시험이 하나뿐이어야 한다: 다른 시험이 먼저 열면 첫 열기가 아니다.

use std::sync::{Arc, Barrier};

#[test]
fn first_sqlite_open_from_many_threads_at_once() {
    const THREADS: usize = 32;
    let gate = Arc::new(Barrier::new(THREADS));
    let opened: Vec<_> = (0..THREADS)
        .map(|_| {
            let gate = gate.clone();
            std::thread::spawn(move || {
                gate.wait();
                lodelai_relay::db::Db::memory().is_ok()
            })
        })
        .collect();
    for t in opened {
        assert!(t.join().expect("opening thread died"));
    }
}
