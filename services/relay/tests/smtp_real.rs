//! 실제 SMTP 서버로 보내 보기(묶음 29 §1-3) — 평소 검사에서는 건너뛴다(`#[ignore]`). `scripts/smtp-real-check.sh` 가
//! 로컬 시험 서버(aiosmtpd, STARTTLS 필수·AUTH, 자체 서명 인증서)를 띄우고 env 를 채워 이것을 돌린다.

use lodelai_relay::mail::{MailFrom, Mailer, SmtpMailer};

#[test]
#[ignore = "scripts/smtp-real-check.sh 가 시험 서버를 띄우고 돌린다"]
fn real_smtp_server_starttls_auth() {
    let var = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("{k} 가 필요하다"));
    let port: u16 = var("LODELAI_SMTP_TEST_PORT").parse().unwrap();
    let pem = std::fs::read(var("LODELAI_SMTP_TEST_CA")).unwrap();
    let from = MailFrom::parse("lodelai <noreply@example.org>").unwrap();
    let m =
        SmtpMailer::starttls_for_test("localhost", port, &pem, "lodelai", "pw-시험", from).unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _g = rt.enter();
    m.send_code("a@x.io", "123456", "ko").unwrap();
}
