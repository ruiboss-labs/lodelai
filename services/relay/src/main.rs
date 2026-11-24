//! lodelai-relay — 얇은 main. 인자·하위 명령·진입점은 라이브러리의 [`lodelai_relay::cli`](앱이 번들하는 사이드카도 같은 것을 부른다).

use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    lodelai_relay::run(std::env::args().skip(1).collect()).await
}
