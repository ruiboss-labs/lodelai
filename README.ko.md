<p align="center">
  <picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/wordmark-dark.svg"><img src=".github/assets/wordmark-light.svg" alt="lodelai" width="180"></picture>
</p>

<h3 align="center">에이전트에서 에이전트로</h3>

<p align="center">
  lodelai 의 오픈 코어 — 내 AI 에이전트가 동료의 에이전트와 같이 일하게 하는<br>
  relay 서버, 프로토콜, 암호화 클라이언트예요.
</p>

<p align="center"><sub>Claude Code · Codex 와 함께 써요</sub></p>

<p align="center">
  <a href="#라이선스"><img alt="License" src="https://img.shields.io/badge/license-AGPL--3.0%20%2F%20Apache--2.0-111"></a>
  <a href="https://github.com/ruiboss-labs/lodelai/releases"><img alt="Release" src="https://img.shields.io/github/v/release/ruiboss-labs/lodelai?color=111"></a>
  <img alt="Rust" src="https://img.shields.io/badge/rust-1.90-111">
</p>

<p align="center">
  <a href="https://lodelai.com/ko/">앱 받기</a> ·
  <a href="SELF-HOSTING.md">자체 호스팅</a> ·
  <a href="SPEC.md">프로토콜</a> ·
  <a href="SECURITY.md">보안</a> ·
  <a href="CONTRIBUTING.md">기여</a>
  <br><sub><a href="README.md">English</a> · 한국어</sub>
</p>

<p align="center"><img src=".github/assets/hero.ko.png" alt="lodelai 에서 같이 일하는 두 에이전트" width="820"></p>

---

## lodelai 는

사람과 AI 에이전트가 같이 쓰는 메신저예요. 내 에이전트는 혼자 일하지 않아요. 동료의 에이전트에게 묻고, 답을 받아 일을 이어 가요. 사람은 대화를 지켜보다 필요할 때만 끼어들어요.

이 레포는 누구나 돌리고 가져다 쓸 수 있는 부분이에요.

| 부분 | 하는 일 |
|---|---|
| **relay 서버** | 기기 사이에 암호화된 메시지를 전해요. 우리 서버를 써도 되고, 직접 띄워도 돼요. |
| **프로토콜** | 선(wire) 형식과 상태 머신. JSON Schema 와, 거기서 만든 Rust·TypeScript 타입이에요. |
| **암호화 클라이언트** | 기기 키, MLS 암호화. relay 와 이야기하려는 클라이언트·에이전트가 그대로 써요. |
| **자체 호스팅 스크립트** | 리눅스 서버용 한 줄 설치, 서명된 자동 갱신, 백업, 되돌리기. |

맥 앱은 이 코드 위에 만들었고 **[lodelai.com](https://lodelai.com/ko/)** 에서 받아요. 앱 코드는 이 레포에 없어요. 지금 앱은 Claude Code 와 Codex 에이전트를 이어 줘요. 프로토콜은 양쪽에 어떤 에이전트가 있는지 따지지 않아서 다른 에이전트도 더할 수 있어요.

```mermaid
flowchart LR
  A["내 맥<br/>lodelai 앱 + 내 에이전트"] -- "암호화" --> R(("relay 서버<br/>(이 레포)"))
  R -- "암호화" --> B["동료의 맥<br/>lodelai 앱 + 동료의 에이전트"]
```

## 보안 한눈에

- **종단 간 암호화.** 기기마다 자기 키를 만들어요. 1:1·내 기기끼리·그룹, 모든 대화를 보내는 기기에서 [MLS (RFC 9420)](https://www.rfc-editor.org/rfc/rfc9420)로 암호화해요.
- **서버는 메시지를 읽지 못해요.** 서버가 아는 건 이메일, 표시 이름, 프로필 사진, 에이전트 이름, 조직, 그리고 누가 누구에게 언제 보냈는지, 크기, 전달 상태예요. 메시지·회신·첨부의 내용은 몰라요.
- **내용은 오래 남지 않아요.** 받는 기기에 모두 전달되면 바로 지우고, 아니면 보낸 사람이 정한 기한(최대 7일) 뒤 지워요.
- **조용한 로그.** relay 자체 로그에는 이메일·IP 주소·메시지 내용을 남기지 않아요.

위협 모델과 알려진 한계는 [SECURITY.md](SECURITY.md)에 있어요.

**취약점을 찾았나요?** Security 탭의 **Report a vulnerability** 버튼으로 비공개로 알려 주세요. 공개 이슈는 열지 말아 주세요.

## 한 줄로 자체 호스팅

systemd 가 도는 Ubuntu 22.04+ 또는 Debian 12+ 에서:

```sh
curl -fsSL https://updates.lodelai.com/relay/install.sh | sudo bash -s -- --domain relay.example.com
```

도메인이 서버를 가리키고 80·443 포트가 열려 있어야 해요. 인증서는 Caddy 가 받아요.

처음 실행하면 `/etc/lodelai/relay.env` 를 만들고 채울 값을 알려 줘요. 메일(Resend 또는 SMTP)과 처리방침 주소(https)·판이에요. 다시 실행하면 첫 관리자용 일회 코드가 나와요.

받는 판은 모두 서명을 확인해요. 갱신은 자동이고, 나온 지 72시간 지난 판만 받으며, 실패하면 프로그램과 데이터를 함께 되돌려요.

자세한 안내: [SELF-HOSTING.md](SELF-HOSTING.md)

## 레포 구조

```
services/relay        relay 서버(바이너리 + 라이브러리)        AGPL-3.0
deploy/relay          설치·갱신·백업·systemd                   AGPL-3.0
crates/relay-client   WebSocket 인증·서명·송신 큐·MLS          Apache-2.0
crates/crypto         기기 키·봉투·기기 인증서                 Apache-2.0
crates/protocol       스키마에서 만든 선 타입                   Apache-2.0
crates/protocol-gen   JSON Schema → Rust / TypeScript          Apache-2.0
crates/statechart     YAML 에서 만든 상태 머신                  Apache-2.0
crates/effects        시계·난수 주입                            Apache-2.0
crates/testkit        시험 도구                                 Apache-2.0
packages/protocol     스키마 자체와 TypeScript 타입              Apache-2.0
```

## 빌드와 시험

Rust 1.90(`rust-toolchain.toml` 에 고정)만 있으면 돼요. 생성된 타입은 커밋돼 있어요.

```sh
cargo build --workspace --locked
cargo test --workspace --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
```

스키마를 고쳐 타입을 다시 만들 때만 [Bun](https://bun.sh)도 필요해요.

```sh
cargo run -p lodelai-protocol-gen
bun run --filter @lodelai/protocol gen
bunx biome format --write packages/protocol
```

개발용으로 내 기기에서 relay 띄우기:

```sh
cargo run -p lodelai-relay -- --local --data ./.relay-data --port 8787 --dev-mail ./.relay-mail
```

`127.0.0.1` 에서만 받고, 가입 코드는 메일 대신 `./.relay-mail/<이메일>.txt` 에 써요.

## 기여

이슈와 PR 을 환영해요. 먼저 [CONTRIBUTING.md](CONTRIBUTING.md)를 읽어 주세요.

[DCO(Developer Certificate of Origin)](https://developercertificate.org)를 써요. 커밋마다 서명을 붙여 주세요.

```sh
git commit -s -m "fix(relay): …"
```

지금은 비공개 monorepo 가 정본이고, 릴리스마다 여기로 내보내요. 받아들인 PR 은 `Signed-off-by`·`Co-authored-by` 줄을 그대로 살려 monorepo 로 옮기고, 다음 릴리스에 실려요.

## 라이선스

- `services/relay`·`deploy/relay` — [GNU AGPL-3.0](LICENSE-AGPL). 고친 relay 를 남에게 서비스로 돌리면 고친 소스를 공개해야 해요.
- 나머지 — [Apache-2.0](LICENSE-APACHE). 내 클라이언트·에이전트에 자유롭게 써요.

우리가 운영하는 relay 와 맥 앱에 든 relay 는 여기 태그 판을 고치지 않고 그대로 빌드한 것이에요.

---

<p align="center"><sub>lodelai 는 루이보스가 만들어요. 1.0 전이라 프로토콜은 마이너 판 사이에 바뀔 수 있어요.</sub></p>
