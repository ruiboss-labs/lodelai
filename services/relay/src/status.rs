//! 서버 상태(`server.status`, 묶음 5 m1-spec §17.3) — 원격 relay 의 관리자만.
//!
//! 집계 숫자·시각만 낸다(주소·아이디·기기 id·메시지별 시각 없음). 주의·문제 기준은 여기 한 곳에 둔다 — 화면은
//! `levels` → 색, `reasons` → 문구만 그린다. 계산값은 10초 캐시하고 `now_ms` 만 매번 새로 넣는다(앱이 시계 차를 잰다).

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use lodelai_protocol::ws;

use crate::db::{BackupLast, BackupOffsite, BackupRecord};
use crate::Relay;

/// 계산값 캐시 시간.
pub const CACHE_MS: i64 = 10_000;
const HOUR_MS: i64 = 60 * 60 * 1000;
/// 마지막 백업 성공이 이보다 오래되면 주의·문제(`backup_stale`).
pub const BACKUP_STALE_WARN_MS: i64 = 36 * HOUR_MS;
pub const BACKUP_STALE_BAD_MS: i64 = 72 * HOUR_MS;
/// 디스크 여유(`disk_low`): 전체의 15% 와 20 GB 중 작은 쪽 아래면 주의, 5% 와 5 GB 중 작은 쪽 아래면 문제.
/// relay 가 쓰는 여유는 디스크 크기가 아니라 데이터 크기에 달려 있어, 큰 디스크는 절대값이 먼저 걸린다(#899 — 926 GB 중
/// 52 GB 여유가 늘 주의였다). 문제 5 GB 는 `--blob-min-free` 기본 하한과 같은 자리다.
pub const DISK_WARN_PERCENT: u64 = 15;
pub const DISK_WARN_BYTES: u64 = 20_000_000_000;
pub const DISK_BAD_PERCENT: u64 = 5;
pub const DISK_BAD_BYTES: u64 = 5_000_000_000;
/// 전달 대기 봉투 수: 넘으면 주의·문제(`queue_high`).
pub const QUEUE_WARN: u64 = 10_000;
pub const QUEUE_BAD: u64 = 50_000;
/// 오늘 발송이 하루 상한의 이 비율 이상이면 주의, 상한이면 문제(`mail_quota`).
pub const MAIL_WARN_PERCENT: u64 = 80;
/// 이 시간 안에 Resend 실패가 있으면 주의(`mail_failed`).
pub const MAIL_FAILED_WINDOW_MS: i64 = HOUR_MS;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Ok,
    Warn,
    Bad,
}

impl Level {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warn => "warn",
            Self::Bad => "bad",
        }
    }
}

/// 판정에 쓰는 값.
#[derive(Debug, Clone)]
pub struct Inputs {
    pub backup: BackupRecord,
    /// (여유, 전체) 바이트. 모르면(데이터 폴더 없음 — 시험) `None` 이고 판정하지 않는다.
    pub disk: Option<(u64, u64)>,
    pub pending: u64,
    pub sent_today: u64,
    pub daily_limit: u64,
    pub mail_last_failed_ms: Option<i64>,
    /// 첨부 폴더 파일시스템의 남은 바이트(묶음 15). 모르면 판정하지 않는다.
    pub blob_free: Option<u64>,
    /// `--blob-min-free`.
    pub blob_min_free: u64,
}

/// 판정 결과: 항목별 level 과 이유(표의 순서).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assessment {
    pub backup: Level,
    pub disk: Level,
    pub queue: Level,
    pub mail: Level,
    pub files: Level,
    pub reasons: Vec<ws::ServerStatusReasonsItem>,
}

impl Assessment {
    #[must_use]
    pub fn level(&self) -> Level {
        self.backup
            .max(self.disk)
            .max(self.queue)
            .max(self.mail)
            .max(self.files)
    }
}

/// 기준 표(m1-spec §17.3)대로 판정한다. `started_ms` 는 프로세스 시작 — 한 번도 성공한 백업이 없을 때 그때부터 센다.
#[must_use]
pub fn assess(i: &Inputs, now_ms: i64, started_ms: i64) -> Assessment {
    use ws::ServerStatusReasonsItem as R;
    let mut reasons = Vec::new();
    let mut hit = |level: Level, reason: R, at: &mut Level| {
        if level > Level::Ok {
            reasons.push(reason);
            *at = (*at).max(level);
        }
    };

    let mut backup = Level::Ok;
    hit(
        if i.backup.last == BackupLast::Failed {
            Level::Bad
        } else {
            Level::Ok
        },
        R::BackupFailed,
        &mut backup,
    );
    let since_ok = now_ms.saturating_sub(i.backup.last_ok_ms.unwrap_or(started_ms));
    hit(
        if since_ok > BACKUP_STALE_BAD_MS {
            Level::Bad
        } else if since_ok > BACKUP_STALE_WARN_MS {
            Level::Warn
        } else {
            Level::Ok
        },
        R::BackupStale,
        &mut backup,
    );
    hit(
        if i.backup.offsite == BackupOffsite::Failed {
            Level::Warn
        } else {
            Level::Ok
        },
        R::OffsiteFailed,
        &mut backup,
    );

    let mut disk = Level::Ok;
    if let Some((free, total)) = i.disk {
        let below = |percent: u64, bytes: u64| {
            free < bytes && u128::from(free) * 100 < u128::from(total) * u128::from(percent)
        };
        hit(
            if below(DISK_BAD_PERCENT, DISK_BAD_BYTES) {
                Level::Bad
            } else if below(DISK_WARN_PERCENT, DISK_WARN_BYTES) {
                Level::Warn
            } else {
                Level::Ok
            },
            R::DiskLow,
            &mut disk,
        );
    }

    let mut queue = Level::Ok;
    hit(
        if i.pending > QUEUE_BAD {
            Level::Bad
        } else if i.pending > QUEUE_WARN {
            Level::Warn
        } else {
            Level::Ok
        },
        R::QueueHigh,
        &mut queue,
    );

    let mut mail = Level::Ok;
    hit(
        if i.sent_today >= i.daily_limit {
            Level::Bad
        } else if i.sent_today * 100 >= i.daily_limit * MAIL_WARN_PERCENT {
            Level::Warn
        } else {
            Level::Ok
        },
        R::MailQuota,
        &mut mail,
    );
    hit(
        if i.mail_last_failed_ms
            .is_some_and(|t| now_ms.saturating_sub(t) < MAIL_FAILED_WINDOW_MS)
        {
            Level::Warn
        } else {
            Level::Ok
        },
        R::MailFailed,
        &mut mail,
    );

    // 파일 저장 공간(묶음 15 §2.7): 예약을 막는 하한(storage_full)의 두 배 아래면 주의, 하한 아래면 문제.
    let mut files = Level::Ok;
    if let Some(free) = i.blob_free {
        hit(
            if free < i.blob_min_free {
                Level::Bad
            } else if free < i.blob_min_free.saturating_mul(2) {
                Level::Warn
            } else {
                Level::Ok
            },
            R::FilesDiskLow,
            &mut files,
        );
    }

    Assessment {
        backup,
        disk,
        queue,
        mail,
        files,
        reasons,
    }
}

/// 데이터 폴더가 있는 파일시스템의 (여유, 전체) 바이트(statvfs — 일반 사용자가 쓸 수 있는 여유).
pub(crate) fn disk_of(dir: &Path) -> Option<(u64, u64)> {
    let s = rustix::fs::statvfs(dir).ok()?;
    Some((
        s.f_bavail.saturating_mul(s.f_frsize),
        s.f_blocks.saturating_mul(s.f_frsize),
    ))
}

/// DB 파일 + WAL 크기.
fn db_bytes_of(dir: &Path) -> u64 {
    ["relay.sqlite3", "relay.sqlite3-wal"]
        .iter()
        .filter_map(|f| std::fs::metadata(dir.join(f)).ok())
        .map(|m| m.len())
        .sum()
}

/// 조직별 10초 캐시(조직 → (계산 시각, 응답)) — 기기·인원 수가 조직마다 다르다.
#[derive(Default)]
pub struct Cache(Mutex<HashMap<String, (i64, ws::ServerStatus)>>);

fn ms(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

fn parse<T: std::str::FromStr>(level: Level) -> T
where
    T::Err: std::fmt::Debug,
{
    // 생성된 level 형들은 모두 ok|warn|bad 이다.
    level.as_str().parse().expect("ok|warn|bad")
}

/// `server.status` 응답. 호출자가 권한(원격·관리자)을 먼저 본다. sqlite 오류면 `None`.
pub fn server_status(app: &Relay, org: &str) -> Option<ws::ServerStatus> {
    let now = app.effects.clock.now().0;
    let mut cache = app
        .status_cache
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some((at, s)) = cache.get(org) {
        if now.saturating_sub(*at) < CACHE_MS && now >= *at {
            let mut s = s.clone();
            s.now_ms = ms(now);
            return Some(s);
        }
    }
    let db = &app.db;
    let dir = app.config.data_dir.as_deref();
    let inputs = Inputs {
        backup: db.backup_record().ok()?,
        disk: dir.and_then(disk_of),
        pending: ms(db.pending_count().ok()?),
        sent_today: ms(db.signup_sent_today(now).ok()?),
        daily_limit: ms(app.config.mail_per_day),
        mail_last_failed_ms: db.mail_last_failed().ok()?,
        blob_free: crate::blob::free_bytes(app),
        blob_min_free: app.config.blob_min_free,
    };
    let (attachments, avatars) = db.blob_totals().ok()?;
    let kind = |(bytes, count): (u64, u64)| ws::ServerStatusFileKind { bytes, count };
    let a = assess(&inputs, now, app.started_ms);
    let (free, total) = inputs.disk.unwrap_or((0, 0));
    let b = &inputs.backup;
    let s = ws::ServerStatus {
        t: ws::ServerStatusT::ServerStatus,
        version: ws::ServerStatusVersion {
            relay: env!("CARGO_PKG_VERSION").to_owned(),
            protocol: u64::from(lodelai_protocol::PROTOCOL_VERSION),
        },
        started_ms: ms(app.started_ms),
        now_ms: ms(now),
        backup: ws::ServerStatusBackup {
            last: match b.last {
                BackupLast::Ok => ws::ServerStatusBackupLast::Ok,
                BackupLast::Failed => ws::ServerStatusBackupLast::Failed,
                BackupLast::None => ws::ServerStatusBackupLast::None,
            },
            last_attempt_ms: b.last_attempt_ms.map(ms),
            last_ok_ms: b.last_ok_ms.map(ms),
            offsite: match b.offsite {
                BackupOffsite::Ok => ws::ServerStatusBackupOffsite::Ok,
                BackupOffsite::Failed => ws::ServerStatusBackupOffsite::Failed,
                BackupOffsite::Skipped => ws::ServerStatusBackupOffsite::Skipped,
                BackupOffsite::None => ws::ServerStatusBackupOffsite::None,
            },
        },
        disk: ws::ServerStatusDisk {
            free_bytes: free,
            total_bytes: total,
        },
        db_bytes: dir.map_or(0, db_bytes_of),
        files: Some(ws::ServerStatusFiles {
            bytes: attachments.0 + avatars.0,
            count: attachments.1 + avatars.1,
            attachments: Some(kind(attachments)),
            avatars: Some(kind(avatars)),
        }),
        queue: ws::ServerStatusQueue {
            pending: inputs.pending,
        },
        devices: ws::ServerStatusDevices {
            // 내 조직(내보내지 않은 사람)의 기기만 — 다른 조직의 규모는 보이지 않는다(10-25 결정).
            connected: db
                .people_in_org(org)
                .ok()?
                .iter()
                .map(|(u, _)| app.conns.connections_of(u) as u64)
                .sum(),
            total: ms(db.live_device_count(org).ok()?),
        },
        members: ms(db.member_count(org).ok()?),
        mail: ws::ServerStatusMail {
            sent_today: inputs.sent_today,
            daily_limit: inputs.daily_limit,
            last_failed_ms: inputs.mail_last_failed_ms.map(ms),
        },
        levels: ws::ServerStatusLevels {
            backup: parse(a.backup),
            disk: parse(a.disk),
            queue: parse(a.queue),
            mail: parse(a.mail),
            files: Some(parse(a.files)),
        },
        level: parse(a.level()),
        reasons: a.reasons,
    };
    cache.retain(|_, (at, _)| now.saturating_sub(*at) < CACHE_MS);
    cache.insert(org.to_owned(), (now, s.clone()));
    Some(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ws::ServerStatusReasonsItem as R;

    const NOW: i64 = 1_000 * HOUR_MS;

    fn calm() -> Inputs {
        Inputs {
            backup: BackupRecord {
                last_attempt_ms: Some(NOW - HOUR_MS),
                last_ok_ms: Some(NOW - HOUR_MS),
                last: BackupLast::Ok,
                offsite: BackupOffsite::Ok,
            },
            disk: Some((50_000_000_000, 100_000_000_000)),
            pending: 0,
            sent_today: 0,
            daily_limit: 80,
            mail_last_failed_ms: None,
            blob_free: Some(50_000_000_000),
            blob_min_free: 5_000_000_000,
        }
    }

    fn of(i: &Inputs) -> (Level, Vec<R>) {
        let a = assess(i, NOW, NOW - 2 * HOUR_MS);
        (a.level(), a.reasons)
    }

    #[test]
    fn calm_is_ok_without_reasons() {
        assert_eq!(of(&calm()), (Level::Ok, vec![]));
    }

    #[test]
    fn backup_boundaries() {
        let mut i = calm();
        i.backup.last_ok_ms = Some(NOW - BACKUP_STALE_WARN_MS);
        assert_eq!(of(&i), (Level::Ok, vec![]), "36시간 정각은 아직 정상");
        i.backup.last_ok_ms = Some(NOW - BACKUP_STALE_WARN_MS - 1);
        assert_eq!(of(&i), (Level::Warn, vec![R::BackupStale]));
        i.backup.last_ok_ms = Some(NOW - BACKUP_STALE_BAD_MS - 1);
        assert_eq!(of(&i), (Level::Bad, vec![R::BackupStale]));
        // 한 번도 없음: 켜진 지 36시간 넘으면 주의, 그 전엔 정상.
        i.backup.last_ok_ms = None;
        assert_eq!(of(&i).0, Level::Ok);
        let a = assess(&i, NOW, NOW - BACKUP_STALE_WARN_MS - 1);
        assert_eq!((a.level(), a.reasons), (Level::Warn, vec![R::BackupStale]));
        let mut i = calm();
        i.backup.last = BackupLast::Failed;
        i.backup.offsite = BackupOffsite::Failed;
        assert_eq!(
            of(&i),
            (Level::Bad, vec![R::BackupFailed, R::OffsiteFailed])
        );
        i.backup.last = BackupLast::Ok;
        assert_eq!(of(&i), (Level::Warn, vec![R::OffsiteFailed]));
        i.backup.offsite = BackupOffsite::Skipped;
        assert_eq!(of(&i), (Level::Ok, vec![]), "skipped 는 이유 아님");
    }

    #[test]
    fn disk_boundaries() {
        let mut i = calm();
        let total = 100_000_000_000;
        for (free, want) in [
            (15_000_000_000, Level::Ok),
            (14_999_999_999, Level::Warn),
            (5_000_000_000, Level::Warn),
            (4_999_999_999, Level::Bad),
        ] {
            i.disk = Some((free, total));
            assert_eq!(of(&i).0, want, "free {free}");
        }
        // 큰 디스크는 절대값이 먼저 걸린다(#899: 926 GB 중 52 GB 여유는 5.7% 지만 정상).
        let big = 926_000_000_000;
        for (free, want) in [
            (52_000_000_000, Level::Ok),
            (DISK_WARN_BYTES, Level::Ok),
            (DISK_WARN_BYTES - 1, Level::Warn),
            (19_000_000_000, Level::Warn),
            (DISK_BAD_BYTES, Level::Warn),
            (DISK_BAD_BYTES - 1, Level::Bad),
            (4_000_000_000, Level::Bad),
        ] {
            i.disk = Some((free, big));
            assert_eq!(of(&i).0, want, "926 GB 중 free {free}");
        }
        // 작은 디스크는 비율이 먼저 걸린다: 20 GB 의 15% = 3 GB, 5% = 1 GB.
        let small = 20_000_000_000;
        for (free, want) in [
            (3_000_000_000, Level::Ok),
            (2_500_000_000, Level::Warn),
            (1_000_000_000, Level::Warn),
            (900_000_000, Level::Bad),
        ] {
            i.disk = Some((free, small));
            assert_eq!(
                of(&i),
                (
                    want,
                    if want == Level::Ok {
                        vec![]
                    } else {
                        vec![R::DiskLow]
                    }
                ),
                "20 GB 중 free {free}"
            );
        }
        i.disk = None;
        assert_eq!(of(&i).0, Level::Ok, "모르면 판정 안 함");
    }

    /// 묶음 15 §2.7: 첨부 폴더 남은 공간이 `--blob-min-free` × 2 아래면 주의, 그 아래면 문제(`files_disk_low`).
    #[test]
    fn files_boundaries() {
        let mut i = calm();
        for (free, want) in [
            (10_000_000_000, Level::Ok),
            (9_999_999_999, Level::Warn),
            (5_000_000_000, Level::Warn),
            (4_999_999_999, Level::Bad),
        ] {
            i.blob_free = Some(free);
            let a = assess(&i, NOW, NOW - 2 * HOUR_MS);
            assert_eq!((a.files, a.level()), (want, want), "free {free}");
            let reasons = if want == Level::Ok {
                vec![]
            } else {
                vec![R::FilesDiskLow]
            };
            assert_eq!(a.reasons, reasons, "free {free}");
        }
        i.blob_free = None;
        assert_eq!(of(&i), (Level::Ok, vec![]), "모르면 판정 안 함");
    }

    #[test]
    fn queue_and_mail_boundaries() {
        let mut i = calm();
        i.pending = QUEUE_WARN;
        assert_eq!(of(&i).0, Level::Ok);
        i.pending = QUEUE_WARN + 1;
        assert_eq!(of(&i), (Level::Warn, vec![R::QueueHigh]));
        i.pending = QUEUE_BAD + 1;
        assert_eq!(of(&i), (Level::Bad, vec![R::QueueHigh]));
        let mut i = calm();
        i.sent_today = 63;
        assert_eq!(of(&i).0, Level::Ok);
        i.sent_today = 64;
        assert_eq!(of(&i), (Level::Warn, vec![R::MailQuota]));
        i.sent_today = 80;
        assert_eq!(of(&i), (Level::Bad, vec![R::MailQuota]));
        let mut i = calm();
        i.mail_last_failed_ms = Some(NOW - MAIL_FAILED_WINDOW_MS + 1);
        assert_eq!(of(&i), (Level::Warn, vec![R::MailFailed]));
        i.mail_last_failed_ms = Some(NOW - MAIL_FAILED_WINDOW_MS);
        assert_eq!(of(&i).0, Level::Ok);
    }
}
