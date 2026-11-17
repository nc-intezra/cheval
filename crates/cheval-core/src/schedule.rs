//! Run schedules for `cheval daemon` (`[daemon] schedule`): daily times or an interval.
use anyhow::{Context, Result, bail};
use chrono::{DateTime, Local, NaiveDateTime, NaiveTime, TimeZone};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Schedule {
    /// Every day at these local times (sorted).
    Daily(Vec<NaiveTime>),
    /// This long after the previous run started.
    Every(Duration),
}

impl Schedule {
    pub fn parse(s: &str) -> Result<Schedule> {
        let s = s.trim();
        if s.contains(':') {
            let mut times = Vec::new();
            for part in s.split(',') {
                let t = NaiveTime::parse_from_str(part.trim(), "%H:%M")
                    .with_context(|| format!("{part:?}: expected a time of day such as \"03:17\""))?;
                times.push(t);
            }
            times.sort();
            times.dedup();
            return Ok(Schedule::Daily(times));
        }
        let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
        let (num, unit) = s.split_at(split);
        let n: u64 = num.parse().with_context(|| {
            format!("{s:?}: expected times of day (\"03:17\", \"03:17,15:17\") or an interval (\"6h\", \"30m\")")
        })?;
        let secs = match unit.trim() {
            "s" => n,
            "m" | "min" => n * 60,
            "h" => n * 3600,
            "d" => n * 86_400,
            u => bail!("{s:?}: unknown unit {u:?} (use s, m, h or d)"),
        };
        if secs < 10 {
            bail!("{s:?}: the interval must be at least 10 seconds");
        }
        Ok(Schedule::Every(Duration::from_secs(secs)))
    }

    /// When the next run is due. `last_start` is the start of the previous run, or the
    /// daemon's own start when nothing has run yet.
    pub fn next(&self, now: DateTime<Local>, last_start: DateTime<Local>) -> DateTime<Local> {
        match self {
            Schedule::Every(d) => (last_start + chrono::Duration::from_std(*d).unwrap_or_default()).max(now),
            Schedule::Daily(times) => {
                let naive = next_daily(now.naive_local(), times);
                // A time that does not exist on the day clocks jump forward runs an hour later.
                Local
                    .from_local_datetime(&naive)
                    .earliest()
                    .or_else(|| Local.from_local_datetime(&(naive + chrono::Duration::hours(1))).earliest())
                    .unwrap_or(now + chrono::Duration::hours(24))
            }
        }
    }
}

/// First of `times` strictly after `now`, today or tomorrow.
fn next_daily(now: NaiveDateTime, times: &[NaiveTime]) -> NaiveDateTime {
    match times.iter().find(|t| **t > now.time()) {
        Some(t) => now.date().and_time(*t),
        None => (now.date() + chrono::Duration::days(1)).and_time(times[0]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

    fn at(h: u32, m: u32) -> NaiveDateTime {
        NaiveDate::from_ymd_opt(2026, 11, 12).unwrap().and_hms_opt(h, m, 30).unwrap()
    }

    #[test]
    fn schedules_parse() {
        let t = |h, m| NaiveTime::from_hms_opt(h, m, 0).unwrap();
        assert_eq!(Schedule::parse("03:17").unwrap(), Schedule::Daily(vec![t(3, 17)]));
        assert_eq!(Schedule::parse(" 15:17, 03:17,03:17 ").unwrap(), Schedule::Daily(vec![t(3, 17), t(15, 17)]));
        assert_eq!(Schedule::parse("6h").unwrap(), Schedule::Every(Duration::from_secs(21_600)));
        assert_eq!(Schedule::parse("30m").unwrap(), Schedule::Every(Duration::from_secs(1800)));
        assert_eq!(Schedule::parse("1d").unwrap(), Schedule::Every(Duration::from_secs(86_400)));
        for bad in ["", "25:00", "03:61", "6", "6w", "5s", "soon", "-1h", "03:17;04:00"] {
            assert!(Schedule::parse(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn daily_times_roll_over_to_tomorrow() {
        let times = [NaiveTime::from_hms_opt(3, 17, 0).unwrap(), NaiveTime::from_hms_opt(15, 17, 0).unwrap()];
        assert_eq!(next_daily(at(1, 0), &times), at(3, 17).with_second(0).unwrap());
        assert_eq!(next_daily(at(3, 16), &times).time(), times[0]);
        // 03:17:30 is past 03:17:00: the next slot is the afternoon one, not the same minute again.
        assert_eq!(next_daily(at(3, 17), &times).time(), times[1]);
        let tomorrow = next_daily(at(23, 0), &times);
        assert_eq!(tomorrow.date(), NaiveDate::from_ymd_opt(2026, 11, 13).unwrap());
        assert_eq!(tomorrow.time(), times[0]);
    }

    #[test]
    fn interval_counts_from_the_previous_start() {
        let s = Schedule::Every(Duration::from_secs(3600));
        let now = Local::now();
        assert_eq!(s.next(now, now - chrono::Duration::minutes(20)), now + chrono::Duration::minutes(40));
        // A run that took longer than the interval makes the next one due at once, not in the past.
        assert_eq!(s.next(now, now - chrono::Duration::hours(3)), now);
        let d = Schedule::parse("03:17").unwrap().next(now, now);
        assert!(d > now && d <= now + chrono::Duration::hours(25));
    }

    use chrono::Timelike;
}
