//! JSON Canonicalization Scheme (RFC 8785).
//!
//! 구현은 `serde_json_canonicalizer` 크레이트에 맡기고, 여기서는 RFC 의 예제·부록 B 숫자 표를 시험으로 고정한다.
//! TS 쪽(`packages/protocol`)이 같은 fixtures 를 왕복해 바이트가 같아야 한다(m1-plan U1 완료 기준).

use serde::Serialize;

use crate::Result;

/// 값을 JCS 바이트로 직렬화한다.
///
/// # Errors
/// NaN·무한대, 고립 서로게이트 등 I-JSON 밖의 값이면 오류.
pub fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    Ok(serde_json_canonicalizer::to_vec(value)?)
}

/// 값을 JCS 문자열로 직렬화한다.
///
/// # Errors
/// [`to_vec`] 과 같다.
pub fn to_string<T: Serialize>(value: &T) -> Result<String> {
    Ok(serde_json_canonicalizer::to_string(value)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    #[test]
    fn rfc8785_section_3_2_sample() {
        // RFC 8785 §3.2.2 입력 → §3.2.3 출력
        let input = r#"{
          "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
          "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
          "literals": [null, true, false]
        }"#;
        let v: Value = serde_json::from_str(input).unwrap();
        let out = to_string(&v).unwrap();
        assert_eq!(
            out,
            "{\"literals\":[null,true,false],\"numbers\":[333333333.3333333,1e+30,4.5,0.002,1e-27],\"string\":\"€$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"}"
        );
    }

    #[test]
    fn rfc8785_section_3_2_3_unicode_key_order() {
        // RFC 8785 §3.2.3: 키는 UTF-16 코드 유닛 순. "\u{1f600}"(서로게이트 쌍, 0xd83d) 가 "\u{ff5e}" 보다 앞,
        // "\u{20ac}" 는 그보다 앞, 빈 문자열이 맨 앞.
        let input = r#"{
          "\u20ac": "Euro Sign",
          "\r": "Carriage Return",
          "\ufb33": "Hebrew Letter Dalet With Dagesh",
          "1": "One",
          "\ud83d\ude00": "Emoji: Grinning Face",
          "\u0080": "Control",
          "\u00f6": "Latin Small Letter O With Diaeresis"
        }"#;
        let v: Value = serde_json::from_str(input).unwrap();
        let out = to_string(&v).unwrap();
        assert_eq!(
            out,
            "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u{80}\":\"Control\",\"\u{f6}\":\"Latin Small Letter O With Diaeresis\",\"\u{20ac}\":\"Euro Sign\",\"\u{1f600}\":\"Emoji: Grinning Face\",\"\u{fb33}\":\"Hebrew Letter Dalet With Dagesh\"}"
        );
    }

    #[test]
    fn rfc8785_appendix_b_numbers() {
        // (IEEE 754 비트, 기대 표기) — RFC 8785 부록 B
        let cases: &[(u64, &str)] = &[
            (0x0000000000000000, "0"),
            (0x8000000000000000, "0"),
            (0x0000000000000001, "5e-324"),
            (0x8000000000000001, "-5e-324"),
            (0x7fefffffffffffff, "1.7976931348623157e+308"),
            (0xffefffffffffffff, "-1.7976931348623157e+308"),
            (0x4340000000000000, "9007199254740992"),
            (0xc340000000000000, "-9007199254740992"),
            (0x4430000000000000, "295147905179352830000"),
            (0x44b52d02c7e14af5, "9.999999999999997e+22"),
            (0x44b52d02c7e14af6, "1e+23"),
            (0x44b52d02c7e14af7, "1.0000000000000001e+23"),
            (0x444b1ae4d6e2ef4e, "999999999999999700000"),
            (0x444b1ae4d6e2ef4f, "999999999999999900000"),
            (0x444b1ae4d6e2ef50, "1e+21"),
            (0x3eb0c6f7a0b5ed8c, "9.999999999999997e-7"),
            (0x3eb0c6f7a0b5ed8d, "0.000001"),
            (0x41b3de4355555553, "333333333.3333332"),
            (0x41b3de4355555554, "333333333.33333325"),
            (0x41b3de4355555555, "333333333.3333333"),
            (0x41b3de4355555556, "333333333.3333334"),
            (0x41b3de4355555557, "333333333.33333343"),
            (0xbecbf647612f3696, "-0.0000033333333333333333"),
            (0x43143ff3c1cb0959, "1424953923781206.2"),
        ];
        for (bits, expect) in cases {
            let f = f64::from_bits(*bits);
            let v = json!(f);
            assert_eq!(to_string(&v).unwrap(), *expect, "bits {bits:016x}");
        }
    }

    #[test]
    fn nan_and_infinity_are_rejected() {
        // serde_json 은 NaN 을 null 로 만들기 때문에 Value 로는 못 만든다. 직접 Serialize 하는 타입으로 확인.
        assert!(to_vec(&f64::NAN).is_err());
        assert!(to_vec(&f64::INFINITY).is_err());
    }

    #[test]
    fn nested_objects_in_arrays_are_sorted_but_arrays_keep_order() {
        let v = json!({"b": [{"z": 1, "a": 2}, 3, {"y": null}], "a": {"d": 1, "c": 2}});
        assert_eq!(
            to_string(&v).unwrap(),
            r#"{"a":{"c":2,"d":1},"b":[{"a":2,"z":1},3,{"y":null}]}"#
        );
    }

    #[test]
    fn korean_emoji_newline_round_trip() {
        // AC-HH-5: 한글·이모지·줄바꿈이 그대로 남는다.
        let text = "안녕하세요 🙂\n두 번째 줄\t탭";
        let v = json!({"text": text});
        let out = to_string(&v).unwrap();
        assert_eq!(out, "{\"text\":\"안녕하세요 🙂\\n두 번째 줄\\t탭\"}");
        let back: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(back["text"], text);
    }
}
