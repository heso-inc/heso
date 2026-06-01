//! RFC 8785 (JSON Canonicalization Scheme) conformance vectors.
//!
//! This suite breaks the **self-validation circularity** elsewhere in the
//! codebase. Everywhere else, the only checks on the canonicalizer are
//! self-consistency (the same `serde_jcs` reached through one binary
//! agreeing with itself reached through another) or BLAKE3 hashes derived
//! *from* `serde_jcs` output. A `serde_jcs` upgrade that silently changed
//! number formatting, key ordering, or escaping would redden **none** of
//! those -- both producer and verifier share the one canonicalizer.
//!
//! Here the expected side is an **independent, spec-derived oracle**: the
//! exact bytes mandated by RFC 8785 (the section 3.2.2 string/number
//! rules, the ECMA-262 `Number.prototype.toString` of section 3.2.2.3,
//! the section 3.2.3 UTF-16 key-sort, Appendix B), cross-checked against
//! the cyberphone/json-canonicalization reference `es6testfile`. Each
//! `expected` byte string was re-derived by hand from the RFC text -- NOT
//! captured by blessing `serde_jcs` output. The suite is green against
//! `serde_jcs` 0.2.0 today and is therefore a regression lock: a future
//! bump that drifts off the spec reddens the exact affected row.
//!
//! Hermetic: pure in-memory `serde_json::from_str` -> `canonicalize_raw`
//! -> `assert_eq`. No network, filesystem, or clock.
//!
//! [RFC 8785]: https://www.rfc-editor.org/rfc/rfc8785

use heso_verify::canonicalize_raw;
use serde_json::Value;

/// Parse `input` JSON, canonicalize via the strip-free conformance
/// canonicalizer, and assert the bytes equal the spec-derived `expected`.
///
/// Uses [`canonicalize_raw`] (no `plat_hash`/`sig` strip) so a vector
/// whose top-level object legitimately contains those keys is not
/// corrupted by the hash/sign strip.
fn check(name: &str, input: &str, expected: &str) {
    let value: Value = serde_json::from_str(input)
        .unwrap_or_else(|e| panic!("[{name}] input is not valid JSON: {e}"));
    let got = canonicalize_raw(&value)
        .unwrap_or_else(|e| panic!("[{name}] canonicalize_raw failed: {e}"));
    assert_eq!(
        got,
        expected.as_bytes(),
        "[{name}] canonical bytes diverge from the RFC 8785 spec oracle\n  \
         got:      {:?}\n  expected: {:?}",
        String::from_utf8_lossy(&got),
        expected,
    );
}

/// RFC 8785 section 3.2.3 (Sorting of Object Properties) -- the canonical
/// surrogate-pair gotcha. Keys are sorted by their UTF-16 code units, NOT
/// by Unicode scalar value. The non-BMP emoji U+1F603 encodes in UTF-16
/// as the surrogate pair whose lead unit is 0xD83D; the Hebrew ligature
/// U+FB33 is a single BMP code unit 0xFB33. The comparison is on the
/// first differing UTF-16 unit, and 0xD83D < 0xFB33, so U+1F603 sorts
/// BEFORE U+FB33 -- the opposite of a naive scalar-value sort
/// (U+1F603 > U+FB33). This is the single most fragile row: a
/// "simplification" to code-point sorting silently inverts it.
///
/// Keep the inline `0xD83D < 0xFB33` comment -- it pins the ordering.
#[test]
fn rfc8785_object_key_sort_utf16_surrogates() {
    // Keys (deliberately supplied out of canonical order):
    //   U+0001 (control), U+000D ("\r"), "1", U+00F6, U+20AC, U+1F603,
    //   U+FB33. The control key is injected as a JSON  escape so the
    //   input is valid JSON; non-ASCII keys are raw UTF-8. `bs` is one
    //   backslash, used to spell \u / \r in the JSON text without raw
    //   control bytes in this source file.
    let bs = "\\";
    let input = String::from("{")
        + &format!("\"{bs}u0001\":\"ctrl\",")
        + &format!("\"{bs}r\":\"CR\",")
        + "\"1\":\"One\","
        + "\"\u{00f6}\":\"oe\","
        + "\"\u{20ac}\":\"Euro\","
        + "\"\u{1f603}\":\"smile\","
        + "\"\u{fb33}\":\"dalet\""
        + "}";

    // Canonical order by UTF-16 code units:
    //   U+0001 < U+000D(\r) < '1'(0x31) < U+00F6 < U+20AC
    //     < U+1F603(lead 0xD83D) < U+FB33.          // 0xD83D < 0xFB33
    // The control key emits as lowercase ""; "\r" uses its named
    // short escape; all non-ASCII keys/values pass through as raw UTF-8.
    let expected = "{\
\"\\u0001\":\"ctrl\",\
\"\\r\":\"CR\",\
\"1\":\"One\",\
\"\u{00f6}\":\"oe\",\
\"\u{20ac}\":\"Euro\",\
\"\u{1f603}\":\"smile\",\
\"\u{fb33}\":\"dalet\"\
}";
    check(
        "RFC8785 section 3.2.3 key sort (UTF-16 surrogates)",
        &input,
        expected,
    );
}

/// RFC 8785 section 3.2.2.3 (Serialization of Numbers) -- ECMA-262
/// `Number.prototype.toString`. The headline edge cases from the
/// cyberphone `es6testfile`, and the rows most likely to drift on a
/// `ryu`/`serde_jcs` bump. Each expected string is the ECMAScript
/// canonical form re-derived from ECMA-262 section 7.1.12.1, NOT
/// serde_jcs output.
#[test]
fn rfc8785_number_serialization() {
    let rows: &[(&str, &str)] = &[
        // 1e30: exponent >= 21 uses 'e+' form. RFC 8785 Appendix B.
        ("1e30", "1e+30"),
        // Negative zero collapses to "0" (ECMA-262 stringifies -0 as "0").
        ("-0", "0"),
        // Smallest positive subnormal double; ryu/ECMA-262 shortest form.
        ("5e-324", "5e-324"),
        // Largest finite double -- note the inserted '+' in the exponent.
        ("1.7976931348623157e308", "1.7976931348623157e+308"),
        // Long fraction preserved verbatim (JCS never rounds).
        ("333333333.3333333", "333333333.3333333"),
        // Trailing-zero fraction trimmed: 4.50 -> 4.5.
        ("4.50", "4.5"),
        // 2e-3 expands to plain decimal (exponent > -7): 0.002.
        ("2e-3", "0.002"),
        // 1e-6 stays plain decimal (the boundary, inclusive of -6).
        ("0.000001", "0.000001"),
        // 1e-7 crosses into exponential form: "1e-7".
        ("0.0000001", "1e-7"),
        // Large integer below 1e21 stays integer form (no exponent).
        ("295147905179352830000", "295147905179352830000"),
        // 1e-27 (far below the -7 boundary) -> "1e-27".
        ("0.000000000000000000000000001", "1e-27"),
        // Plain integers round-trip unchanged.
        ("0", "0"),
        ("100", "100"),
    ];
    for (input, expected) in rows {
        check(
            &format!("RFC8785 section 3.2.2.3 number {input} -> {expected}"),
            input,
            expected,
        );
    }
}

/// RFC 8785 section 3.2.2.2 (Serialization of Strings) -- escaping rules.
/// Named short escapes for backspace, form-feed, newline, carriage
/// return, tab, double-quote, backslash only; every other control in
/// U+0000..U+001F as lowercase `\u00xx`; the solidus `/` is NOT escaped;
/// non-ASCII passes through as raw UTF-8.
///
/// Control-character inputs are supplied as JSON `\uXXXX` escapes (spelled
/// with the `bs` backslash variable, so this source file holds no raw
/// control bytes); the canonicalizer re-emits them in lowercase short or
/// `\u` form.
#[test]
fn rfc8785_string_escaping() {
    let bs = "\\";
    let rows: Vec<(String, &str)> = vec![
        // The seven named short escapes, in order b f n r t " \.
        (
            format!("\"{bs}b{bs}f{bs}n{bs}r{bs}t{bs}\"{bs}{bs}\""),
            "\"\\b\\f\\n\\r\\t\\\"\\\\\"",
        ),
        // Unnamed controls U+0001 and U+001F -> lowercase \u00xx.
        (format!("\"{bs}u0001{bs}u001f\""), "\"\\u0001\\u001f\""),
        // Solidus is NOT escaped (RFC 8785 forbids escaping '/').
        ("\"a/b\"".to_string(), "\"a/b\""),
        // Raw UTF-8 passthrough for non-ASCII (NOT \u-escaped).
        (
            "\"\u{e9}\u{65e5}\u{672c}\"".to_string(),
            "\"\u{e9}\u{65e5}\u{672c}\"",
        ),
        // Currency sign U+20AC + non-BMP emoji U+1F603, both raw UTF-8.
        (
            "\"\u{20ac}\u{1f603}\"".to_string(),
            "\"\u{20ac}\u{1f603}\"",
        ),
        // Named (backspace) vs unnamed (U+0000) in one string.
        (format!("\"{bs}b{bs}u0000\""), "\"\\b\\u0000\""),
        // U+0080 is >= U+0020 so it is NOT escaped -- raw UTF-8 (0xC2 0x80).
        // Supplied as a \u escape; canonical form is the raw 2-byte UTF-8.
        (format!("\"{bs}u0080\""), "\"\u{0080}\""),
        // U+000F is an unnamed control -> lowercase .
        (format!("\"{bs}u000f\""), "\"\\u000f\""),
    ];
    for (input, expected) in &rows {
        check(
            &format!("RFC8785 section 3.2.2.2 string {input}"),
            input,
            expected,
        );
    }
}

/// RFC 8785 section 3.2.1 (Whitespace) + structural canonicalization.
/// Insignificant whitespace is stripped; arrays keep element order;
/// nested objects recursively key-sort; no space follows `:` or `,`.
#[test]
fn rfc8785_structural_whitespace_and_arrays() {
    // Arbitrary whitespace and out-of-order keys collapse to the compact,
    // key-sorted canonical form. Array element order is PRESERVED -- only
    // object keys sort.
    let input = r#"
        {
            "b" : [ 3 , 1 , 2 ] ,
            "a" : { "y" : true , "x" : false , "z" : null } ,
            "0" : "zero"
        }
    "#;
    let expected = "{\"0\":\"zero\",\"a\":{\"x\":false,\"y\":true,\"z\":null},\"b\":[3,1,2]}";
    check(
        "RFC8785 section 3.2.1 whitespace + array order",
        input,
        expected,
    );
}

/// RFC 8785 Appendix B (the worked example, abridged to the
/// number/literal/array/string/key-sort interplay). One divergence
/// anywhere -- number form, key order, escape, array order -- reddens this
/// single row.
#[test]
fn rfc8785_appendix_b_combined() {
    // string value carries: U+20AC (raw), '$', U+000F (-> ), 'A',
    //   '\'' (apostrophe NOT escaped), 'B', '"' (-> \"), '\' (-> \\),
    //   '"' (-> \"), '/' (raw). Built with the `bs` backslash variable so
    //   U+000F and the quote/backslash escapes are JSON text, not raw
    //   bytes.
    let bs = "\\";
    let input = String::from("{")
        + "\"numbers\":[333333333.33333329,1e30,4.50,2e-3,0.000000000000000000000000001],"
        + &format!(
            "\"string\":\"\u{20ac}${bs}u000fA'B{bs}\"{bs}{bs}{bs}\"/\","
        )
        + "\"literals\":[null,true,false]"
        + "}";

    // Keys sort literals < numbers < string. numbers:
    //   333333333.33333329 -> "333333333.3333333" (double shortest
    //   round-trip); 1e30 -> "1e+30"; 4.50 -> "4.5"; 2e-3 -> "0.002";
    //   1e-27 -> "1e-27".
    let expected = "{\
\"literals\":[null,true,false],\
\"numbers\":[333333333.3333333,1e+30,4.5,0.002,1e-27],\
\"string\":\"\u{20ac}$\\u000fA'B\\\"\\\\\\\"/\"\
}";
    check("RFC8785 Appendix B combined", &input, expected);
}
