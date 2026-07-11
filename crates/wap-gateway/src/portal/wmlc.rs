//! Minimal WBXML v1.1 / WML 1.1 encoder for the built-in portal.
//!
//! This is deliberately *not* a general WBXML library. It emits exactly the
//! subset needed to build 3–4 short pages that render on MTP3550 /
//! MTP6550 hardware:
//!
//! * WBXML version **0x01** (v1.1). Tonight's H35 chain proved that anything
//!   newer (0x03) rejects on the MTP6550.
//! * WML **public-ID `-//WAPFORUM//DTD WML 1.1//EN`**, well-known integer
//!   `0x04`.
//! * UTF-8 charset (MIB 106 = 0x6A).
//! * **Empty string table** — every string is inlined with `STR_I`
//!   (`0x03 … 0x00`). Simpler to write and every browser we care about
//!   handles it.
//!
//! Tag codes come from WAP-238 §14.3.3.1 (WML 1.1 code page 0). We only need
//! the tiny subset used in the portal pages, so they are declared as `const`s
//! here rather than a table.

/// WBXML global token: inline NUL-terminated string.
pub const STR_I: u8 = 0x03;
/// WBXML global token: element with content (tag payload byte becomes
/// `tag_code | CONTENT_MASK`). Followed by content + [`END`].
pub const CONTENT_MASK: u8 = 0x40;
/// WBXML global token: element has attribute list (payload byte becomes
/// `tag_code | ATTR_MASK`). Attribute list terminates with [`END`].
pub const ATTR_MASK: u8 = 0x80;
/// WBXML global token: end-of-element / end-of-attribute-list marker.
pub const END: u8 = 0x01;

/// WML 1.1 tag codes (WAP-238 §14.3.3.1) — only the ones we emit.
pub mod tag {
    pub const WML: u8 = 0x3F;
    pub const CARD: u8 = 0x27;
    pub const P: u8 = 0x20;
    pub const BR: u8 = 0x22;
    pub const A: u8 = 0x1C;
}

/// WML 1.1 attribute-start codes.
pub mod attr {
    pub const HREF: u8 = 0x4A;
}

/// Public identifier code for `-//WAPFORUM//DTD WML 1.1//EN`.
const PUBLIC_ID_WML_1_1: u8 = 0x04;
/// MIB code for UTF-8 charset (IANA 106).
const CHARSET_UTF8: u8 = 0x6A;
/// WBXML version byte — v1.1 (`0x01`). Proven to render on both MTP3550 and MTP6550.
const WBXML_VERSION: u8 = 0x01;

/// Maximum encoded WMLC bytes per page. Empirically 386 B renders reliably
/// on MTP3550; we shave a safety margin to leave room for WSP framing.
pub const MAX_PAGE_BYTES: usize = 350;

/// Emit the WBXML header: version (0x01) + public-id (0x04) + charset (0x6A)
/// + string-table length (0 as uintvar). This exact 4-byte prefix is what
/// the H35 known-good response begins with (`01 04 6a 00`).
pub fn header() -> Vec<u8> {
    vec![WBXML_VERSION, PUBLIC_ID_WML_1_1, CHARSET_UTF8, 0x00]
}

/// Append an inline STR_I string. Bytes are copied verbatim after a leading
/// `0x03` and followed by a `0x00` terminator, per WBXML §5.8.4.4.
pub fn push_str_i(out: &mut Vec<u8>, s: &str) {
    out.push(STR_I);
    out.extend_from_slice(s.as_bytes());
    out.push(0x00);
}

/// Emit a self-closing element with no content and no attributes.
pub fn push_empty_element(out: &mut Vec<u8>, tag_code: u8) {
    out.push(tag_code);
}

/// Emit an element with inline text content: `<tag>text</tag>`. When `text`
/// is empty the element is emitted as an empty tag (no content byte).
pub fn push_text_element(out: &mut Vec<u8>, tag_code: u8, text: &str) {
    if text.is_empty() {
        push_empty_element(out, tag_code);
        return;
    }
    out.push(tag_code | CONTENT_MASK);
    push_str_i(out, text);
    out.push(END);
}

/// Emit `<a href="url">label</a>` in the smallest WBXML form we can get away
/// with. `href` is emitted as a plain `HREF` attribute + STR_I string.
pub fn push_anchor(out: &mut Vec<u8>, href: &str, label: &str) {
    // element has content AND attributes → tag | CONTENT_MASK | ATTR_MASK.
    out.push(tag::A | CONTENT_MASK | ATTR_MASK);
    // attribute list.
    out.push(attr::HREF);
    push_str_i(out, href);
    out.push(END); // end of attribute list.
    // content.
    push_str_i(out, label);
    out.push(END); // end of element.
}

/// Emit a paragraph break: closes the currently-open `<p>` and opens a
/// new one. Use this instead of a `<br/>` element when you need MTP
/// UP.Browser (Motorola firmware) to reliably render a hard line break —
/// `<br/>` inside a single `<p>` can be rendered as a soft space.
///
/// Must only be called from inside a [`wrap_card`] fill closure, and
/// only after emitting at least one child of the current `<p>`.
pub fn push_paragraph_break(out: &mut Vec<u8>) {
    out.push(END); // </p>
    out.push(tag::P | CONTENT_MASK); // <p>
}

/// Wrap a body producer with the standard `<wml><card><p>…</p></card></wml>`
/// chrome. Returns the fully-encoded WMLC bytes.
pub fn wrap_card<F: FnOnce(&mut Vec<u8>)>(title: &str, fill: F) -> Vec<u8> {
    let mut out = header();

    // <wml>
    out.push(tag::WML | CONTENT_MASK);

    // <card> — we skip attributes (title etc.) to keep the byte budget tight.
    // The `title` argument stays in the signature so callsites document intent.
    let _ = title;
    out.push(tag::CARD | CONTENT_MASK);

    // <p>
    out.push(tag::P | CONTENT_MASK);

    fill(&mut out);

    out.push(END); // </p>
    out.push(END); // </card>
    out.push(END); // </wml>

    debug_assert!(
        out.len() <= MAX_PAGE_BYTES,
        "portal page = {} B (budget {})",
        out.len(),
        MAX_PAGE_BYTES
    );

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_matches_h35_known_good_prefix() {
        assert_eq!(header(), vec![0x01, 0x04, 0x6a, 0x00]);
    }

    #[test]
    fn wrap_card_emits_valid_frame() {
        let bytes = wrap_card("t", |out| push_str_i(out, "hi"));
        assert!(bytes.starts_with(&[0x01, 0x04, 0x6a, 0x00]));
        assert!(bytes.ends_with(&[END, END, END]));
        assert!(bytes.len() <= MAX_PAGE_BYTES);
    }

    #[test]
    fn push_anchor_shape() {
        let mut out = Vec::new();
        push_anchor(&mut out, "/portal", "home");
        assert_eq!(out[0], tag::A | CONTENT_MASK | ATTR_MASK);
        assert_eq!(*out.last().unwrap(), END);
    }

    #[test]
    fn push_text_element_empty_yields_bare_tag() {
        let mut out = Vec::new();
        push_text_element(&mut out, tag::BR, "");
        assert_eq!(out, vec![tag::BR]);
    }
}
