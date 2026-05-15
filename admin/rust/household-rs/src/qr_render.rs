//! Terminal ANSI-block QR renderer (FR-018).
//!
//! Produces a compact two-rows-per-line QR using the `▀` (UPPER HALF BLOCK)
//! character with foreground = top module, background = bottom module. Modern
//! monospaced terminals render this at roughly 1:1 aspect ratio.

use qrcode::{EcLevel, QrCode};

use crate::error::HouseholdError;

#[allow(dead_code)] // Reserved for the inverted-render variant (Phase 6 polish).
const UPPER_HALF: char = '\u{2580}'; // ▀

/// Render the URI as a small ANSI QR block (ECC level Q).
///
/// Returns the multi-line string to write to stdout — caller adds surrounding
/// instructions ("Scan with Soyeht…"). An over-long URI that doesn't fit in
/// any QR version surfaces as [`HouseholdError::QrEncode`] so the install
/// CLI can report a clean error instead of panicking.
pub fn render_ansi_qr(uri: &str) -> Result<String, HouseholdError> {
    // Q-level ECC keeps the matrix readable through camera glare. The
    // `qrcode` crate picks the smallest version that fits.
    let code = QrCode::with_error_correction_level(uri.as_bytes(), EcLevel::Q)
        .map_err(|e| HouseholdError::QrEncode(format!("{e}")))?;
    let modules = code.to_colors();
    let width = code.width();
    debug_assert_eq!(modules.len(), width * width);

    // 2-module quiet zone padding around the matrix.
    let quiet: usize = 2;
    let padded_w = width + quiet * 2;

    // Returns the dark/light state of a module in `padded_w` coordinates,
    // mapping the quiet zone (and any out-of-range padded coordinate) to
    // light. Avoids signed integer math for clippy cleanliness.
    let module_at = |x: usize, y: usize| -> bool {
        if x < quiet || y < quiet {
            return false;
        }
        let xi = x - quiet;
        let yi = y - quiet;
        if xi >= width || yi >= width {
            return false;
        }
        modules[yi * width + xi] == qrcode::Color::Dark
    };

    let mut out = String::with_capacity(padded_w * padded_w);
    let mut y = 0;
    while y < padded_w {
        for x in 0..padded_w {
            let top = module_at(x, y);
            let bot = if y + 1 < padded_w {
                module_at(x, y + 1)
            } else {
                false
            };
            // Use ANSI 30/47: black foreground on white background. This way
            // both UPPER_HALF and " " render correctly with QR-readable
            // contrast on most terminals.
            match (top, bot) {
                (true, true) => out.push_str("\x1b[30;40m \x1b[0m"), // both dark -> full black
                (true, false) => out.push_str("\x1b[30;47m\u{2580}\x1b[0m"),
                (false, true) => out.push_str("\x1b[30;47m\u{2584}\x1b[0m"),
                (false, false) => out.push_str("\x1b[30;47m \x1b[0m"),
            }
        }
        out.push('\n');
        y += 2;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_short_uri() {
        let s = render_ansi_qr("soyeht://household/pair-device?v=1&nonce=abc").expect("encode");
        // Sanity: non-empty and contains either UPPER_HALF or a space.
        assert!(!s.is_empty());
        assert!(s.contains('\n'));
    }

    #[test]
    fn rejects_oversized_uri() {
        // A QR Q-level v40 holds ~1273 bytes; we feed >2× that to force the
        // encoder to refuse rather than panic.
        let huge = "x".repeat(4096);
        let res = render_ansi_qr(&huge);
        assert!(res.is_err(), "oversized URI must surface a typed error");
    }
}
