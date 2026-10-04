<?php

declare(strict_types=1);

require_once __DIR__ . '/admin_common.php';

/* admin_captcha.php - GET, unauthenticated (shown on the login screen itself,
   before any session exists). Generates a short random code, stores it in
   the session, and streams back an image of that code for the user to read
   and retype. Only the password-login path requires this; passkey/fingerprint
   login never calls this endpoint at all, so it stays fast.

   No external libraries and no stored image files - everything is drawn on
   the fly. Uses GD when available (virtually always true on cPanel/shared
   hosting) and falls back to a hand-built SVG (needs nothing but PHP itself)
   if GD is somehow missing, so this never leaves the login screen without a
   captcha to show. */

try {
    $config = nutricula_admin_load_config();
    nutricula_admin_start_session($config);

    // Unambiguous character set only - no 0/O, 1/I/l, 2/Z, 5/S, 8/B mixups,
    // since the one admin actually has to read and retype this correctly.
    $chars = 'ACDEFGHJKLMNPQRTUVWXY34679';
    $code = '';
    for ($i = 0; $i < 5; $i++) {
        $code .= $chars[random_int(0, strlen($chars) - 1)];
    }
    $_SESSION['nutricula_admin_captcha_code'] = $code;
    $_SESSION['nutricula_admin_captcha_at'] = time();
    session_write_close();

    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('Pragma: no-cache');

    $w = 160;
    $h = 56;

    if (extension_loaded('gd')) {
        header('Content-Type: image/png');

        $im = imagecreatetruecolor($w, $h);
        $bg = imagecolorallocate($im, 241, 244, 238);
        imagefilledrectangle($im, 0, 0, $w, $h, $bg);

        // Noise lines behind the text.
        for ($i = 0; $i < 7; $i++) {
            $c = imagecolorallocate($im, random_int(170, 205), random_int(170, 205), random_int(170, 205));
            imageline($im, random_int(0, $w), random_int(0, $h), random_int(0, $w), random_int(0, $h), $c);
        }
        // Scattered dots for extra texture.
        for ($i = 0; $i < 60; $i++) {
            $c = imagecolorallocate($im, random_int(180, 215), random_int(180, 215), random_int(180, 215));
            imagesetpixel($im, random_int(0, $w - 1), random_int(0, $h - 1), $c);
        }

        // Draw each character separately (GD's built-in font 5, no TTF
        // dependency needed) with a random baseline jitter and a random
        // dark color per character, so they don't all sit in one neat row.
        $charW = 15; // imagechar() font 5 glyph width
        $startX = (int)(($w - $charW * strlen($code)) / 2);
        for ($i = 0; $i < strlen($code); $i++) {
            $x = $startX + $i * $charW + random_int(-2, 2);
            $y = random_int(12, 20);
            $textColor = imagecolorallocate($im, random_int(20, 60), random_int(25, 70), random_int(20, 60));
            imagechar($im, 5, $x, $y, $code[$i], $textColor);
        }

        imagepng($im);
        imagedestroy($im);
    } else {
        // GD missing - fall back to an inline SVG. Still an <img>-compatible
        // image response, so the frontend needs no special-casing.
        header('Content-Type: image/svg+xml');

        $lines = '';
        for ($i = 0; $i < 6; $i++) {
            $x1 = random_int(0, $w); $y1 = random_int(0, $h);
            $x2 = random_int(0, $w); $y2 = random_int(0, $h);
            $lines .= "<line x1=\"$x1\" y1=\"$y1\" x2=\"$x2\" y2=\"$y2\" stroke=\"#c7cfc0\" stroke-width=\"1\"/>";
        }
        $glyphs = '';
        $charW = $w / (strlen($code) + 1);
        for ($i = 0; $i < strlen($code); $i++) {
            $x = (int)($charW * ($i + 0.8));
            $y = random_int(32, 42);
            $rot = random_int(-18, 18);
            $ch = htmlspecialchars($code[$i], ENT_QUOTES);
            $glyphs .= "<text x=\"$x\" y=\"$y\" transform=\"rotate($rot $x $y)\" font-family=\"monospace\" font-size=\"26\" font-weight=\"700\" fill=\"#242b22\">$ch</text>";
        }
        echo '<svg xmlns="http://www.w3.org/2000/svg" width="' . $w . '" height="' . $h . '" viewBox="0 0 ' . $w . ' ' . $h . '">'
            . '<rect width="100%" height="100%" fill="#f1f4ee"/>'
            . $lines . $glyphs . '</svg>';
    }
} catch (Throwable $e) {
    error_log('[Nutricula admin captcha] ' . $e->getMessage());
    http_response_code(500);
    header('Content-Type: text/plain');
    echo '';
}
