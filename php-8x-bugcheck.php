<?php
/**
 * php-8x-bugcheck - behaviour checks for PHP 8.4 / 8.5 / 8.6 builds.
 *
 * Prints one state line per area and nothing else: no payload bytes, no crash
 * inputs, no root-cause notes. Every line is "ok", "BUG", or "NA" when the
 * extension the check needs is not loaded.
 *
 * A "BUG" line means this build does not behave the way a fixed build should.
 * It does not by itself prove that anything is exploitable, and an all-clear
 * run does not prove that a host is safe.
 *
 * Deliberately not included: memory-corruption reproducers, GD brush/one-shot
 * inputs, /proc access, and any deserialisation or phar payload.
 */
declare(strict_types=1);

header('Content-Type: text/plain; charset=utf-8');
error_reporting(0);
ini_set('display_errors', '0');

if (PHP_SAPI === 'cli' && in_array($argv[1] ?? '', ['-h', '--help'], true)) {
    fwrite(STDOUT, "php-8x-bugcheck - read-only behaviour checks\n\n");
    fwrite(STDOUT, "  php php-8x-bugcheck.php\n\n");
    fwrite(STDOUT, "Prints one line per area. Exit code 1 when any area reports BUG.\n");
    exit(0);
}

function line(string $name, string $value): void
{
    printf("%-22s %s\n", $name, $value);
}

line('php', PHP_VERSION);
line('sapi', PHP_SAPI);
line('arch', php_uname('m'));
line('opcache', extension_loaded('Zend OPcache') ? (string) ini_get('opcache.enable') : 'absent');
line('open_basedir', ini_get('open_basedir') === '' ? 'unset' : 'set');
line('disable_functions', trim((string) ini_get('disable_functions')) === '' ? 'unset' : 'set');
line('memory_limit', (string) ini_get('memory_limit'));
echo "\n";

$checks = [];

/* Does FILTER_VALIDATE_URL accept alternative numeric spellings of an IPv4 host? */
$urls = [
    'http://2130706433/', 'http://127.1/', 'http://0x7f000001/',
    'http://0x7f.1/', 'http://0177.0.0.1/', 'https://192.168/',
];
$accepted = 0;
foreach ($urls as $url) {
    if (@filter_var($url, FILTER_VALIDATE_URL) !== false) {
        $accepted++;
    }
}
$checks['url_numeric_hosts'] = $accepted . '/' . count($urls) . ($accepted ? ' BUG' : ' ok');

/* Does an out-of-range relative date offset wrap instead of failing? */
$date = @date_create('+999999');
$year = $date ? (int) $date->format('Y') : 0;
$checks['date_out_of_range'] = $year > 9998 ? 'BUG' : 'ok';

/* Does a numeric-string conversion stop at an embedded NUL? */
if (function_exists('bcadd')) {
    $bc = @bcadd("1\x002", '0');
    $checks['numeric_nul'] = $bc === '1' ? 'BUG' : 'ok';
} else {
    $checks['numeric_nul'] = 'NA';
}

/* Does SQLite3 return the full contents of a TEXT value containing NUL? */
$checks['sqlite_nul_text'] = 'NA';
if (class_exists('SQLite3')) {
    try {
        $db = new SQLite3(':memory:');
        $db->exec('CREATE TABLE t(v TEXT)');
        $st = $db->prepare('INSERT INTO t VALUES (?)');
        $st->bindValue(1, "A\0B", SQLITE3_TEXT);
        $st->execute();
        $stored = (string) $db->querySingle('SELECT v FROM t');
        $checks['sqlite_nul_text'] = strlen($stored) === 1 ? 'BUG' : 'ok';
        $db->close();
    } catch (Throwable $e) {
        $checks['sqlite_nul_text'] = 'NA';
    }
}

/* Does a deep clone of a <template> element keep its children? */
$checks['dom_template'] = 'NA';
if (class_exists('Dom\\HTMLDocument')) {
    try {
        $doc = Dom\HTMLDocument::createFromString(
            '<!doctype html><template id="t"><b>x</b></template>',
            LIBXML_NOERROR
        );
        $tpl = $doc->getElementById('t');
        $copy = $tpl->cloneNode(true);
        $checks['dom_template'] = str_contains($copy->innerHTML, 'x') ? 'ok' : 'BUG';
    } catch (Throwable $e) {
        $checks['dom_template'] = 'NA';
    }
}

/* Does a multibyte replacement longer than the pattern inflate the subject? */
$checks['mb_replacement'] = 'NA';
if (function_exists('mb_ereg_replace')) {
    $in = str_repeat('A', 6) . "\xF0";
    $out = (string) @mb_ereg_replace('a', $in, 'a');
    $checks['mb_replacement'] = strlen($out) > strlen($in) ? 'BUG' : 'ok';
}

/* Does IDNA map a fullwidth commercial-at to ASCII "@" instead of rejecting it? */
$checks['idn_at_sign'] = 'NA';
if (function_exists('idn_to_ascii')) {
    $info = [];
    $mapped = @idn_to_ascii("\u{FF20}a", IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46, $info);
    $checks['idn_at_sign'] = (is_string($mapped) && ($info['errors'] ?? 1) === 0) ? 'BUG' : 'ok';
}

/* Does the GD2 writer produce an image that the GD2 reader accepts? */
$checks['gd2_support'] = 'NA';
if (function_exists('imagegd2') && function_exists('imagecreatetruecolor')) {
    $tmp = tempnam(sys_get_temp_dir(), 'gd2');
    $warning = '';
    set_error_handler(function (int $no, string $msg) use (&$warning): bool {
        $warning = $msg;
        return true;
    });
    $written = imagegd2(imagecreatetruecolor(4, 4), $tmp);
    restore_error_handler();

    $size = @filesize($tmp) ?: 0;
    if (preg_match('/disabled|not supported|compiled/i', $warning)) {
        // The writer is a stub in this build: GD2 was compiled out of libgd.
        $checks['gd2_support'] = 'unavailable';
    } elseif (!$written) {
        $checks['gd2_support'] = 'unavailable';
    } elseif ($size === 0) {
        // Reported success without writing anything at all.
        $checks['gd2_support'] = 'BUG';
    } elseif (!@imagecreatefromgd2($tmp)) {
        // Wrote a file it refuses to read back.
        $checks['gd2_support'] = 'BUG';
    } else {
        $checks['gd2_support'] = 'available';
    }
    @unlink($tmp);
}

/* Does proc_open() accept an embedded NUL in the working directory? */
$checks['path_nul'] = 'NA';
if (function_exists('proc_open')) {
    $err = '';
    set_error_handler(function (int $no, string $msg) use (&$err): bool {
        $err = $msg;
        return true;
    });
    // Starts a single /bin/true; nothing else is executed anywhere in this script.
    $proc = @proc_open(['/bin/true'], [1 => ['pipe', 'w']], $pipes, sys_get_temp_dir() . "\0x");
    restore_error_handler();

    if (is_resource($proc)) {
        @proc_close($proc);
        $checks['path_nul'] = 'BUG';
    } elseif (preg_match('/null bytes/i', $err)) {
        $checks['path_nul'] = 'ok';
    }
}

foreach ($checks as $name => $value) {
    line($name, $value);
}

$bugs = 0;
$na = 0;
foreach ($checks as $value) {
    if (str_contains($value, 'BUG')) {
        $bugs++;
    } elseif ($value === 'NA') {
        $na++;
    }
}

echo "\n";
line('result', 'detection only, no exploit payloads included');
line('summary', sprintf('BUG=%d NA=%d checks=%d', $bugs, $na, count($checks)));

if (PHP_SAPI === 'cli') {
    exit($bugs > 0 ? 1 : 0);
}
