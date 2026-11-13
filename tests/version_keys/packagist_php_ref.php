<?php
// packagist_php_ref.php answers PHP's own comparisons of Packagist versions, for
// test_packagist_php.py: the real PHP behind packagist_ref.py, which is a Python port.
// Input: one pair "a<TAB>b" per line. Output: one line per pair, "raw<TAB>composer":
//   raw       version_compare(a, b) on the strings with a leading v dropped:
//             the order osv.dev's PackagistVersion ports;
//   composer  version_compare of VersionParser::normalize(a) and normalize(b): the order Composer
//             gives what a user installs; ERR when normalize refuses either version.
// Composer's parser comes from the Debian package php-composer-semver.
require '/usr/share/php/Composer/Semver/autoload.php';

use Composer\Semver\VersionParser;

$parser = new VersionParser();

function strip_v(string $version): string
{
    return (strlen($version) > 0 && $version[0] === 'v') ? substr($version, 1) : $version;
}

while (($line = fgets(STDIN)) !== false) {
    [$a, $b] = explode("\t", rtrim($line, "\n"));
    $raw = version_compare(strip_v($a), strip_v($b));
    try {
        $composer = version_compare($parser->normalize($a), $parser->normalize($b));
    } catch (UnexpectedValueException $e) {
        $composer = 'ERR';
    }
    echo $raw, "\t", $composer, "\n";
}
