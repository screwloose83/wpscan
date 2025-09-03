<?php

$noColor = in_array('--no-color', $argv);
$quiet = in_array('--quiet', $argv);
$logFile = 'scan_log.txt';
$whitelistFile = 'whitelist_checksums.txt';
$coreChecksums = [];
$pluginChecksums = []; // [slug][relpath] => md5
$extraPatterns = [];

$excludeExtensions = ['jpg','jpeg','css','png','gif','webp','svg','mp4','mov','avi','mp3','woff','woff2','ttf','zip','gz','tar','tgz','bz2','7z','wpress','pdf','sql'];
$maxSizeMB = 10; // default 10MB cap for scanning
$fastDays = null;
$skippedDueToFast = 0;

// CLI
foreach ($argv as $arg) {
    if (preg_match('/^--fast=(\d+)$/', $arg, $m)) { $fastDays = (int)$m[1]; }
    if (preg_match('/^--exclude=(.+)$/', $arg, $m)) { $excludeExtensions = array_map('strtolower', explode(',', $m[1])); }
    if (preg_match('/^--max-size=(\d+)$/', $arg, $m)) { $maxSizeMB = (int)$m[1]; }
}

$fastDays = null;
$skippedDueToFast = 0;

if (in_array('--help', $argv)) {
    echo "Usage: php wpscan.php /path/to/scan [--quiet] [--no-color] [--fast=N]\n";
    echo "  --quiet       Suppress detailed output\n";
    echo "  --no-color    Disable colorized output\n";
    echo "  --fast=N      Scan only files modified in the last N days\n";
    echo "  --exclude=ext1,ext2  Comma-separated list of extensions to exclude\n";
    exit;
}

foreach ($argv as $arg) {
    if (preg_match('/^--fast=(\d+)/', $arg, $m)) {
        $fastDays = (int)$m[1];
    }
    if (preg_match('/^--exclude=(.+)$/', $arg, $m)) {
        $excludeExtensions = array_map('strtolower', explode(',', $m[1]));
    }
}

function ansi($code) { return chr(27) . "[" . $code . "m"; }
function color($text, $color) {
    global $noColor;
    if ($noColor) return $text;
    $colors = ['red'=>31,'green'=>32,'yellow'=>33,'blue'=>34,'magenta'=>35,'cyan'=>36,'gray'=>90];
    return isset($colors[$color]) ? ansi($colors[$color]) . $text . ansi(0) : $text;
}
function log_msg($msg, $color = null) {
    global $logFile;
    echo color($msg . "\n", $color);
    file_put_contents($logFile, "[" . date('Y-m-d H:i:s') . "] $msg\n", FILE_APPEND);
}
function save_to_whitelist($checksum) {
    global $whitelistFile;
    file_put_contents($whitelistFile, $checksum . "\n", FILE_APPEND | LOCK_EX);
}
function detect_wp_version($path) {
    $verFile = $path . '/wp-includes/version.php';
    if (file_exists($verFile)) {
        $contents = file_get_contents($verFile);
        if (preg_match('/\$wp_version\s*=\s*[\'"](.+?)[\'"]/', $contents, $matches)) {
            return $matches[1];
        }
    }
    return null;
}
function load_core_checksums($version) {
    global $coreChecksums;
    $url = "https://api.wordpress.org/core/checksums/1.0/?version=$version&locale=en_US";
    $json = file_get_contents($url);
    $data = json_decode($json, true);
    if (!empty($data['checksums'])) $coreChecksums = $data['checksums'];
}
function load_plugin_checksums($pluginSlug, $version) {
    global $pluginChecksums;
    $url = "https://downloads.wordpress.org/plugin-checksums/$pluginSlug/$version.json";
    $json = @file_get_contents($url);
    if (!$json) return;
    $data = json_decode($json, true);
    if (!isset($data['files'])) return;
    foreach ($data['files'] as $path => $info) {
        $pluginChecksums[$pluginSlug][$path] = $info['md5'];
    }
}
function load_patterns() {
    global $extraPatterns;
    if (file_exists('patterns_raw.txt')) {
        $lines = file('patterns_raw.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($lines as $pattern) $extraPatterns[] = trim($pattern);
        echo "[+] Loaded " . count($extraPatterns) . " extra patterns from patterns_raw.txt\n";
    }
}

function scan_file($filepath) {
    global $extraPatterns, $coreChecksums, $pluginChecksums, $whitelistFile;

    // Compute checksum once (doesn't load file into PHP memory)
    $checksum = @md5_file($filepath);
    if ($checksum === false) return;
    $whitelist = @file($whitelistFile, FILE_IGNORE_NEW_LINES);
    if ($whitelist && in_array($checksum, $whitelist, true)) return;

    // Stream the file line-by-line
    $fh = @fopen($filepath, 'r');
    if (!$fh) return;

    $matchFound = false;
    $lineNo = 0;
    while (($line = fgets($fh)) !== false) {
        $lineNo++;

        if (preg_match('/eval\s*\(/i', $line)) {
            log_msg("[ALERT] $filepath | Line $lineNo | Pattern: eval() | Match: \"eval(\"", 'red');
            $matchFound = true;
        }
        foreach ($extraPatterns as $pattern) {
            if (@preg_match($pattern, $line, $match)) {
                $matchedText = isset($match[0]) ? trim($match[0]) : '[match not captured]';
                log_msg("[ALERT] $filepath | Line $lineNo | Pattern: $pattern | Match: \"$matchedText\"", 'red');
                $matchFound = true;
            }
        }
    }
    fclose($fh);
    if (!$matchFound) return;

    // Core / plugin checksum handling
    $wpRoot = $GLOBALS['wp_root_path'] ?? getcwd();
    $relativePath = ltrim(str_replace($wpRoot . '/', '', realpath($filepath)), '/');
    $relativePath = str_replace('\\', '/', $relativePath);
    $actualMd5 = $checksum;

    // Core files
    if (isset($coreChecksums[$relativePath])) {
        $expected = $coreChecksums[$relativePath];
        if ($expected === $actualMd5) {
            log_msg("[INFO] $filepath matches official WP checksum. Skipping whitelist.", 'cyan');
            return;
        }
        echo color("[WARN] Core file mismatch. Show diff? [D=diff / Y=whitelist / N=skip]: ", 'yellow');
        $input = strtolower(trim(fgets(STDIN)));
        if ($input === 'd') {
            $wpVersion = detect_wp_version(dirname(dirname($filepath)));
            $githubUrl = "https://raw.githubusercontent.com/WordPress/WordPress/$wpVersion/$relativePath";
            $originalContent = @file_get_contents($githubUrl);
            if ($originalContent !== false) {
                $localLines  = explode("\n", @file_get_contents($filepath) ?: '');
                $remoteLines = explode("\n", $originalContent);
                echo color("== DIFF with official WordPress [$wpVersion] ==\n", 'magenta');
                $max = max(count($localLines), count($remoteLines));
                for ($i=0; $i<$max; $i++) {
                    $l = $localLines[$i]  ?? '';
                    $r = $remoteLines[$i] ?? '';
                    if ($l !== $r) {
                        echo color(sprintf("-%4d | %s\n", $i+1, $l), 'red');
                        echo color(sprintf("+%4d | %s\n", $i+1, $r), 'green');
                    }
                }
            } else {
                log_msg("[ERROR] Could not fetch official file for diff: $githubUrl", 'red');
            }
        } elseif ($input === 'y') {
            save_to_whitelist($checksum);
            log_msg("[WHITELISTED] $filepath (checksum) added to whitelist_checksums.txt", 'green');
        }
        return;
    }

    // Plugin files
    if (!empty($pluginChecksums)) {
        foreach ($pluginChecksums as $slug => $files) {
            $pluginBase = "wp-content/plugins/$slug/";
            if (strpos($relativePath, $pluginBase) === 0) {
                $relPluginPath = substr($relativePath, strlen($pluginBase));
                if (isset($files[$relPluginPath])) {
                    $expected = $files[$relPluginPath];
                    if ($expected === $actualMd5) {
                        log_msg("[INFO] $filepath matches plugin checksum ($slug).", 'cyan');
                        return;
                    }
                    log_msg("[WARN] Plugin file mismatch in $slug: $relPluginPath", 'yellow');
                }
            }
        }
    }

    // Non-core (or no checksum available): prompt whitelist
    echo color("Add checksum for $filepath to whitelist? [y/N]: ", 'yellow');
    $input = trim(fgets(STDIN));
    if (strtolower($input) === 'y') {
        save_to_whitelist($checksum);
        log_msg("[WHITELISTED] $filepath (checksum) added to whitelist_checksums.txt", 'green');
    }
}

function scan_dir($dir) {
    echo "[*] Scanning directory: $dir\n";
    global $quiet, $fastDays, $excludeExtensions, $maxSizeMB;

    // Pass 1: count files cheaply (consumes iterator)
    $it1 = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS));
    $total = iterator_count($it1);

    // Pass 2: actual scan (new iterator)
    $iter = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS));
    $count = 0;

    foreach ($iter as $file) {
        $count++;
        if ($file->isFile()) {
            $path = $file->getPathname();

            // Skip excluded extensions
            $ext = strtolower(pathinfo($file->getFilename(), PATHINFO_EXTENSION));
            if (in_array($ext, $excludeExtensions, true)) continue;

            // Skip UpdraftPlus backups
            if (strpos($path, '/wp-content/updraft/') !== false) continue;

            // Fast mode: only recent files
            if ($fastDays !== null && $file->getMTime() < strtotime("-{$fastDays} days")) {
                $GLOBALS['skippedDueToFast']++;
                continue;
            }

            // Size cap (in MB)
            if ($maxSizeMB !== null && $maxSizeMB > 0) {
                $bytes = $file->getSize();
                if ($bytes !== false && $bytes > ($maxSizeMB * 1024 * 1024)) {
                    if (!$quiet) log_msg("[SKIP] >{$maxSizeMB}MB: $path", 'gray');
                    continue;
                }
            }

            if (!$quiet) echo color("[*] Checking: $path\n", 'gray');
            scan_file($path);
        }

        if (($count % 25 === 0) || ($count === $total)) {
            $percent = $total ? number_format(($count / $total) * 100, 1) : '0.0';
            echo color("[=] Progress: $count / $total files ($percent%)\n", 'cyan');
        }
    }
}

// === MAIN ===
$target = $argv[1] ?? '';
if (!$target) die("Usage: php wpscan.php /path/to/scan [--quiet] [--no-color]\n");

load_patterns();
$wpVer = detect_wp_version($target);
if ($wpVer) {
    echo "[+] WordPress detected at $target (v$wpVer)\n";
    load_core_checksums($wpVer);
    $GLOBALS['wp_root_path'] = realpath($target);
}

$pluginsDir = $target . '/wp-content/plugins';
if (is_dir($pluginsDir)) {
    foreach (glob($pluginsDir . '/*', GLOB_ONLYDIR) as $pluginPath) {
        $slug = basename($pluginPath);
        $mainFile = "$pluginPath/$slug.php";
        $readme = "$pluginPath/readme.txt";
        $version = null;
        if (file_exists($mainFile) && preg_match('/Version:\s*(.+)/i', file_get_contents($mainFile), $m)) {
            $version = trim($m[1]);
        } elseif (file_exists($readme) && preg_match('/Stable tag:\s*(.+)/i', file_get_contents($readme), $m)) {
            $version = trim($m[1]);
        }
        if ($version) load_plugin_checksums($slug, $version);
    }
}

log_msg("[*] Starting scan in: $target", 'blue');
scan_dir($target);
echo "[?] Scan complete.\n";
if ($fastDays !== null) echo "[?] Skipped $skippedDueToFast files due to --fast=$fastDays\n";
?>
