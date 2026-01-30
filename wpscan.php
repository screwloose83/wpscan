<?php
/* ============================================================
   WordPress Incident Scanner / Integrity Monitor
   ------------------------------------------------------------

   New in this version:
   - Binary/executable detection (ELF, PE/EXE, Mach-O) with ClamAV
   - Executable scan runs regardless of text-pattern hits
   - Uploads watcher flags extensionless executables
   - --bin-quarantine to aggressively quarantine unexpected binaries
   - --no-clamav to disable ClamAV scanning entirely

   Newer changes:
   - Cache for official checksums (~/.wpscan-cache)
   - NEW: ZIP cache (~/.wpscan-cache/zips)
   - NEW: Extracted-file cache (~/.wpscan-cache/files)
   - NEW: Interactive repair of core/plugin/theme files using official ZIPs
   - NEW: Final summary lists [ALERT] lines and core/plugin/theme mismatches

   NEW (requested):
   - Backup option for *repairs* before overwriting any file:
       --repair-backup
       --repair-backup=/path/to/dir
     (backs up original file(s) before core/plugin/theme repair writes)

   NEW (added here):
   - WordPress DB option injection detector for "Header, Footer and Post Injections" (hefo)
   - Stronger wp_options scanning (not only autoload=yes)
   ============================================================ */


/* ===========================
   GLOBAL CONFIG / STATE
   =========================== */

$logFile           = 'scan_log.txt';
$whitelistFile     = 'whitelist_checksums.txt';

// legit admin usernames you expect
$knownGoodAdmins   = ['admin']; // <-- EDIT THIS PER SITE

$coreChecksums      = []; // official WP core file md5s
$pluginChecksums    = []; // [slug] => relpath=>md5
$themeChecksums     = []; // [slug] => relpath=>md5
$pluginVersions     = []; // [slug] => version (for repair)
$themeVersions      = []; // [slug] => version (for repair)
$checksumsAvailable = false; // core availability

// cache dir for downloaded checksums, zips, and extracted files
$baseCacheDir      = rtrim(getenv('HOME') ?: '/root', '/') . '/.wpscan-cache';
$checksumCacheDir  = $baseCacheDir;
$zipCacheDir       = $baseCacheDir . '/zips';
$fileCacheDir      = $baseCacheDir . '/files';

$extraPatterns     = []; // suspicious regex lines from patterns_raw.txt

$excludeExtensions = [
    'jpg','jpeg','css','png','gif','webp','svg','mp4','mov','avi','mp3',
    'woff','woff2','ttf','zip','gz','tar','tgz','bz2','7z','wpress','pdf','sql','html','mo','eot'
];

// Allowlist for common legit "extra" files
$extraFileAllow = [
    'wp-config.php',
    '.htaccess',
];

$maxSizeMB         = 10;
$fastDays          = null;
$skippedDueToFast  = 0;

$quiet             = false;
$noColor           = false;
$nonInteractive    = false;
$verifyAll         = false; // checksum/baseline strict mode
$verbose           = false; // debug diagnostics

// NEW: binary handling
$binQuarantine     = false; // --bin-quarantine to aggressively quarantine binaries

// NEW: ClamAV enable/disable
$clamavEnabled     = true;  // --no-clamav to disable ClamAV runs

// NEW: repair backup option (requested)
$repairBackup      = false; // --repair-backup
$repairBackupDir   = null;  // --repair-backup=/path (optional)

// Baseline snapshot
$baselineSaveFile  = null; // --baseline-save=FILE
$baselineLoadFile  = null; // --baseline-load=FILE
$baselineMap       = [];   // loaded known-good relpath => md5
$currentHashes     = [];   // this run relpath => md5

// Quarantine
$quarantineDir     = null; // --quarantine=DIR
$quarantinedFiles  = [];
$didQuarantine     = false;
$quarantineAutoMode= null; // 'Y','N','A','S' once remembered with R

// Findings / severity tracking
$alertCount        = 0;
$coreMismatchCount = 0;
$newFileCount      = 0;
$baselineDriftCnt  = 0;

$uploadsSuspicious = []; // suspicious uploads (pre/post actions)
$optionsFindings   = [];
$rogueRespawnHits  = [];

$hadCritical       = false;

$whitelist         = []; // hash allowlist
$wp_root_path      = null;

// DB audit results
$adminUsers        = [];
$dbAuditError      = null;
$activeThemeSlugs  = [];

// NEW: detailed summaries
$alertDetails      = []; // list of "[ALERT] ..." lines
$mismatchDetails   = []; // list of core/plugin/theme mismatch descriptions


/* ===========================
   CLI ARG PARSING
   =========================== */

$target = null;

foreach ($argv as $index => $arg) {
    if ($arg === '--quiet')            { $quiet = true; continue; }
    if ($arg === '--no-color')         { $noColor = true; continue; }
    if ($arg === '--noninteractive')   { $nonInteractive = true; continue; }
    if ($arg === '--verify-all')       { $verifyAll = true; continue; }
    if ($arg === '--verbose' || $arg === '--debug') { $verbose = true; continue; }
    if ($arg === '--bin-quarantine')   { $binQuarantine = true; continue; }
    if ($arg === '--no-clamav')        { $clamavEnabled = false; continue; }

    // NEW: repair backup flags
    if ($arg === '--repair-backup') {
        $repairBackup = true;
        continue;
    }
    if (preg_match('/^--repair-backup=(.+)$/', $arg, $m)) {
        $repairBackup = true;
        $repairBackupDir = rtrim($m[1], '/');
        continue;
    }

    if (preg_match('/^--fast=(\d+)$/', $arg, $m)) {
        $fastDays = (int)$m[1];
        continue;
    }

    if (preg_match('/^--exclude=(.+)$/', $arg, $m)) {
        $excludeExtensions = array_map('strtolower', explode(',', $m[1]));
        continue;
    }

    if (preg_match('/^--max-size=(\d+)$/', $arg, $m)) {
        $maxSizeMB = (int)$m[1];
        continue;
    }

    if (preg_match('/^--baseline-save=(.+)$/', $arg, $m)) {
        $baselineSaveFile = $m[1];
        continue;
    }

    if (preg_match('/^--baseline-load=(.+)$/', $arg, $m)) {
        $baselineLoadFile = $m[1];
        continue;
    }

    if (preg_match('/^--quarantine=(.+)$/', $arg, $m)) {
        $quarantineDir = rtrim($m[1], '/');
        continue;
    }

    if ($arg === '--help') {
        echo "WordPress Malware / Integrity Scanner\n\n";
        echo "USAGE:\n";
        echo "  php wpscan.php /path/to/wordpress [options]\n\n";

        echo "GENERAL OPTIONS:\n";
        echo "  --help                  Show this help text\n";
        echo "  --quiet                 Less console output (still logs to scan_log.txt)\n";
        echo "  --no-color              Disable ANSI color\n";
        echo "  --noninteractive        Never prompt (good for cron)\n";
        echo "  --fast=N                Only scan files modified in last N days\n";
        echo "  --exclude=ext1,ext2     Comma-separated extensions to skip entirely\n";
        echo "  --max-size=MB           Skip files larger than MB MB (default 10)\n";
        echo "  --verbose | --debug     Verbose network/cache diagnostics for checksums\n";
        echo "  --no-clamav             Disable ClamAV scanning (skips clamscan calls)\n\n";

        echo "INTEGRITY / CHECKS:\n";
        echo "  --verify-all            Strict integrity mode (core/plugins/themes/baseline)\n\n";

        echo "REPAIR SAFETY:\n";
        echo "  --repair-backup         Backup files before any repair overwrite (default dir)\n";
        echo "  --repair-backup=/DIR    Backup files before repair overwrite into /DIR\n\n";

        echo "BASELINE SNAPSHOT:\n";
        echo "  --baseline-load=FILE    Load a known-good snapshot (JSON relpath=>md5)\n";
        echo "  --baseline-save=FILE    After scanning, write a fresh baseline snapshot\n\n";

        echo "QUARANTINE:\n";
        echo "  --quarantine=DIR        Enable quarantine. Suspicious files can be MOVED\n";
        echo "  --bin-quarantine        Aggressively quarantine unexpected executables\n\n";

        echo "BINARY/EXECUTABLE SCAN:\n";
        echo "  Detects: ELF, PE/EXE (MZ), Mach-O. Always runs ClamAV on these files.\n";
        echo "  Flags executable binaries found in webroots (plugins/themes/uploads etc.).\n\n";

        echo "EXIT CODES:\n";
        echo "  0 = Looks clean-ish\n";
        echo "  1 = Critical indicators found\n";
        echo "  2 = DB audit couldn't run, filesystem ok\n";
        exit;
    }

    // first non-flag positional arg = target directory
    if ($index > 0 && substr($arg, 0, 1) !== '-' && $target === null) {
        $target = rtrim($arg, '/');
    }
}

if (empty($target) || !is_dir($target)) {
    fwrite(STDERR, "ERROR: Please specify a valid directory to scan.\n");
    fwrite(STDERR, "Usage: php wpscan.php /path/to/wordpress [...flags]\n");
    exit(1);
}


/* ===========================
   COLOR / LOGGING
   =========================== */

function ansi($code) { return chr(27) . "[" . $code . "m"; }
function color($text, $color) {
    global $noColor;
    if ($noColor) return $text;
    $colors = ['red'=>31,'green'=>32,'yellow'=>33,'blue'=>34,'magenta'=>35,'cyan'=>36,'gray'=>90];
    return isset($colors[$color]) ? ansi($colors[$color]) . $text . ansi(0) : $text;
}
function log_msg($msg, $color=null, $force=false) {
    global $logFile, $quiet;
    if (!$quiet || $force) echo color($msg . "\n", $color);
    file_put_contents($logFile, "[" . date('Y-m-d H:i:s') . "] $msg\n", FILE_APPEND);
}
function vmsg($msg) {
    global $verbose, $noColor;
    if ($verbose) {
        $pref = $noColor ? '' : "\033[36m";
        $suf  = $noColor ? '' : "\033[0m";
        echo $pref."[DEBUG] $msg".$suf."\n";
    }
}
// NEW: uniform ClamAV tag for logs
function format_clamav_tag($clam) {
    if (!empty($clam['_disabled'])) return "[clamav disabled]";
    return $clam['hit'] ? "[CLAMAV HIT] {$clam['raw']}" : "[clamav clean rc={$clam['code']}]";
}


/* ===========================
   FILE UTILS / QUARANTINE HELPERS
   =========================== */

function ensure_dir_exists($dir) { if (!is_dir($dir)) { @mkdir($dir, 0755, true); } }

function relative_from_root($absPath) {
    global $wp_root_path;
    $relativePath = $absPath;
    if ($wp_root_path) {
        $realWp   = realpath($wp_root_path);
        $realFile = realpath($absPath);
        if ($realWp && $realFile && strpos($realFile, $realWp) === 0) {
            $relativePath = ltrim(substr($realFile, strlen($realWp)), '/');
        }
    }
    return str_replace('\\', '/', $relativePath);
}

function quarantine_file($absPath) {
    global $quarantineDir, $wp_root_path, $quarantinedFiles, $didQuarantine, $hadCritical;
    if (!$quarantineDir) return false;
    if (!is_file($absPath)) return false;

    $rel = relative_from_root($absPath);
    $destPath = $quarantineDir . '/' . $rel;
    $destDir  = dirname($destPath);
    ensure_dir_exists($destDir);

    if (@rename($absPath, $destPath)) {
        $quarantinedFiles[] = ['from'=>$absPath,'to'=>$destPath];
        $didQuarantine = true;
        $hadCritical   = true; // quarantining implies serious issue
        return $destPath;
    }
    return false;
}

function save_to_whitelist($checksum) {
    global $whitelistFile, $whitelist;
    file_put_contents($whitelistFile, $checksum . "\n", FILE_APPEND | LOCK_EX);
    $whitelist[$checksum] = true;
}

/**
 * NEW: Backup original file before a repair overwrite
 * Writes to:
 *   - default: ./repair-backups-YYYYmmdd-HHMMSS/<relative-path>
 *   - or custom: --repair-backup=/some/dir/<relative-path>
 */
function backup_before_repair_write($absPath) {
    global $repairBackup, $repairBackupDir;

    if (!$repairBackup) return null;
    if (!is_file($absPath)) return null;

    $base = $repairBackupDir;
    if (!$base) {
        $base = rtrim(getcwd(), '/') . '/repair-backups-' . date('Ymd-His');
    }
    ensure_dir_exists($base);

    $rel = relative_from_root($absPath);
    if ($rel === '' || $rel === $absPath) {
        // fallback: avoid weirdness if root not set
        $rel = ltrim(str_replace(':','', $absPath), '/\\');
    }

    $dest = rtrim($base, '/') . '/' . $rel;
    ensure_dir_exists(dirname($dest));

    // Avoid overwrite if same file already backed up
    if (is_file($dest)) {
        $dest .= '.bak-' . date('His');
    }

    if (@copy($absPath, $dest)) {
        log_msg("[BACKUP] Saved original before repair: $absPath -> $dest", 'cyan', true);
        return $dest;
    }

    log_msg("[BACKUP-FAIL] Could not backup before repair: $absPath", 'yellow', true);
    return null;
}


/* ===========================
   CLAMAV + URL HARVEST
   =========================== */

function run_clamav_scan($filepath) {
    global $clamavEnabled;
    if (!$clamavEnabled) {
        return ['hit'=>false,'raw'=>'[ClamAV disabled]','code'=>0,'_disabled'=>true];
    }

    $safe = escapeshellarg($filepath);
    $cmd  = "clamscan --no-summary $safe 2>&1";
    $output = [];
    $ret    = 0;
    @exec($cmd, $output, $ret);

    $joined = trim(implode("\n", $output));
    $hit    = false;
    if ($ret === 1 || preg_match('/FOUND$/m', $joined)) $hit = true;

    return ['hit'=>$hit,'raw'=>$joined,'code'=>$ret,'_disabled'=>false];
}

function extract_urls_from_file($filepath) {
    $data = @file_get_contents($filepath);
    if ($data === false) return [];
    $urls = [];
    if (preg_match_all('#https?://[^\s"\']+#i', $data, $m)) {
        foreach ($m[0] as $u) {
            $u = rtrim($u, "');],>\"");
            $urls[$u] = true;
        }
    }
    return array_keys($urls);
}


/* ===========================
   PATTERNS / WHITELIST / BASELINE
   =========================== */

function load_patterns() {
    global $extraPatterns, $quiet;
    if (file_exists('patterns_raw.txt')) {
        $lines = file('patterns_raw.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($lines as $pattern) {
            $pattern = trim($pattern);
            if ($pattern === '' || $pattern[0] === '#' || str_starts_with($pattern, '//')) continue;
            $extraPatterns[] = $pattern;
        }
        if (!$quiet) echo "[+] Loaded " . count($extraPatterns) . " extra patterns from patterns_raw.txt\n";
    }
}
function load_baseline_file($path) {
    if (!$path || !file_exists($path)) return [];
    $json = @file_get_contents($path);
    $data = @json_decode($json, true);
    if (!is_array($data)) return [];
    return $data; // relpath => md5
}

function save_baseline_file($path, $map) {
    $json = json_encode($map, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    @file_put_contents($path, $json);
}

/* ===========================
   DB OPTION INJECTION HELPERS (NEW)
   =========================== */

function safe_unserialize($str) {
    if (!is_string($str) || $str === '') return null;
    // Block object injection patterns
    if (preg_match('/(^|;)O:\d+:/', $str)) return null;
    $data = @unserialize($str, ['allowed_classes' => false]);
    return is_array($data) ? $data : null;
}

function hefo_malware_detect($optionValue) {
    $arr = safe_unserialize($optionValue);
    if (!$arr) return null;

    $enablePhp = !empty($arr['enable_php']);

    // keys this plugin can execute/inject
    $execKeys = [
        'head','head_home','body','footer',
        'before','after',
        'generic_1','generic_2','generic_3','generic_4','generic_5',
        'mobile_head','mobile_body','mobile_footer',
        'mobile_before','mobile_after',
        'amp_head','amp_css','amp_body','amp_footer','amp_post_before','amp_post_after'
    ];

    $hits = [];
    foreach ($execKeys as $k) {
        if (empty($arr[$k])) continue;
        $v = (string)$arr[$k];

        if ($enablePhp && stripos($v, '<?php') !== false) {
            $hits[] = "$k: contains PHP (enable_php=1)";
        }

        $needles = [
            'openssl_decrypt',
            'curl_exec',
            'curl_init',
            "file_get_contents('http",
            'file_get_contents("http',
            'eval(',
            'base64_decode',
            'gzinflate',
            'gzuncompress',
        ];
        foreach ($needles as $n) {
            if (stripos($v, $n) !== false) {
                $hits[] = "$k: matched {$n}";
                break;
            }
        }

        if (preg_match('#https?://#i', $v)) {
            $hits[] = "$k: contains URL";
        }
    }

    if (empty($hits)) return null;

    return [
        'enable_php' => $enablePhp ? 1 : 0,
        'hits'       => array_values(array_unique($hits)),
    ];
}


/* ===========================
   WORDPRESS VERSION / CHECKSUMS (CACHED)
   =========================== */

/* ======== BEGIN: checksum helpers ======== */

function checksum_cache_path_core($version, $locale='en_US') {
    global $checksumCacheDir; ensure_dir_exists($checksumCacheDir);
    return $checksumCacheDir . "/core_{$version}_{$locale}.json";
}
function checksum_cache_path_plugin($slug, $version) {
    global $checksumCacheDir; ensure_dir_exists($checksumCacheDir);
    $safeSlug = preg_replace('/[^a-zA-Z0-9_\-]/','_',$slug);
    $safeVer  = preg_replace('/[^a-zA-Z0-9_\-\.]/','_',$version);
    return $checksumCacheDir . "/plugin_{$safeSlug}_{$safeVer}.json";
}
function checksum_cache_path_theme($slug, $version) {
    global $checksumCacheDir; ensure_dir_exists($checksumCacheDir);
    $safeSlug = preg_replace('/[^a-zA-Z0-9_\-]/','_',$slug);
    $safeVer  = preg_replace('/[^a-zA-Z0-9_\-\.]/','_',$version);
    return $checksumCacheDir . "/theme_{$safeSlug}_{$safeVer}.json";
}
function detect_wp_version($path) {
    $verFile = $path . '/wp-includes/version.php';
    if (file_exists($verFile)) {
        $contents = file_get_contents($verFile);
        if (preg_match('/\$wp_version\s*=\s*[\'"](.+?)[\'"]/', $contents, $m)) return $m[1];
    }
    return null;
}
function detect_wp_locale_from_config($rootPath) {
    $confFile = rtrim($rootPath, '/') . '/wp-config.php';
    if (!file_exists($confFile)) return 'en_US';
    $conf = file_get_contents($confFile);
    if (preg_match("/define\\s*\\(\\s*'WPLANG'\\s*,\\s*'([^']*)'\\s*\\)/", $conf, $m)) {
        $loc = trim($m[1]);
        if ($loc !== '') return $loc;
    }
    return 'en_US';
}
function http_get_json($url) {
    vmsg("GET $url");
    $context = stream_context_create([
        'http' => ['ignore_errors' => true,'timeout' => 20,]
    ]);
    $body = @file_get_contents($url, false, $context);
    $statusLine = null;
    if (isset($http_response_header[0])) {
        $statusLine = $http_response_header[0];
        vmsg("HTTP: ".$http_response_header[0]);
    }
    if ($body === false) { vmsg("Download failed (no body)"); return [null, null, $statusLine]; }
    vmsg("Bytes received: ".strlen($body));
    $data = @json_decode($body, true);
    if (!is_array($data)) { vmsg("JSON decode failed. First 200 bytes: ".substr($body, 0, 200)); $data = null; }
    return [$data, $body, $statusLine];
}

/**
 * Binary fetch with file_get_contents + cURL fallback (for ZIPs etc.)
 */
function http_get_binary($url) {
    vmsg("GET (binary) $url");

    $statusLine = null;
    $body       = false;

    // Prefer file_get_contents if allow_url_fopen is enabled
    if (ini_get('allow_url_fopen')) {
        $context = stream_context_create([
            'http' => [
                'ignore_errors' => true,
                'timeout'       => 30,
            ]
        ]);
        $body = @file_get_contents($url, false, $context);
        if (isset($http_response_header[0])) {
            $statusLine = $http_response_header[0];
        }
    }

    // Fallback to cURL if file_get_contents failed or is disabled
    if (($body === false || $body === null) && function_exists('curl_init')) {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_TIMEOUT        => 30,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_HEADER         => true,
        ]);
        $raw = curl_exec($ch);
        if ($raw !== false) {
            $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
            $statusCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $statusLine = "HTTP/1.1 $statusCode";
            $body       = substr($raw, $headerSize);
        }
        curl_close($ch);
    }

    vmsg("HTTP status for binary fetch: " . ($statusLine ?: 'none'));
    return [$body, $statusLine];
}

function parse_md5sum_listing($rawBody) {
    $map = [];
    $lines = preg_split('/\r?\n/', $rawBody);
    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '') continue;
        if (preg_match('/^([0-9a-f]{32})\s+\.(\/.+)$/i', $line, $m)) {
            $hash = strtolower($m[1]); $rel  = ltrim($m[2], './'); $map[$rel] = $hash; continue;
        }
        if (preg_match('/^([0-9a-f]{32})\s+(.+)$/i', $line, $m)) {
            $hash = strtolower($m[1]); $rel  = ltrim($m[2], './'); $map[$rel] = $hash; continue;
        }
    }
    return $map;
}
function load_core_checksums_from_web($version, $locale='en_US') {
    $url  = "http://api.wordpress.org/core/checksums/1.0/?version=$version&locale=$locale";
    list($data, $raw,) = http_get_json($url);
    if (is_array($data) && !empty($data['checksums']) && is_array($data['checksums'])) {
        vmsg("Core checksums loaded from api.wordpress.org: ".count($data['checksums'])." entries");
        return $data['checksums']; // relpath => md5
    }
    vmsg("api.wordpress.org did not return checksums");
    $alt = "http://wpmd5.mattjung.net/core/$version/$locale/";
    list($altData, $altRaw,) = http_get_json($alt);
    if (is_array($altData) && !empty($altData)) return $altData;
    if (!empty($altRaw)) { $map = parse_md5sum_listing($altRaw); if (!empty($map)) return $map; }
    return [];
}
function load_core_checksums($version, $locale='en_US') {
    global $coreChecksums, $checksumsAvailable;
    $cachePath = checksum_cache_path_core($version, $locale);
    $cached = [];
    if (file_exists($cachePath)) {
        vmsg("Loading core checksums from cache: $cachePath");
        $tmp = @file_get_contents($cachePath);
        $cached = @json_decode($tmp, true);
        if (is_array($cached) && !empty($cached)) {
            $coreChecksums      = $cached;
            $checksumsAvailable = true;
            vmsg("Loaded core from cache: ".count($cached)." entries");
            return;
        }
        vmsg("Core cache present but invalid, will refetch.");
    }
    $fetched = load_core_checksums_from_web($version, $locale);
    if (!empty($fetched)) {
        $coreChecksums      = $fetched;
        $checksumsAvailable = true;
        @file_put_contents($cachePath, json_encode($fetched, JSON_PRETTY_PRINT));
        vmsg("Saved core cache: $cachePath (".count($fetched)." entries)");
    }
}
function load_plugin_checksums_from_web($pluginSlug, $version) {
    $url = "http://downloads.wordpress.org/plugin-checksums/$pluginSlug/$version.json";
    vmsg("Fetching plugin checksums: $pluginSlug $version");
    list($data, $raw, $status) = http_get_json($url);
    if (is_array($data) && isset($data['files']) && is_array($data['files'])) {
        $map = [];
        foreach ($data['files'] as $relPath => $info) { $map[$relPath] = $info['md5'] ?? null; }
        return $map;
    }
    $alt = "http://wpmd5.mattjung.net/plugin/$pluginSlug/$version/";
    list($altData, $altRaw,) = http_get_json($alt);
    if (is_array($altData) && !empty($altData)) return $altData;
    if (!empty($altRaw)) { $map = parse_md5sum_listing($altRaw); if (!empty($map)) return $map; }
    return [];
}
function load_plugin_checksums($pluginSlug, $version) {
    global $pluginChecksums, $pluginVersions;
    $pluginVersions[$pluginSlug] = $version;

    $cachePath = checksum_cache_path_plugin($pluginSlug, $version);
    if (file_exists($cachePath)) {
        vmsg("Loading plugin cache: $cachePath");
        $tmp = @file_get_contents($cachePath);
        $cached = @json_decode($tmp, true);
        if (is_array($cached) && !empty($cached)) {
            $pluginChecksums[$pluginSlug] = $cached;
            return;
        }
    }
    $fetched = load_plugin_checksums_from_web($pluginSlug, $version);
    if (!empty($fetched)) {
        $pluginChecksums[$pluginSlug] = $fetched;
        @file_put_contents($cachePath, json_encode($fetched, JSON_PRETTY_PRINT));
    }
}
function load_theme_checksums_from_web($themeSlug, $version) {
    $url = "http://wpmd5.mattjung.net/theme/$themeSlug/$version/";
    vmsg("Fetching theme checksums: $themeSlug $version ($url)");
    list($data, $raw,) = http_get_json($url);
    if (is_array($data) && !empty($data)) return $data;
    if (!empty($raw)) { $map = parse_md5sum_listing($raw); if (!empty($map)) return $map; }
    return [];
}
function load_theme_checksums($themeSlug, $version) {
    global $themeChecksums, $themeVersions;
    $themeVersions[$themeSlug] = $version;

    $cachePath = checksum_cache_path_theme($themeSlug, $version);
    if (file_exists($cachePath)) {
        vmsg("Loading theme cache: $cachePath");
        $tmp = @file_get_contents($cachePath);
        $cached = @json_decode($tmp, true);
        if (is_array($cached) && !empty($cached)) {
            $themeChecksums[$themeSlug] = $cached;
            return;
        }
    }
    $fetched = load_theme_checksums_from_web($themeSlug, $version);
    if (!empty($fetched)) {
        $themeChecksums[$themeSlug] = $fetched;
        @file_put_contents($cachePath, json_encode($fetched, JSON_PRETTY_PRINT));
    }
}
/* ======== END: checksum helpers ======== */


/* ===========================
   QUARANTINE DECISION LOGIC
   =========================== */

function prompt_quarantine_decision($absPath, $reasonLabel, $md5) {
    echo color("$reasonLabel\n", 'yellow');
    echo color("Quarantine this file?\n", 'yellow');
    echo color("    Y = quarantine now\n", 'yellow');
    echo color("    N = leave it, warn\n", 'yellow');
    echo color("    A = allowlist this hash\n", 'yellow');
    echo color("    S = skip silently\n", 'yellow');
    echo color("    R = remember my choice for rest of this scan\n", 'yellow');
    echo color("[ Y / N / A / S / R ]: ", 'yellow');
    $choice = strtoupper(trim(fgets(STDIN)));
    if (!in_array($choice, ['Y','N','A','S','R'], true)) return 'N';
    return $choice;
}
function prompt_remember_choice() {
    echo color("Remember which action for the rest of this scan? [Y/N/A/S]: ", 'yellow');
    $choice = strtoupper(trim(fgets(STDIN)));
    if (!in_array($choice, ['Y','N','A','S'], true)) return null;
    return $choice;
}

function maybe_handle_suspicious_file($absPath, $reasonLabel, $allowQuarantine, $suggestAllowlist=true) {
    global $nonInteractive, $quarantineDir, $quarantineAutoMode, $hadCritical, $whitelist, $whitelistFile;

    $hadCritical = true; // serious suspicion

    $md5 = @md5_file($absPath);
    if ($md5 === false) $md5 = null;

    if (!$quarantineDir) {
        log_msg("[!] $reasonLabel (no quarantine dir set)", 'red', true);
        return;
    }

    $action = null;
    if ($nonInteractive && $allowQuarantine) {
        $action = 'Y';
    } elseif ($nonInteractive && !$allowQuarantine) {
        $action = 'N';
    } elseif ($quarantineAutoMode !== null) {
        $action = $quarantineAutoMode;
    } else {
        $action = prompt_quarantine_decision($absPath, $reasonLabel, $md5);
        if ($action === 'R') {
            $remember = prompt_remember_choice();
            if ($remember !== null) { $quarantineAutoMode = $remember; $action = $remember; }
            else { $action = 'N'; }
        }
    }

    switch ($action) {
        case 'Y':
            if ($allowQuarantine) {
                $res = quarantine_file($absPath);
                if ($res !== false) log_msg("[QUARANTINED] $absPath -> $res", 'red', true);
                else log_msg("[QUARANTINE-FAIL] $absPath could not be moved", 'yellow', true);
            } else {
                log_msg("[SKIP] $absPath not quarantined (protected/core/plugin/theme)", 'yellow', true);
            }
            break;
        case 'A':
            if ($md5 && $suggestAllowlist) {
                save_to_whitelist($md5);
                log_msg("[ALLOWLISTED] $absPath (hash added to whitelist_checksums.txt)", 'green', true);
            } else {
                log_msg("[ALLOWLIST-SKIP] could not allowlist (no md5?) $absPath", 'yellow', true);
            }
            break;
        case 'S':
            break; // silent skip
        case 'N':
        default:
            log_msg("[LEAVE] $absPath left in place (suspicious)", 'yellow', true);
            break;
    }
}


/* ===========================
   CORE / PLUGIN / THEME MISMATCH HANDLING (heuristic path)
   =========================== */

function handle_core_plugin_theme_mismatch($filepath, $relativePath, $actualMd5) {
    global $coreChecksums, $pluginChecksums, $themeChecksums, $nonInteractive;
    global $coreMismatchCount, $newFileCount, $hadCritical, $mismatchDetails, $pluginVersions, $themeVersions;

    $coreMismatchCount++;

    // core file?
    if (isset($coreChecksums[$relativePath])) {
        $expected = $coreChecksums[$relativePath];
        if ($expected === $actualMd5) {
            log_msg("[INFO] $filepath matches official WP checksum; code looked suspicious but hash is stock.", 'cyan');
            return;
        }
        $hadCritical = true;
        $msg = "[WARN] Core file mismatch: $filepath ($relativePath)";
        $mismatchDetails[] = "[CORE mismatch] $filepath ($relativePath)";
        log_msg($msg, 'yellow', true);

        if ($nonInteractive) return;

        echo color("[WARN] Core mismatch. Show diff? [D=diff / Y=whitelist / N=skip]: ", 'yellow');
        $input = strtoupper(trim(fgets(STDIN)));
        if ($input === 'D') {
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
                log_msg("[ERROR] Could not fetch official file for diff.", 'red');
            }
        } elseif ($input === 'Y') {
            save_to_whitelist($actualMd5);
            log_msg("[WHITELISTED] $filepath checksum added to whitelist_checksums.txt", 'green');
        }
        return;
    }

    // plugin file?
    foreach ($pluginChecksums as $slug => $files) {
        $pluginBase = "wp-content/plugins/$slug/";
        if (strpos($relativePath, $pluginBase) === 0) {
            $relPluginPath = substr($relativePath, strlen($pluginBase));
            if (isset($files[$relPluginPath])) {
                $expected = $files[$relPluginPath];
                if ($expected === $actualMd5) {
                    log_msg("[INFO] $filepath matches plugin checksum ($slug); code looked suspicious but hash is stock.", 'cyan');
                    return;
                }
                $hadCritical = true;
                $mismatchDetails[] = "[PLUGIN mismatch] $slug: $relPluginPath ($filepath)";
                log_msg("[WARN] Plugin file mismatch in $slug: $relPluginPath", 'yellow', true);
                return;
            }
        }
    }

    // theme file?
    foreach ($themeChecksums as $slug => $files) {
        $themeBase = "wp-content/themes/$slug/";
        if (strpos($relativePath, $themeBase) === 0) {
            $relThemePath = substr($relativePath, strlen($themeBase));
            if (isset($files[$relThemePath])) {
                $expected = $files[$relThemePath];
                if ($expected === $actualMd5) {
                    log_msg("[INFO] $filepath matches theme checksum ($slug); code looked suspicious but hash is stock.", 'cyan');
                    return;
                }
                $hadCritical = true;
                $mismatchDetails[] = "[THEME mismatch] $slug: $relThemePath ($filepath)";
                log_msg("[WARN] Theme file mismatch in $slug: $relThemePath", 'yellow', true);
                return;
            }
        }
    }

    // totally unknown file
    $newFileCount++;
    $hadCritical = true;

    $reason = "[WARN] Suspicious unknown file (not WP core/plugin/theme): $filepath";
    $mismatchDetails[] = "[EXTRA unknown] $filepath";
    maybe_handle_suspicious_file($filepath, $reason, /*allowQuarantine*/true);
}


/* ===========================
   FAST LOOKUP: official checksum?
   =========================== */

function file_matches_official_checksum($relPath, $md5sum) {
    global $coreChecksums, $pluginChecksums, $themeChecksums;
    if (isset($coreChecksums[$relPath]) && $coreChecksums[$relPath] === $md5sum) return true;
    foreach ($pluginChecksums as $slug => $files) {
        $pluginBase = "wp-content/plugins/$slug/";
        if (strpos($relPath, $pluginBase) === 0) {
            $relPluginPath = substr($relPath, strlen($pluginBase));
            if (isset($files[$relPluginPath]) && $files[$relPluginPath] === $md5sum) return true;
        }
    }
    foreach ($themeChecksums as $slug => $files) {
        $themeBase = "wp-content/themes/$slug/";
        if (strpos($relPath, $themeBase) === 0) {
            $relThemePath = substr($relPath, strlen($themeBase));
            if (isset($files[$relThemePath]) && $files[$relThemePath] === $md5sum) return true;
        }
    }
    return false;
}


/* ===========================
   BINARY / EXECUTABLE DETECTION
   =========================== */

function read_file_head($path, $n=8) {
    $h = @fopen($path, 'rb');
    if (!$h) return '';
    $buf = @fread($h, $n);
    @fclose($h);
    return $buf === false ? '' : $buf;
}

/**
 * Returns one of: 'ELF', 'PE', 'MACHO', 'SCRIPT', 'ZIP', 'OTHER', or '' if unknown.
 */
function sniff_magic($path) {
    $head = read_file_head($path, 8);
    if ($head === '') return '';
    // ELF: 0x7F 'E' 'L' 'F'
    if (substr($head, 0, 4) === "\x7F" . "ELF") return 'ELF';
    // PE/EXE: 'MZ'
    if (substr($head, 0, 2) === "MZ") return 'PE';
    // Mach-O (fat): 0xCAFEBABE / 0xCAFED00D, (thin): 0xFEEDFACE / 0xFEEDFACF / 0xCEFAEDFE
    $u32 = unpack('N', substr($head, 0, 4))[1] ?? 0;
    if (in_array($u32, [0xCAFEBABE,0xCAFED00D,0xFEEDFACE,0xFEEDFACF,0xCEFAEDFE], true)) return 'MACHO';
    // ZIP container
    if (substr($head, 0, 2) === "PK") return 'ZIP';
    // Shebang -> script text
    if (substr($head, 0, 2) === "#!") return 'SCRIPT';
    return 'OTHER';
}

/** Heuristic: is file binary-ish (non-text)? */
function is_probably_binary($path) {
    // Prefer PHP's finfo if available
    if (function_exists('finfo_open')) {
        $finfo = @finfo_open(FILEINFO_MIME_TYPE);
        if ($finfo) {
            $mime = @finfo_file($finfo, $path);
            @finfo_close($finfo);
            if (is_string($mime) && $mime !== '') {
                if (preg_match('#^(text/|application/(json|xml|javascript))#i', $mime)) return false;
                return true;
            }
        }
    }
    // Fallback heuristic: sample and count NULs/non-printables
    $buf = read_file_head($path, 512);
    if ($buf === '') return false;
    $nonPrintable = 0;
    $len = strlen($buf);
    for ($i=0; $i<$len; $i++) {
        $ord = ord($buf[$i]);
        if ($ord === 9 || $ord === 10 || $ord === 13) continue; // \t \n \r
        if ($ord < 32 || $ord > 126) $nonPrintable++;
    }
    return ($len > 0 && ($nonPrintable / $len) > 0.3);
}

/** Decide if a binary is suspicious given its location in WP tree. */
function binary_location_is_suspicious($relPath) {
    $badZones = [
        'wp-content/uploads/',
        'wp-content/plugins/',
        'wp-content/themes/',
        'wp-content/mu-plugins/',
        'wp-includes/js/',
        'wp-admin/',
    ];
    foreach ($badZones as $pref) {
        if (strpos($relPath, $pref) === 0) return true;
    }
    $base = basename($relPath);
    $rootSuspicious = ['index', 'license.txt', 'readme.html', 'xmlrpc.php', 'wp-settings.php','wp-config.php'];
    if (!in_array($base, $rootSuspicious, true) && strpos($relPath, '/') === false) return true;
    return false;
}

/** Handle a detected executable/binary */
function handle_binary_file($path) {
    global $alertCount, $hadCritical, $binQuarantine, $alertDetails;

    $rel = relative_from_root($path);
    $magic = sniff_magic($path);
    $isExecMagic = in_array($magic, ['ELF','PE','MACHO'], true);
    $probBin = is_probably_binary($path);

    if (!$isExecMagic && !$probBin) return; // not binary-ish

    $why = $isExecMagic ? "Executable binary detected ($magic)" : "Binary blob detected";
    $suspiciousLoc = binary_location_is_suspicious($rel);

    $clam = run_clamav_scan($path);
    if ($clam['hit']) $hadCritical = true;

    $alertCount++;
    $msg = "[ALERT][BIN] $path | $why" .
           " | location=" . ($suspiciousLoc ? "suspicious" : "unknown") .
           " | " . format_clamav_tag($clam);
    $alertDetails[] = $msg;
    log_msg($msg, $clam['hit'] ? 'red' : ($suspiciousLoc ? 'yellow' : 'magenta'), true);

    $allowQ = $clam['hit'] || $suspiciousLoc || $binQuarantine;
    if ($allowQ) {
        $reason = "[BIN] $why at $rel";
        maybe_handle_suspicious_file($path, $reason, /*allowQuarantine*/true, /*suggestAllowlist*/false);
    }
}


/* ===========================
   FILE CONTENT SCAN (TEXT + BIN)
   =========================== */

function scan_file($filepath) {
    global $extraPatterns, $alertCount, $hadCritical, $alertDetails;

    $checksum = @md5_file($filepath);
    if ($checksum === false) return;

    $relPath = relative_from_root($filepath);

    // If this exact file matches official checksums, skip text/binary heuristics.
    if (file_matches_official_checksum($relPath, $checksum)) {
        return;
    }

    // NEW: First, check for binaries/executables and handle them immediately.
    handle_binary_file($filepath);

    $fh = @fopen($filepath, 'r');
    if (!$fh) return;

    $matchFound        = false;
    $suspiciousReasons = [];
    $lineNo            = 0;

    while (($line = fgets($fh)) !== false) {
        $lineNo++;
        if (preg_match('/eval\s*\(/i', $line)) {
            $matchFound = true;
            $suspiciousReasons[] = "eval() at line $lineNo";
        }
        foreach ($extraPatterns as $pattern) {
            if (@preg_match($pattern, $line, $m)) {
                $matchedText = isset($m[0]) ? trim($m[0]) : '[match not captured]';
                $matchFound = true;
                $suspiciousReasons[] = "Pattern $pattern at line $lineNo (\"$matchedText\")";
            }
        }
    }
    fclose($fh);

    if (!$matchFound) return;

    $clam = run_clamav_scan($filepath);
    if ($clam['hit']) $hadCritical = true;

    $urls = extract_urls_from_file($filepath);
    $urlsNote = '';
    if (!empty($urls)) $urlsNote = " | URLs: " . implode(",", $urls);

    $alertCount++;

    $msg = "[ALERT] $filepath | " .
        implode("; ", $suspiciousReasons) . " | " .
        format_clamav_tag($clam) .
        $urlsNote;

    $alertDetails[] = $msg;
    log_msg($msg, $clam['hit'] ? 'red' : 'magenta', true);

    handle_core_plugin_theme_mismatch($filepath, $relPath, $checksum);
}


/* ===========================
   VERIFY-ALL / BASELINE DRIFT
   + ZIP & FILE CACHE REPAIR HELPERS
   =========================== */

function looks_like_wp_core_path($relativePath) {
    if (preg_match('#^(wp-admin/|wp-includes/)#', $relativePath)) return true;
    $coreRoots = [
        'index.php','wp-login.php','wp-settings.php','wp-config-sample.php',
        'wp-comments-post.php','xmlrpc.php','wp-cron.php','wp-links-opml.php',
        'wp-mail.php','wp-signup.php','wp-trackback.php','license.txt','readme.html'
    ];
    foreach ($coreRoots as $f) if ($relativePath === $f) return true;
    return false;
}

/**
 * Core repair using official WordPress ZIP:
 *   https://wordpress.org/wordpress-{$version}.zip
 * Cached in $zipCacheDir and $fileCacheDir.
 */
function attempt_core_repair_interactive($relPath, $absPath, $expectedMd5, $currentMd5) {
    global $nonInteractive, $zipCacheDir, $fileCacheDir, $mismatchDetails, $wpVer;

    if ($nonInteractive) return;
    if (!$wpVer) return; // can't know which core version to fetch

    log_msg("[REPAIR] $absPath (CORE mismatch)", 'yellow', true);
    echo color("    R = replace with OFFICIAL clean copy\n", 'yellow');
    echo color("    N = leave as-is\n", 'yellow');
    echo color("Choice [R/N]: ", 'yellow');
    $choice = strtoupper(trim(fgets(STDIN)));
    if ($choice !== 'R') {
        log_msg("[INFO] User chose not to repair $absPath", 'yellow', true);
        return;
    }

    ensure_dir_exists($zipCacheDir);
    ensure_dir_exists($fileCacheDir);

    $cacheFilePath = $fileCacheDir . "/core/{$wpVer}/" . $relPath;
    $cacheDir      = dirname($cacheFilePath);
    ensure_dir_exists($cacheDir);

    // 1) If we already have an extracted cached file, and md5 matches expected, use it
    if (is_file($cacheFilePath)) {
        $data = @file_get_contents($cacheFilePath);
        if ($data !== false) {
            $md5 = md5($data);
            if ($expectedMd5 && $md5 === $expectedMd5) {
                backup_before_repair_write($absPath);
                if (@file_put_contents($absPath, $data) !== false) {
                    clearstatcache(true, $absPath);
                    $finalMd5 = @md5_file($absPath);
                    log_msg("[OK] Repaired core file from cache $cacheFilePath -> $absPath (MD5 $finalMd5)", 'green', true);
                    return;
                }
            }
        }
    }

    // 2) Need ZIP: use cached or download
    $zipPath = $zipCacheDir . "/core-{$wpVer}.zip";
    if (!is_file($zipPath) || filesize($zipPath) < 1024) {
        $url = "https://wordpress.org/wordpress-{$wpVer}.zip";
        vmsg("Fetching core ZIP for repair: $url");
        list($zipData, $statusLine) = http_get_binary($url);
        if ($zipData === false || $zipData === null || strlen($zipData) < 1024 || ($statusLine && strpos($statusLine, '200') === false)) {
            $statusNote = $statusLine ? "HTTP status: $statusLine" : "no HTTP status";
            log_msg("[ERROR] Could not download core ZIP for repair ($url); repair aborted. ($statusNote)", 'red', true);
            return;
        }
        if (@file_put_contents($zipPath, $zipData) === false) {
            log_msg("[ERROR] Could not write core ZIP cache at $zipPath; repair aborted.", 'red', true);
            return;
        }
    } else {
        vmsg("Using cached core ZIP: $zipPath");
    }

    if (!class_exists('ZipArchive')) {
        log_msg("[ERROR] ZipArchive PHP extension not available; cannot repair core.", 'red', true);
        return;
    }

    $zip = new ZipArchive();
    if ($zip->open($zipPath) !== true) {
        log_msg("[ERROR] Could not open core ZIP at $zipPath; repair aborted.", 'red', true);
        return;
    }

    $zipPathName = 'wordpress/' . $relPath;
    $fileContent = $zip->getFromName($zipPathName);
    if ($fileContent === false) {
        log_msg("[ERROR] Could not locate $zipPathName in core ZIP; repair aborted.", 'red', true);
        $zip->close();
        return;
    }

    $zip->close();

    $newMd5 = md5($fileContent);
    if ($expectedMd5 && $newMd5 !== $expectedMd5) {
        log_msg("[WARN] Downloaded core file MD5 does not match expected official checksum for $relPath.", 'yellow', true);
        echo color("Downloaded core copy still does not match expected checksum.\n", 'yellow');
        echo color("    W = write it anyway\n    C = cancel repair\nChoice [W/C]: ", 'yellow');
        $c2 = strtoupper(trim(fgets(STDIN)));
        if ($c2 !== 'W') {
            log_msg("[INFO] User cancelled core repair for $absPath due to checksum mismatch.", 'yellow', true);
            return;
        }
    }

    @file_put_contents($cacheFilePath, $fileContent);

    backup_before_repair_write($absPath);
    if (@file_put_contents($absPath, $fileContent) === false) {
        log_msg("[ERROR] Failed to overwrite $absPath with repaired core content.", 'red', true);
        return;
    }

    clearstatcache(true, $absPath);
    $finalMd5 = @md5_file($absPath);
    $mismatchDetails[] = "[CORE repaired] $absPath (MD5 now $finalMd5)";
    log_msg("[OK] Repaired core file $absPath (MD5 now $finalMd5)", 'green', true);
}

/**
 * Plugin repair using official plugin ZIP:
 *   https://downloads.wordpress.org/plugin/slug.version.zip
 * Cached in $zipCacheDir and $fileCacheDir.
 */
function attempt_plugin_repair_interactive($slug, $version, $relPluginPath, $absPath, $expectedMd5, $currentMd5) {
    global $nonInteractive, $zipCacheDir, $fileCacheDir, $mismatchDetails;

    if ($nonInteractive) return;

    log_msg("[REPAIR] $absPath (PLUGIN mismatch)", 'yellow', true);
    echo color("    R = replace with OFFICIAL clean copy\n", 'yellow');
    echo color("    N = leave as-is\n", 'yellow');
    echo color("Choice [R/N]: ", 'yellow');
    $choice = strtoupper(trim(fgets(STDIN)));
    if ($choice !== 'R') {
        log_msg("[INFO] User chose not to repair $absPath", 'yellow', true);
        return;
    }

    ensure_dir_exists($zipCacheDir);
    ensure_dir_exists($fileCacheDir);

    $cacheFilePath = $fileCacheDir . "/plugin/{$slug}/{$version}/" . $relPluginPath;
    $cacheDir      = dirname($cacheFilePath);
    ensure_dir_exists($cacheDir);

    if (is_file($cacheFilePath)) {
        $data = @file_get_contents($cacheFilePath);
        if ($data !== false) {
            $md5 = md5($data);
            if ($expectedMd5 && $md5 === $expectedMd5) {
                backup_before_repair_write($absPath);
                if (@file_put_contents($absPath, $data) !== false) {
                    clearstatcache(true, $absPath);
                    $finalMd5 = @md5_file($absPath);
                    $mismatchDetails[] = "[PLUGIN repaired] $slug: $relPluginPath ($absPath) (MD5 $finalMd5)";
                    log_msg("[OK] Repaired plugin file from cache $cacheFilePath -> $absPath (MD5 $finalMd5)", 'green', true);
                    return;
                }
            }
        }
    }

    $zipPath = $zipCacheDir . "/plugin-{$slug}-{$version}.zip";
    if (!is_file($zipPath) || filesize($zipPath) < 1024) {
        $repairUrl = "https://downloads.wordpress.org/plugin/{$slug}.{$version}.zip";
        vmsg("Fetching plugin ZIP for repair: $repairUrl");
        list($zipData, $statusLine) = http_get_binary($repairUrl);

        if ($zipData === false || $zipData === null || strlen($zipData) < 1024 || ($statusLine && strpos($statusLine, '200') === false)) {
            $statusNote = $statusLine ? "HTTP status: $statusLine" : "no HTTP status";
            log_msg("[ERROR] Could not download official content for $absPath; repair aborted. ($statusNote)", 'red', true);
            return;
        }
        if (@file_put_contents($zipPath, $zipData) === false) {
            log_msg("[ERROR] Could not write plugin ZIP cache at $zipPath; repair aborted.", 'red', true);
            return;
        }
    } else {
        vmsg("Using cached plugin ZIP: $zipPath");
    }

    if (!class_exists('ZipArchive')) {
        log_msg("[ERROR] ZipArchive PHP extension not available; cannot repair plugin.", 'red', true);
        return;
    }

    $zip = new ZipArchive();
    if ($zip->open($zipPath) !== true) {
        log_msg("[ERROR] Could not open plugin ZIP for $slug; repair aborted.", 'red', true);
        return;
    }

    $expectedZipPath = $slug . '/' . $relPluginPath;
    $fileContent = $zip->getFromName($expectedZipPath);

    if ($fileContent === false) {
        for ($i = 0; $i < $zip->numFiles; $i++) {
            $stat = $zip->statIndex($i);
            if (!$stat || !isset($stat['name'])) continue;
            $name = $stat['name'];
            if (substr($name, -strlen($relPluginPath)) === $relPluginPath) {
                $fileContent = $zip->getFromIndex($i);
                if ($fileContent !== false) break;
            }
        }
    }

    if ($fileContent === false) {
        log_msg("[ERROR] Could not locate $relPluginPath in plugin ZIP for $slug; repair aborted.", 'red', true);
        $zip->close();
        return;
    }

    $zip->close();

    $newMd5 = md5($fileContent);
    if ($expectedMd5 && $expectedMd5 !== $newMd5) {
        log_msg("[WARN] Downloaded plugin file MD5 does not match expected official checksum for $relPluginPath.", 'yellow', true);
        echo color("Downloaded copy still does not match expected checksum.\n", 'yellow');
        echo color("    W = write it anyway\n    C = cancel repair\nChoice [W/C]: ", 'yellow');
        $c2 = strtoupper(trim(fgets(STDIN)));
        if ($c2 !== 'W') {
            log_msg("[INFO] User cancelled repair for $absPath due to checksum mismatch.", 'yellow', true);
            return;
        }
    }

    @file_put_contents($cacheFilePath, $fileContent);

    backup_before_repair_write($absPath);
    if (@file_put_contents($absPath, $fileContent) === false) {
        log_msg("[ERROR] Failed to overwrite $absPath with repaired content.", 'red', true);
        return;
    }

    clearstatcache(true, $absPath);
    $finalMd5 = @md5_file($absPath);
    $mismatchDetails[] = "[PLUGIN repaired] $slug: $relPluginPath ($absPath) (MD5 $finalMd5)";
    log_msg("[OK] Repaired plugin file $absPath (MD5 now $finalMd5)", 'green', true);
}

/**
 * Theme repair using official theme ZIP:
 *   https://downloads.wordpress.org/theme/slug.version.zip
 * Cached in $zipCacheDir and $fileCacheDir.
 */
function attempt_theme_repair_interactive($slug, $version, $relThemePath, $absPath, $expectedMd5, $currentMd5) {
    global $nonInteractive, $zipCacheDir, $fileCacheDir, $mismatchDetails;

    if ($nonInteractive) return;

    log_msg("[REPAIR] $absPath (THEME mismatch)", 'yellow', true);
    echo color("    R = replace with OFFICIAL clean copy\n", 'yellow');
    echo color("    N = leave as-is\n", 'yellow');
    echo color("Choice [R/N]: ", 'yellow');
    $choice = strtoupper(trim(fgets(STDIN)));
    if ($choice !== 'R') {
        log_msg("[INFO] User chose not to repair $absPath", 'yellow', true);
        return;
    }

    ensure_dir_exists($zipCacheDir);
    ensure_dir_exists($fileCacheDir);

    $cacheFilePath = $fileCacheDir . "/theme/{$slug}/{$version}/" . $relThemePath;
    $cacheDir      = dirname($cacheFilePath);
    ensure_dir_exists($cacheDir);

    if (is_file($cacheFilePath)) {
        $data = @file_get_contents($cacheFilePath);
        if ($data !== false) {
            $md5 = md5($data);
            if ($expectedMd5 && $md5 === $expectedMd5) {
                backup_before_repair_write($absPath);
                if (@file_put_contents($absPath, $data) !== false) {
                    clearstatcache(true, $absPath);
                    $finalMd5 = @md5_file($absPath);
                    $mismatchDetails[] = "[THEME repaired] $slug: $relThemePath ($absPath) (MD5 $finalMd5)";
                    log_msg("[OK] Repaired theme file from cache $cacheFilePath -> $absPath (MD5 $finalMd5)", 'green', true);
                    return;
                }
            }
        }
    }

    $zipPath = $zipCacheDir . "/theme-{$slug}-{$version}.zip";
    if (!is_file($zipPath) || filesize($zipPath) < 1024) {
        $repairUrl = "https://downloads.wordpress.org/theme/{$slug}.{$version}.zip";
        vmsg("Fetching theme ZIP for repair: $repairUrl");
        list($zipData, $statusLine) = http_get_binary($repairUrl);

        if ($zipData === false || $zipData === null || strlen($zipData) < 1024 || ($statusLine && strpos($statusLine, '200') === false)) {
            $statusNote = $statusLine ? "HTTP status: $statusLine" : "no HTTP status";
            log_msg("[ERROR] Could not download official content for $absPath; repair aborted. ($statusNote)", 'red', true);
            return;
        }
        if (@file_put_contents($zipPath, $zipData) === false) {
            log_msg("[ERROR] Could not write theme ZIP cache at $zipPath; repair aborted.", 'red', true);
            return;
        }
    } else {
        vmsg("Using cached theme ZIP: $zipPath");
    }

    if (!class_exists('ZipArchive')) {
        log_msg("[ERROR] ZipArchive PHP extension not available; cannot repair theme.", 'red', true);
        return;
    }

    $zip = new ZipArchive();
    if ($zip->open($zipPath) !== true) {
        log_msg("[ERROR] Could not open theme ZIP for $slug; repair aborted.", 'red', true);
        return;
    }

    $expectedZipPath = $slug . '/' . $relThemePath;
    $fileContent = $zip->getFromName($expectedZipPath);

    if ($fileContent === false) {
        for ($i = 0; $i < $zip->numFiles; $i++) {
            $stat = $zip->statIndex($i);
            if (!$stat || !isset($stat['name'])) continue;
            $name = $stat['name'];
            if (substr($name, -strlen($relThemePath)) === $relThemePath) {
                $fileContent = $zip->getFromIndex($i);
                if ($fileContent !== false) break;
            }
        }
    }

    if ($fileContent === false) {
        log_msg("[ERROR] Could not locate $relThemePath in theme ZIP for $slug; repair aborted.", 'red', true);
        $zip->close();
        return;
    }

    $zip->close();

    $newMd5 = md5($fileContent);
    if ($expectedMd5 && $expectedMd5 !== $newMd5) {
        log_msg("[WARN] Downloaded theme file MD5 does not match expected official checksum for $relThemePath.", 'yellow', true);
        echo color("Downloaded copy still does not match expected checksum.\n", 'yellow');
        echo color("    W = write it anyway\n    C = cancel repair\nChoice [W/C]: ", 'yellow');
        $c2 = strtoupper(trim(fgets(STDIN)));
        if ($c2 !== 'W') {
            log_msg("[INFO] User cancelled repair for $absPath due to checksum mismatch.", 'yellow', true);
            return;
        }
    }

    @file_put_contents($cacheFilePath, $fileContent);

    backup_before_repair_write($absPath);
    if (@file_put_contents($absPath, $fileContent) === false) {
        log_msg("[ERROR] Failed to overwrite $absPath with repaired theme content.", 'red', true);
        return;
    }

    clearstatcache(true, $absPath);
    $finalMd5 = @md5_file($absPath);
    $mismatchDetails[] = "[THEME repaired] $slug: $relThemePath ($absPath) (MD5 $finalMd5)";
    log_msg("[OK] Repaired theme file $absPath (MD5 now $finalMd5)", 'green', true);
}

function verify_checksums_for_file($path) {
    global $coreChecksums, $pluginChecksums, $themeChecksums, $checksumsAvailable, $baselineMap;
    global $baselineDriftCnt, $hadCritical, $currentHashes, $newFileCount, $extraFileAllow;
    global $mismatchDetails;

    $checksum = @md5_file($path);
    if ($checksum === false) return;

    $relativePath = relative_from_root($path);
    $currentHashes[$relativePath] = $checksum;

    $isCore   = false;
    $isPlugin = false;
    $isTheme  = false;

    // core
    if ($checksumsAvailable && isset($coreChecksums[$relativePath])) {
        $isCore = true;
        $expected = $coreChecksums[$relativePath];
        if ($expected !== $checksum) {
            $hadCritical = true; $baselineDriftCnt++;
            $reason = "[WARN] Core checksum mismatch (verify-all): $path";
            $mismatchDetails[] = "[CORE mismatch verify-all] $path ($relativePath)";
            log_msg($reason, 'yellow', true);

            attempt_core_repair_interactive($relativePath, $path, $expected, $checksum);
            maybe_handle_suspicious_file($path, $reason, /*allowQuarantine*/false);
        }
    }

    // plugin
    if (!$isCore) {
        foreach ($pluginChecksums as $slug => $files) {
            $pluginBase = "wp-content/plugins/$slug/";
            if (strpos($relativePath, $pluginBase) === 0) {
                $isPlugin = true;
                $relPluginPath = substr($relativePath, strlen($pluginBase));
                if (isset($files[$relPluginPath])) {
                    $expected = $files[$relPluginPath];
                    if ($expected !== $checksum) {
                        $hadCritical = true; $baselineDriftCnt++;
                        $reason = "[WARN] Plugin checksum mismatch (verify-all) $slug: $relPluginPath";
                        $mismatchDetails[] = "[PLUGIN mismatch verify-all] $slug: $relPluginPath ($path)";
                        log_msg($reason, 'yellow', true);

                        global $pluginVersions;
                        $version = $pluginVersions[$slug] ?? null;
                        if ($version !== null) {
                            attempt_plugin_repair_interactive($slug, $version, $relPluginPath, $path, $expected, $checksum);
                        } else {
                            vmsg("No version recorded for $slug; skipping plugin repair offer.");
                        }

                        maybe_handle_suspicious_file($path, $reason, /*allowQuarantine*/false);
                    }
                }
                break;
            }
        }
    }

    // theme
    if (!$isCore && !$isPlugin) {
        foreach ($themeChecksums as $slug => $files) {
            $themeBase = "wp-content/themes/$slug/";
            if (strpos($relativePath, $themeBase) === 0) {
                $isTheme = true;
                $relThemePath = substr($relativePath, strlen($themeBase));
                if (isset($files[$relThemePath])) {
                    $expected = $files[$relThemePath];
                    if ($expected !== $checksum) {
                        $hadCritical = true; $baselineDriftCnt++;
                        $reason = "[WARN] Theme checksum mismatch (verify-all) $slug: $relThemePath";
                        $mismatchDetails[] = "[THEME mismatch verify-all] $slug: $relThemePath ($path)";
                        log_msg($reason, 'yellow', true);

                        global $themeVersions;
                        $version = $themeVersions[$slug] ?? null;
                        if ($version !== null) {
                            attempt_theme_repair_interactive($slug, $version, $relThemePath, $path, $expected, $checksum);
                        } else {
                            vmsg("No version recorded for theme $slug; skipping theme repair offer.");
                        }

                        maybe_handle_suspicious_file($path, $reason, /*allowQuarantine*/false);
                    }
                }
                break;
            }
        }
    }

    if ($isCore || $isPlugin || $isTheme) return;

    // Not core/plugin/theme: treat as custom / extra
    $customZones = [
        'wp-content/uploads/',
        'wp-content/cache/',
        'wp-content/themes/',
        'wp-content/plugins/',
        'wp-content/mu-plugins/',
        'wp-content/wflogs/',
    ];
    $looksCustomButExpected = false;
    foreach ($customZones as $prefix) {
        if (strpos($relativePath, $prefix) === 0) { $looksCustomButExpected = true; break; }
    }

    if (!$checksumsAvailable && looks_like_wp_core_path($relativePath)) {
        $looksCustomButExpected = true;
    }

    $baseName = basename($relativePath);
    if (in_array($baseName, $extraFileAllow, true)) {
        log_msg("[INFO] Extra allowlisted file: $path", 'gray');
        return;
    }

    if (isset($baselineMap[$relativePath])) {
        $knownGoodHash = $baselineMap[$relativePath];
        if ($knownGoodHash !== $checksum) {
            $hadCritical = true; $baselineDriftCnt++;
            $reason = "[BASELINE DRIFT] $path hash changed from known-good snapshot";
            log_msg($reason, 'red', true);
            $allowQuarantine = (strpos($relativePath, 'wp-content/') === 0);
            maybe_handle_suspicious_file($path, $reason, $allowQuarantine);
        }
    } else {
        $magic = sniff_magic($path);
        $isExecMagic = in_array($magic, ['ELF','PE','MACHO'], true);
        if ($isExecMagic) {
            $hadCritical = true;
            $reason = "[EXTRA][BIN] $path ï¿½ unexpected executable ($magic) not in baseline or checksums";
            log_msg($reason, 'red', true);
            maybe_handle_suspicious_file($path, $reason, /*allowQuarantine*/true, /*suggestAllowlist*/false);
            return;
        }

        if ($looksCustomButExpected) {
            $reason = "[EXTRA] (new custom) $path ï¿½ not in baseline, not official core/plugin/theme";
            log_msg($reason, 'yellow', true);
            maybe_handle_suspicious_file($path, $reason, /*allowQuarantine*/false, /*suggestAllowlist*/true);
        } else {
            $hadCritical   = true; $newFileCount++;
            $reason = "[EXTRA] $path ï¿½ not official WP/plugin/theme AND not in baseline";
            log_msg($reason, 'red', true);
            maybe_handle_suspicious_file($path, $reason, /*allowQuarantine*/true);
        }
    }
}


/* ===========================
   WORDPRESS DB AUDIT
   =========================== */

function parse_wp_config($rootPath) {
    $confFile = rtrim($rootPath, '/') . '/wp-config.php';
    if (!file_exists($confFile)) return [null, "wp-config.php not found"];

    $conf = file_get_contents($confFile);
    $info = [
        'DB_NAME'=>null,'DB_USER'=>null,'DB_PASSWORD'=>null,'DB_HOST'=>null,
        'table_prefix'=>'wp_'
    ];

    foreach (['DB_NAME','DB_USER','DB_PASSWORD','DB_HOST'] as $key) {
        if (preg_match("/define\\s*\\(\\s*['\"]".$key."['\"]\\s*,\\s*['\"]([^'\"]+)['\"]\\s*\\)/", $conf, $m)) {
            $info[$key] = $m[1];
        }
    }
    if (preg_match('/\\$table_prefix\\s*=\\s*[\'"]([^\'"]+)[\'"]\\s*;/', $conf, $m)) {
        $info['table_prefix'] = $m[1];
    }

    if (!$info['DB_NAME'] || !$info['DB_USER'] || !$info['DB_HOST']) {
        return [null, "Could not parse DB credentials from wp-config.php"];
    }
    return [$info, null];
}

function audit_wp_db($creds) {
    $db = @new mysqli(
        $creds['DB_HOST'],
        $creds['DB_USER'],
        $creds['DB_PASSWORD'],
        $creds['DB_NAME']
    );
    if ($db->connect_error) {
        return [[], [], [], "DB connect error: " . $db->connect_error];
    }

    $p = $creds['table_prefix'];
    $usersTbl    = $db->real_escape_string($p . 'users');
    $usermetaTbl = $db->real_escape_string($p . 'usermeta');
    $optionsTbl  = $db->real_escape_string($p . 'options');
    $metaKey     = $db->real_escape_string($p . 'capabilities');

    $sqlAdmins = "
        SELECT u.ID, u.user_login, u.user_email, u.user_registered
        FROM `$usersTbl` u
        INNER JOIN `$usermetaTbl` m ON m.user_id = u.ID
        WHERE m.meta_key = '$metaKey'
          AND m.meta_value LIKE '%administrator%'
    ";
    $adminsResult = $db->query($sqlAdmins);
    if (!$adminsResult) {
        $err = "Query error (admins): " . $db->error;
        $db->close();
        return [[], [], [], $err];
    }
    $admins = [];
    while ($row = $adminsResult->fetch_assoc()) {
        $admins[] = [
            'ID'=>$row['ID'],
            'login'=>$row['user_login'],
            'email'=>$row['user_email'],
            'registered'=>$row['user_registered']
        ];
    }
    $adminsResult->close();

    $susRows = [];
    $sqlKeyOptions = "
        SELECT option_name, option_value
        FROM `$optionsTbl`
        WHERE option_name IN ('siteurl','home','active_plugins','template','stylesheet')
    ";
    $rKey = $db->query($sqlKeyOptions);
    $template   = null;
    $stylesheet = null;
    if ($rKey) {
        while ($row = $rKey->fetch_assoc()) {
            $susRows[] = [
                'name'=>$row['option_name'],
                'why'=>'core_site_setting',
                'val'=>$row['option_value']
            ];
            if ($row['option_name'] === 'template')   $template   = $row['option_value'];
            if ($row['option_name'] === 'stylesheet') $stylesheet = $row['option_value'];
        }
        $rKey->close();
    }

    // NEW: specifically inspect "hefo" option (Header/Footer injection plugin)
    $sqlHefo = "SELECT option_name, option_value FROM `$optionsTbl` WHERE option_name='hefo' LIMIT 1";
    $rHefo = $db->query($sqlHefo);
    if ($rHefo) {
        if ($row = $rHefo->fetch_assoc()) {
            $res = hefo_malware_detect($row['option_value']);
            if ($res) {
                $susRows[] = [
                    'name' => 'hefo',
                    'why'  => 'hefo_injection_exec',
                    'val'  => 'enable_php=' . $res['enable_php'] . ' | ' . implode(' ; ', $res['hits'])
                ];
            }
        }
        $rHefo->close();
    }

    $sqlBigAuto = "SELECT option_name, option_value
                   FROM `$optionsTbl`
                   WHERE autoload='yes' AND LENGTH(option_value) > 2000
                   LIMIT 50";
    $rBig = $db->query($sqlBigAuto);
    if ($rBig) {
        while ($row = $rBig->fetch_assoc()) {
            $susRows[] = [
                'name'=>$row['option_name'],
                'why'=>'large_autoload',
                'val'=>$row['option_value']
            ];
        }
        $rBig->close();
    }

    $badFrags = ['base64_decode','gzinflate','eval(','<script','http://','https://'];
    $sqlAuto = "SELECT option_name, option_value
                FROM `$optionsTbl`
                WHERE autoload='yes'
                LIMIT 200";
    $rAuto = $db->query($sqlAuto);
    if ($rAuto) {
        while ($row = $rAuto->fetch_assoc()) {
            $val = $row['option_value'];
            foreach ($badFrags as $frag) {
                if (stripos($val, $frag) !== false) {
                    $susRows[] = [
                        'name'=>$row['option_name'],
                        'why'=>"pattern:$frag",
                        'val'=>$val
                    ];
                    break;
                }
            }
        }
        $rAuto->close();
    }

    // NEW: scan any option (not only autoload) for strong malware indicators
    $badFragsStrong = ['openssl_decrypt','curl_exec','eval(','base64_decode','gzinflate','<script','iframe','http://','https://','<?php'];
    $sqlAnyOpt = "SELECT option_name, option_value
                  FROM `$optionsTbl`
                  WHERE " . implode(' OR ', array_fill(0, count($badFragsStrong), "option_value LIKE ?")) . "
                  LIMIT 200";

    $stmt = $db->prepare($sqlAnyOpt);
    if ($stmt) {
        $types = str_repeat('s', count($badFragsStrong));
        $params = [];
        foreach ($badFragsStrong as $frag) $params[] = '%' . $frag . '%';

        $bind = [];
        $bind[] = $types;
        foreach ($params as $i => $pval) $bind[] = &$params[$i];
        @call_user_func_array([$stmt, 'bind_param'], $bind);

        if (@$stmt->execute()) {
            $res = @$stmt->get_result();
            if ($res) {
                while ($row = $res->fetch_assoc()) {
                    $susRows[] = [
                        'name' => $row['option_name'],
                        'why'  => 'any_option_strong_pattern',
                        'val'  => $row['option_value'],
                    ];
                }
            }
        }
        $stmt->close();
    }

    $themes = [];
    if (!empty($template))   $themes[$template]   = true;
    if (!empty($stylesheet)) $themes[$stylesheet] = true;

    $db->close();
    return [$admins, $susRows, array_keys($themes), null];
}


/* ===========================
   ROGUE ADMIN RESPAWN DETECTOR
   =========================== */

function scan_for_user_creation_code($pathsToSearch, $suspiciousUsers) {
    $hits = [];
    $patternsBase = [
        'wp_create_user','wp_insert_user','username_exists','user_email','administrator'
    ];

    foreach ($pathsToSearch as $basePath) {
        if (!$basePath || !is_dir($basePath)) continue;
        $it = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($basePath, FilesystemIterator::SKIP_DOTS)
        );
        foreach ($it as $file) {
            if (!$file->isFile()) continue;
            $fpath = $file->getPathname();
            $ext = strtolower(pathinfo($fpath, PATHINFO_EXTENSION));
            if (!in_array($ext, ['php','phtml','php5','php7','phar'], true)) continue;

            $data = @file_get_contents($fpath);
            if ($data === false) continue;

            $foundGeneric = false;
            foreach ($patternsBase as $pat) {
                if (stripos($data, $pat) !== false) { $foundGeneric = true; break; }
            }
            if (!$foundGeneric) {
                foreach ($suspiciousUsers as $u) {
                    if (stripos($data, $u['login']) !== false ||
                        stripos($data, $u['email']) !== false) {
                        $foundGeneric = true;
                        break;
                    }
                }
            }
            if (!$foundGeneric) continue;

            foreach ($suspiciousUsers as $u) {
                $whyBits = [];
                foreach ($patternsBase as $pat) {
                    if (stripos($data, $pat) !== false) $whyBits[] = $pat;
                }
                if (stripos($data, $u['login']) !== false) $whyBits[] = "username:".$u['login'];
                if (stripos($data, $u['email']) !== false) $whyBits[] = "email:".$u['email'];
                if (!empty($whyBits)) {
                    $hits[] = [
                        'file'=>$fpath,
                        'why'=>implode(",", array_unique($whyBits)),
                        'targetUser'=>$u['login']
                    ];
                }
            }
        }
    }
    return $hits;
}


/* ===========================
   UPLOADS WEB SHELL / BINARY WATCHER
   =========================== */

function find_suspicious_uploads($rootPath) {
    global $fastDays, $uploadsSuspicious, $hadCritical;
    $uploadsDir = rtrim($rootPath, '/') . '/wp-content/uploads';
    if (!is_dir($uploadsDir)) return;

    $badExts = ['php','php5','php7','phtml','phar','ico']; // keep these as "bad" in uploads
    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($uploadsDir, FilesystemIterator::SKIP_DOTS)
    );
    foreach ($it as $file) {
        if (!$file->isFile()) continue;
        $path = $file->getPathname();
        $ext  = strtolower(pathinfo($file->getFilename(), PATHINFO_EXTENSION));

        if ($fastDays !== null && $file->getMTime() < strtotime("-{$fastDays} days")) continue;

        $magic       = sniff_magic($path);
        $execMagic   = in_array($magic, ['ELF','PE','MACHO'], true);
        $looksBinary = $execMagic || is_probably_binary($path);
        $isBadExt    = in_array($ext, $badExts, true);

        if ($isBadExt || $execMagic) {
            $hadCritical = true;
            $uploadsSuspicious[] = [
                'path'   => $path,
                'mtime'  => date('Y-m-d H:i:s', $file->getMTime()),
                'reason' => $execMagic ? 'exec_or_shell' : 'php_or_badext',
                'magic'  => $execMagic ? $magic : '',
                'ext'    => $ext,
            ];
        } elseif ($looksBinary && $ext === '') {
            $hadCritical = true;
            $uploadsSuspicious[] = [
                'path'   => $path,
                'mtime'  => date('Y-m-d H:i:s', $file->getMTime()),
                'reason' => 'binary_no_ext',
                'magic'  => $execMagic ? $magic : '',
                'ext'    => $ext,
            ];
        }
    }
}


/* ===========================
   DIRECTORY WALK / MAIN SCAN
   =========================== */

function scan_dir($dir, $verifyAllFlag = false) {
    global $quiet, $fastDays, $excludeExtensions, $maxSizeMB, $skippedDueToFast, $whitelist, $currentHashes;

    if (!$quiet) echo "[*] Scanning directory: $dir\n";

    $it1 = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS)
    );
    $total = iterator_count($it1);

    $iter = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS)
    );

    $count = 0;
    foreach ($iter as $file) {
        $count++;

        if ($file->isFile()) {
            $path = $file->getPathname();
            $ext  = strtolower(pathinfo($file->getFilename(), PATHINFO_EXTENSION));

            if (in_array($ext, $excludeExtensions, true)) goto progressUpdate;
            if (strpos($path, '/wp-content/updraft/') !== false) goto progressUpdate;

            if ($fastDays !== null && $file->getMTime() < strtotime("-{$fastDays} days")) {
                $skippedDueToFast++;
                goto progressUpdate;
            }

            if ($maxSizeMB !== null && $maxSizeMB > 0) {
                $bytes = $file->getSize();
                if ($bytes !== false && $bytes > ($maxSizeMB * 1024 * 1024)) {
                    if (!$quiet) log_msg("[SKIP] >{$maxSizeMB}MB: $path", 'gray');
                    goto progressUpdate;
                }
            }

            $checksumTmp = @md5_file($path);
            if ($checksumTmp !== false && isset($whitelist[$checksumTmp])) {
                $rel = relative_from_root($path);
                $currentHashes[$rel] = $checksumTmp;
                if ($verifyAllFlag) verify_checksums_for_file($path);
                handle_binary_file($path);
                goto progressUpdate;
            }

            if ($verifyAllFlag) {
                verify_checksums_for_file($path);
            } else {
                if ($checksumTmp !== false) {
                    $rel = relative_from_root($path);
                    $currentHashes[$rel] = $checksumTmp;
                }
            }

            if (!$quiet) echo color("[*] Checking: $path\n", 'gray');
            scan_file($path);
        }

        progressUpdate:
        if ((!$quiet) && (($count % 25 === 0) || ($count === $total))) {
            $percent = $total ? number_format(($count / $total) * 100, 1) : '0.0';
            echo color("[=] Progress: $count / $total files ($percent%)\n", 'cyan');
        }
    }
}


/* ===========================
   MAIN FLOW
   =========================== */

// load whitelist
if (file_exists($whitelistFile)) {
    $lines = file($whitelistFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $w) {
        $w = trim($w);
        if ($w !== '') $whitelist[$w] = true;
    }
}

load_patterns();

// load baseline if provided
if ($baselineLoadFile !== null) {
    $baselineMap = load_baseline_file($baselineLoadFile);
}

// detect WP version + locale and load core checksums (from cache or web)
$wpVer   = detect_wp_version($target);
$locale  = detect_wp_locale_from_config($target);
if ($wpVer) {
    if (!$quiet) echo "[+] WordPress detected at $target (v$wpVer, locale $locale)\n";
    load_core_checksums($wpVer, $locale);
    $wp_root_path = realpath($target);
    $GLOBALS['wp_root_path'] = $wp_root_path;
} else {
    $wp_root_path = realpath($target);
    $GLOBALS['wp_root_path'] = $wp_root_path;
}

// load plugin checksums (with cache) by scanning plugin dirs for versions
$pluginsDir = $target . '/wp-content/plugins';
$missingPluginsForWarn = [];
if (is_dir($pluginsDir)) {
    foreach (glob($pluginsDir . '/*', GLOB_ONLYDIR) as $pluginPath) {
        $slug     = basename($pluginPath);
        $mainFile = "$pluginPath/$slug.php";
        $readme   = "$pluginPath/readme.txt";
        $version  = null;
        if (file_exists($mainFile) &&
            preg_match('/^[ \t\/*#@]*Version:\s*(.+)$/mi', file_get_contents($mainFile), $m)) {
            $version = trim($m[1]);
        } elseif (file_exists($readme) &&
            preg_match('/^[ \t]*Stable tag:\s*(.+)$/mi', file_get_contents($readme), $m)) {
            $version = trim($m[1]);
        }
        if ($version) {
            load_plugin_checksums($slug, $version);
            if (empty($pluginChecksums[$slug])) $missingPluginsForWarn[] = $slug;
        } else {
            vmsg("Could not detect version for plugin $slug; skipping remote checksums.");
            $missingPluginsForWarn[] = $slug;
        }
    }
}

// load theme checksums (via wpmd5 corpus) by scanning theme dirs for versions
$themesDir = $target . '/wp-content/themes';
$missingThemesForWarn = [];
if (is_dir($themesDir)) {
    foreach (glob($themesDir . '/*', GLOB_ONLYDIR) as $themePath) {
        $slug    = basename($themePath);
        $style   = "$themePath/style.css";
        $version = null;
        if (file_exists($style) &&
            preg_match('/^[ \t\/*#@]*Version:\s*(.+)$/mi', file_get_contents($style), $m)) {
            $version = trim($m[1]);
        }
        if ($version) {
            load_theme_checksums($slug, $version);
            if (empty($themeChecksums[$slug])) $missingThemesForWarn[] = $slug;
        } else {
            vmsg("Could not detect version for theme $slug; skipping remote checksums.");
            $missingThemesForWarn[] = $slug;
        }
    }
}

// Early interactive heads-up if we have no core checksums
if (!$checksumsAvailable && !$nonInteractive) {
    log_msg("[WARN] Could not load official WordPress CORE checksums. Integrity may show false positives.", 'yellow', true);
    log_msg("       Tip: ensure this machine can reach api.wordpress.org with the real WP version/locale ($wpVer/$locale).", 'yellow', true);
    log_msg("       Or generate a clean checksum snapshot and save to ~/.wpscan-cache/core_{$wpVer}_{$locale}.json", 'yellow', true);
}

// SCAN FILESYSTEM
log_msg("[*] Starting scan in: $target", 'blue', true);
scan_dir($target, $verifyAll);

// CHECK UPLOADS
find_suspicious_uploads($target);

// AUDIT DB
list($creds, $parseErr) = parse_wp_config($target);
if ($creds === null) {
    $dbAuditError = $parseErr;
} else {
    list($admins, $susRows, $themeSlugs, $dbErr) = audit_wp_db($creds);
    if ($dbErr !== null) {
        $dbAuditError = $dbErr;
    } else {
        $adminUsers       = $admins;
        $optionsFindings  = $susRows;
        $activeThemeSlugs = $themeSlugs;

        foreach ($optionsFindings as $opt) {
            if ($opt['why'] === 'core_site_setting') continue;

            if (
                stripos($opt['why'], 'pattern:') === 0 ||
                $opt['why'] === 'large_autoload' ||
                $opt['why'] === 'hefo_injection_exec' ||
                $opt['why'] === 'any_option_strong_pattern'
            ) {
                $hadCritical = true;
                break;
            }
        }
    }
}

// ROGUE ADMIN RESPAWN
$suspiciousAdmins = [];
foreach ($adminUsers as $au) {
    if (!in_array($au['login'], $knownGoodAdmins, true)) {
        $suspiciousAdmins[] = [
            'login'=>$au['login'],
            'email'=>$au['email']
        ];
    }
}
$searchRoots = [];
$searchRoots[] = $target . '/wp-content/mu-plugins';
foreach ($activeThemeSlugs as $themeSlug) {
    $searchRoots[] = $target . "/wp-content/themes/$themeSlug";
}
$searchRoots[] = $target . "/wp-content/plugins";
$searchRoots[] = $target . "/wp-content";

if (!empty($suspiciousAdmins)) {
    $rogueRespawnHits = scan_for_user_creation_code($searchRoots, $suspiciousAdmins);
    if (!empty($rogueRespawnHits)) $hadCritical = true;
}


/* ===========================
   FINAL SUMMARY
   =========================== */

log_msg("[=] Scan complete.", 'blue', true);

if ($fastDays !== null) {
    log_msg("[?] Skipped $skippedDueToFast older files due to --fast=$fastDays", 'cyan', true);
}

log_msg("[?] Alerts (suspicious code hits incl. binaries): $alertCount", $alertCount ? 'red' : 'green', true);
log_msg("[?] Core/plugin/theme mismatches seen: $coreMismatchCount", $coreMismatchCount ? 'yellow' : 'green', true);
log_msg("[?] Baseline drifted files: $baselineDriftCnt", $baselineDriftCnt ? 'red' : 'green', true);
log_msg("[?] Unknown/suspicious new files (post-heuristic): $newFileCount", $newFileCount ? 'yellow' : 'green', true);

// Detailed [ALERT] lines
if (!empty($alertDetails)) {
    log_msg("[!] Alert details ([ALERT] lines):", 'red', true);
    foreach ($alertDetails as $a) {
        log_msg("    $a", 'red', true);
    }
}

// Detailed mismatches (core/plugin/theme, verify-all + heuristic)
if (!empty($mismatchDetails)) {
    log_msg("[!] Core/plugin/theme mismatch details:", 'yellow', true);
    foreach ($mismatchDetails as $d) {
        log_msg("    - $d", 'yellow', true);
    }
}

if (!empty($quarantinedFiles)) {
    log_msg("[?] Quarantined files this run:", 'red', true);
    foreach ($quarantinedFiles as $q) {
        log_msg("    - {$q['from']} -> {$q['to']}", 'red', true);
    }
}

/* NEW: interactive per-file handling for suspicious uploads */
if (!empty($uploadsSuspicious)) {
    log_msg("[!] Suspicious executable-type files found in uploads:", 'red', true);

    foreach ($uploadsSuspicious as $hit) {
        $path   = $hit['path'];
        $mtime  = $hit['mtime'];
        $reason = $hit['reason'] ?? '';
        $magic  = $hit['magic'] ?? '';
        $ext    = $hit['ext'] ?? '';

        if (!file_exists($path)) {
            log_msg("    - $path (mtime $mtime) [already removed or quarantined]", 'yellow', true);
            continue;
        }

        $reasonDesc = "[reason=$reason";
        if ($magic) $reasonDesc .= ", magic=$magic";
        if ($ext !== '') $reasonDesc .= ", ext=$ext";
        $reasonDesc .= "]";

        log_msg("    - $path (mtime $mtime) $reasonDesc", 'red', true);

        // In noninteractive/cron mode we just log.
        if ($nonInteractive) {
            continue;
        }

        echo color("    Action for uploads suspicious file:\n", 'yellow');
        echo color("        Q = quarantine (move to quarantine dir)\n", 'yellow');
        echo color("        D = delete permanently\n", 'yellow');
        echo color("        I = ignore (leave in place)\n", 'yellow');
        echo color("Choice [Q/D/I]: ", 'yellow');
        $choice = strtoupper(trim(fgets(STDIN)));

        switch ($choice) {
            case 'Q':
                if ($quarantineDir) {
                    $dest = quarantine_file($path);
                    if ($dest !== false) {
                        $hadCritical = true;
                        log_msg("[UPLOAD-QUARANTINED] $path -> $dest", 'red', true);
                    } else {
                        log_msg("[UPLOAD-QUARANTINE-FAIL] $path could not be moved", 'yellow', true);
                    }
                } else {
                    log_msg("[UPLOAD-QUARANTINE-SKIP] No quarantine dir set for $path", 'yellow', true);
                }
                break;

            case 'D':
                if (@unlink($path)) {
                    $hadCritical = true;
                    log_msg("[UPLOAD-DELETED] $path removed", 'red', true);
                } else {
                    log_msg("[UPLOAD-DELETE-FAIL] Could not delete $path", 'yellow', true);
                }
                break;

            case 'I':
            default:
                log_msg("[UPLOAD-IGNORED] $path left in place", 'yellow', true);
                break;
        }
    }

    log_msg("[!] PHP or binaries in uploads are almost always malicious. Review the above actions carefully.", 'red', true);
}

// admin audit, respawn, options findings
if ($dbAuditError !== null) {
    log_msg("[?] Admin user audit: could not retrieve admin list ($dbAuditError)", 'yellow', true);
} else {
    if (count($adminUsers) === 0) {
        log_msg("[?] Admin user audit: no admin rows found (check wp-admin > Users)", 'yellow', true);
    } else {
        log_msg("[?] Admin user audit: accounts with administrator capabilities:", 'blue', true);
        foreach ($adminUsers as $u) {
            log_msg("    - {$u['login']} <{$u['email']}> (created {$u['registered']})", 'magenta', true);
        }
        log_msg("[!] Check above for weird / newly created admins.", 'red', true);
    }

    if (!empty($rogueRespawnHits)) {
        log_msg("[!] Possible rogue admin respawn code detected:", 'red', true);
        foreach ($rogueRespawnHits as $hit) {
            log_msg("    - {$hit['file']} | user={$hit['targetUser']} | {$hit['why']}", 'red', true);
        }
        log_msg("[!] Remove any code that auto-creates admin users, then delete that rogue admin in the DB.", 'red', true);
    } else {
        log_msg("[?] No direct user-create code found in mu-plugins/themes/plugins for suspicious admins.", 'cyan', true);
    }

    if (!empty($optionsFindings)) {
        log_msg("[?] wp_options audit findings:", 'blue', true);
        foreach ($optionsFindings as $row) {
            $name = $row['name'];
            $why  = $row['why'];
            $val  = $row['val'];

            $preview = $val;
            if (strlen($preview) > 300) $preview = substr($preview, 0, 300) . "...(truncated)";
            $previewOneLine = preg_replace('/\s+/', ' ', $preview);

            $rowColor = ($why !== 'core_site_setting' ? 'yellow' : 'gray');
            if ($why === 'hefo_injection_exec') $rowColor = 'red';

            log_msg(
                "    - $name [$why]: $previewOneLine",
                $rowColor,
                true
            );
        }
        log_msg("[!] Look for injected JS/malware in suspicious/large autoloaded options above.", 'red', true);
    }
}

// baseline save
if ($baselineSaveFile !== null) {
    save_baseline_file($baselineSaveFile, $currentHashes);
    log_msg("[?] Baseline saved to $baselineSaveFile (" . count($currentHashes) . " files hashed).", 'cyan', true);
}

// Integrity source availability notes
$warned = false;
if (!$checksumsAvailable) {
    $warned = true;
    log_msg("[WARN] Could not load official WordPress CORE checksums. Core file integrity may show false positives.", 'yellow', true);
    log_msg("       Tip: ensure this machine can reach api.wordpress.org with the real WP version/locale ($wpVer/$locale).", 'yellow', true);
    log_msg("       Or generate a clean checksum snapshot and save to ~/.wpscan-cache/core_{$wpVer}_{$locale}.json", 'yellow', true);
}
if (!empty($missingPluginsForWarn)) {
    $warned = true;
    log_msg("[WARN] Could not load checksums for plugin(s): ".implode(', ', $missingPluginsForWarn).". Those plugins may be flagged as [EXTRA] if not treated as custom.", 'yellow', true);
    log_msg("       Tip: for commercial/custom plugins, put a checksum map at ~/.wpscan-cache/plugin_SLUG_VERSION.json", 'yellow', true);
}
if (!empty($missingThemesForWarn)) {
    $warned = true;
    log_msg("[WARN] Could not load checksums for theme(s): ".implode(', ', $missingThemesForWarn).". Active theme files may be flagged as [EXTRA] if not treated as custom.", 'yellow', true);
    log_msg("       Tip: for premium/custom themes, build a checksum map from a clean ZIP and save to ~/.wpscan-cache/theme_THEMESLUG_VERSION.json", 'yellow', true);
}
if ($warned) {
    log_msg("[INFO] Integrity note: some checksum sources were missing or unreachable. Run with --verbose for fetch diagnostics.", 'cyan', true);
}

/*
Exit code rules:
 0 = looks clean-ish
 1 = critical indicators found (shells, tampering, rogue admin code, quarantined files, binaries, etc.)
 2 = DB audit couldn't run, but filesystem didn't scream
*/
if ($dbAuditError !== null) {
    $exitCode = ($hadCritical || !empty($quarantinedFiles)) ? 1 : 2;
} else {
    if ($hadCritical ||
        $baselineDriftCnt > 0 ||
        !empty($uploadsSuspicious) ||
        !empty($rogueRespawnHits) ||
        !empty($quarantinedFiles)) {
        $exitCode = 1;
    } else {
        $exitCode = 0;
    }
}

exit($exitCode);

?>

