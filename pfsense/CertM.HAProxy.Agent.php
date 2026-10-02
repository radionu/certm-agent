#!/usr/local/bin/php -f
<?php

declare(strict_types=1);

const CERTM_PFSENSE_AGENT_VERSION = '1.0.0-rc.34';
const CERTM_PFSENSE_AGENT_TYPE = 'pfsense-haproxy';
const CERTM_PFSENSE_SERVICE = 'pfsense-haproxy';
const CERTM_PFSENSE_CONFIG = '/conf/certm/config.json';
const CERTM_PFSENSE_LOG = '/var/log/certm-haproxy.log';
const CERTM_PFSENSE_LOCK = '/var/run/certm-haproxy.lock';
const CERTM_PFSENSE_PUBLIC_KEY = '/conf/certm/update-public.pem';
const CERTM_PFSENSE_COMMAND = '/conf/certm/certm-haproxy';
const CERTM_PFSENSE_COMMAND_LINK = '/usr/local/sbin/certm-haproxy';

function certm_log(string $message, string $level = 'INFO'): void
{
    $line = sprintf(
        "%s [%s] %s\n",
        date(DATE_ATOM),
        strtoupper($level),
        $message
    );
    file_put_contents(CERTM_PFSENSE_LOG, $line, FILE_APPEND | LOCK_EX);
    fwrite($level === 'ERROR' ? STDERR : STDOUT, $line);
}

function certm_fail(string $message): never
{
    throw new RuntimeException($message);
}

function certm_load_pfsense(): void
{
    global $config, $g;

    foreach ([
        '/etc/inc/config.inc',
        '/etc/inc/certs.inc',
        '/etc/inc/services.inc',
        '/usr/local/pkg/haproxy/haproxy.inc',
    ] as $file) {
        if (!is_file($file)) {
            certm_fail("Required pfSense/HAProxy component is missing: {$file}");
        }
        require_once $file;
    }
}

function certm_config_path(): string
{
    $override = getenv('CERTM_PFSENSE_CONFIG');
    return is_string($override) && $override !== ''
        ? $override
        : CERTM_PFSENSE_CONFIG;
}

function certm_load_config(): array
{
    $path = certm_config_path();
    if (!is_file($path)) {
        certm_fail("CertM configuration is missing: {$path}");
    }
    $config = json_decode((string) file_get_contents($path), true);
    if (!is_array($config)) {
        certm_fail('CertM configuration is not valid JSON.');
    }
    $apiBase = rtrim(trim((string) ($config['api_base'] ?? '')), '/');
    if (!preg_match('#^https://#i', $apiBase)) {
        certm_fail('api_base must be an HTTPS URL.');
    }
    $config['api_base'] = $apiBase;
    return $config;
}

function certm_save_config(array $config): void
{
    $path = certm_config_path();
    $directory = dirname($path);
    if (!is_dir($directory) && !mkdir($directory, 0700, true)) {
        certm_fail("Unable to create {$directory}");
    }
    $temporary = $path.'.tmp.'.getmypid();
    $json = json_encode($config, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    if (!is_string($json) || file_put_contents($temporary, $json."\n", LOCK_EX) === false) {
        certm_fail('Unable to write CertM configuration.');
    }
    chmod($temporary, 0600);
    if (!rename($temporary, $path)) {
        @unlink($temporary);
        certm_fail('Unable to replace CertM configuration atomically.');
    }
}

function certm_machine_id(): string
{
    $uuid = trim((string) shell_exec('/sbin/sysctl -n kern.hostuuid 2>/dev/null'));
    if (!preg_match('/^[A-Fa-f0-9-]{16,64}$/', $uuid)) {
        certm_fail('Unable to read a stable pfSense host UUID.');
    }
    return 'pfsense:'.strtolower($uuid);
}

function certm_pfsense_version(): string
{
    $versionCommand = trim((string) shell_exec(
        '/usr/local/sbin/pfSense-version -sv 2>/dev/null'
    ));

    if ($versionCommand !== '') {
        return $versionCommand;
    }

    if (is_readable('/etc/version')) {
        $versionFile = trim((string) file_get_contents('/etc/version'));
        if ($versionFile !== '') {
            return $versionFile;
        }
    }

    return '';
}

function certm_headers(string $token): array
{
    return [
        'Authorization: Bearer '.$token,
        'X-CertM-Machine-ID: '.certm_machine_id(),
        'X-CertM-Agent-Type: '.CERTM_PFSENSE_AGENT_TYPE,
        'X-CertM-Agent-Version: '.CERTM_PFSENSE_AGENT_VERSION,
        'Accept: application/json',
    ];
}

function certm_api(
    array $config,
    string $method,
    string $path,
    string $token,
    ?array $query = null,
    ?array $body = null
): array {
    if (!function_exists('curl_init')) {
        certm_fail('The pfSense PHP cURL extension is required.');
    }
    $url = $config['api_base'].'/'.$path;
    if ($query !== null) {
        $url .= '?'.http_build_query($query, '', '&', PHP_QUERY_RFC3986);
    }
    $headers = certm_headers($token);
    $curl = curl_init($url);
    if ($curl === false) {
        certm_fail('Unable to initialize HTTPS request.');
    }
    curl_setopt_array($curl, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 15,
        CURLOPT_TIMEOUT => 90,
        CURLOPT_CUSTOMREQUEST => strtoupper($method),
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
    ]);
    if ($body !== null) {
        $encoded = json_encode($body, JSON_UNESCAPED_SLASHES);
        if (!is_string($encoded)) {
            certm_fail('Unable to encode CertM request body.');
        }
        $headers[] = 'Content-Type: application/json';
        curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($curl, CURLOPT_POSTFIELDS, $encoded);
    }
    $response = curl_exec($curl);
    $status = (int) curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
    $error = curl_error($curl);
    curl_close($curl);
    if (!is_string($response)) {
        certm_fail('CertM HTTPS request failed: '.$error);
    }
    $decoded = json_decode($response, true);
    if (!is_array($decoded)) {
        certm_fail("CertM returned non-JSON HTTP {$status}.");
    }
    if ($status < 200 || $status >= 300) {
        $message = (string) ($decoded['message'] ?? $decoded['status'] ?? 'request failed');
        throw new RuntimeException("CertM HTTP {$status}: {$message}", $status);
    }
    return $decoded;
}


function certm_update_report(
    array $config,
    string $token,
    int $releaseId,
    string $status,
    string $message,
    ?string $version = null
): void {
    $body = [
        'release_id' => $releaseId,
        'status' => $status,
        'message' => substr($message, 0, 2000),
    ];
    if ($version !== null) {
        $body['installed_version'] = $version;
    }
    certm_api(
        $config,
        'POST',
        'client/agent-update/report',
        $token,
        null,
        $body
    );
}

function certm_download_update(
    array $config,
    string $token,
    string $path,
    string $destination
): void {
    if (!preg_match('#^/client/agent-update/download/[0-9]+$#', $path)) {
        certm_fail('CertM returned an invalid pfSense update download path.');
    }
    $handle = fopen($destination, 'wb');
    if ($handle === false) {
        certm_fail('Unable to create the pfSense update package.');
    }
    $curl = curl_init($config['api_base'].$path);
    if ($curl === false) {
        fclose($handle);
        certm_fail('Unable to initialize the pfSense update download.');
    }
    curl_setopt_array($curl, [
        CURLOPT_FILE => $handle,
        CURLOPT_CONNECTTIMEOUT => 15,
        CURLOPT_TIMEOUT => 120,
        CURLOPT_HTTPHEADER => certm_headers($token),
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
    ]);
    $ok = curl_exec($curl);
    $status = (int) curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
    $error = curl_error($curl);
    curl_close($curl);
    fclose($handle);
    if ($ok !== true || $status !== 200) {
        @unlink($destination);
        certm_fail(
            "CertM update download failed with HTTP {$status}: {$error}"
        );
    }
}

function certm_pin_update_key(
    array $config,
    string $token,
    string $expectedFingerprint
): string {
    $metadata = certm_api(
        $config,
        'GET',
        'client/agent-update/key',
        $token
    );
    $pem = (string) ($metadata['pem'] ?? '');
    $fingerprint = hash('sha256', $pem);
    if (
        ($metadata['algorithm'] ?? null) !== 'RSA-SHA256' ||
        !hash_equals(
            (string) ($metadata['fingerprint_sha256'] ?? ''),
            $fingerprint
        ) ||
        !hash_equals($expectedFingerprint, $fingerprint) ||
        openssl_pkey_get_public($pem) === false
    ) {
        certm_fail('CertM agent-update signing key validation failed.');
    }
    if (is_file(CERTM_PFSENSE_PUBLIC_KEY)) {
        $pinned = (string) file_get_contents(CERTM_PFSENSE_PUBLIC_KEY);
        if (!hash_equals(hash('sha256', $pinned), $fingerprint)) {
            certm_fail(
                'CertM signing key differs from the pinned pfSense key.'
            );
        }
    } else {
        $temporary = CERTM_PFSENSE_PUBLIC_KEY.'.tmp.'.getmypid();
        if (file_put_contents($temporary, $pem, LOCK_EX) === false) {
            certm_fail('Unable to pin the CertM signing key.');
        }
        chmod($temporary, 0600);
        if (!rename($temporary, CERTM_PFSENSE_PUBLIC_KEY)) {
            @unlink($temporary);
            certm_fail('Unable to install the CertM signing key.');
        }
        certm_log("Pinned agent-update public key {$fingerprint}");
    }
    return $pem;
}

function certm_remove_tree(string $path): void
{
    if (!is_dir($path)) {
        @unlink($path);
        return;
    }
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator(
            $path,
            FilesystemIterator::SKIP_DOTS
        ),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($iterator as $item) {
        $item->isDir()
            ? @rmdir($item->getPathname())
            : @unlink($item->getPathname());
    }
    @rmdir($path);
}

function certm_verify_update_package(
    string $archive,
    string $root,
    string $version
): array {
    $output = [];
    $code = 0;
    exec(
        '/usr/bin/tar -xzf '.escapeshellarg($archive).
        ' -C '.escapeshellarg($root).' 2>&1',
        $output,
        $code
    );
    if ($code !== 0) {
        certm_fail(
            'Unable to extract pfSense update: '.implode(' ', $output)
        );
    }
    $manifestPath = $root.'/manifest.json';
    $manifest = is_file($manifestPath)
        ? json_decode((string) file_get_contents($manifestPath), true)
        : null;
    if (
        !is_array($manifest) ||
        ($manifest['schema'] ?? null) !== 1 ||
        ($manifest['platform'] ?? null) !== 'pfsense' ||
        ($manifest['version'] ?? null) !== $version
    ) {
        certm_fail('Invalid pfSense agent update manifest.');
    }

    $expected = [
        'pfsense/CertM.HAProxy.Agent.php',
        'pfsense/certm-haproxy',
    ];
    $declared = [];
    foreach (($manifest['files'] ?? []) as $file) {
        $relative = (string) ($file['path'] ?? '');
        $hash = (string) ($file['sha256'] ?? '');
        $path = $root.'/'.$relative;
        if (
            !in_array($relative, $expected, true) ||
            isset($declared[$relative]) ||
            !preg_match('/^[a-f0-9]{64}$/', $hash) ||
            !is_file($path) ||
            !hash_equals($hash, hash_file('sha256', $path))
        ) {
            certm_fail("Invalid pfSense update file: {$relative}");
        }
        $declared[$relative] = true;
    }
    $declaredFiles = array_keys($declared);
    sort($declaredFiles);
    sort($expected);
    if ($declaredFiles !== $expected) {
        certm_fail('The pfSense update package is incomplete.');
    }

    $actual = [];
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator(
            $root,
            FilesystemIterator::SKIP_DOTS
        )
    );
    foreach ($iterator as $item) {
        if ($item->isLink() || !$item->isFile()) {
            certm_fail('The pfSense update package has an unsafe entry.');
        }
        $actual[] = substr(
            $item->getPathname(),
            strlen($root) + 1
        );
    }
    sort($actual);
    $allowed = array_merge(['manifest.json'], $expected);
    sort($allowed);
    if ($actual !== $allowed) {
        certm_fail('The pfSense update package has undeclared files.');
    }

    exec(
        '/usr/local/bin/php -l '.
        escapeshellarg($root.'/pfsense/CertM.HAProxy.Agent.php').
        ' >/dev/null 2>&1',
        $output,
        $phpCode
    );
    exec(
        '/bin/sh -n '.escapeshellarg($root.'/pfsense/certm-haproxy').
        ' >/dev/null 2>&1',
        $output,
        $shellCode
    );
    if ($phpCode !== 0 || $shellCode !== 0) {
        certm_fail('The pfSense update package failed syntax validation.');
    }
    return $manifest;
}

function certm_copy_atomic(
    string $source,
    string $target,
    int $mode = 0700
): void {
    $temporary = $target.'.update.'.getmypid();
    if (!copy($source, $temporary)) {
        certm_fail("Unable to stage updated file {$target}.");
    }
    chmod($temporary, $mode);
    if (!rename($temporary, $target)) {
        @unlink($temporary);
        certm_fail("Unable to replace {$target}.");
    }
}

function certm_run_update(bool $manual = false): bool
{
    $config = certm_load_config();
    $token = certm_client_token($config);
    $response = certm_api(
        $config,
        'GET',
        'client/agent-update',
        $token
    );
    $update = $response['update'] ?? null;
    if (!is_array($update)) {
        if ($manual) {
            certm_log('No pfSense agent update is assigned.');
        }
        return false;
    }
    if (($update['platform'] ?? null) !== 'pfsense') {
        certm_fail('CertM assigned a non-pfSense agent package.');
    }

    $releaseId = (int) ($update['release_id'] ?? 0);
    $version = (string) ($update['version'] ?? '');
    $working = '/tmp/certm-pfsense-update-'.getmypid().'-'.
        bin2hex(random_bytes(4));
    $archive = $working.'/package.tar.gz';
    $extracted = $working.'/extracted';
    $backup = $working.'/backup';
    if (
        !mkdir($extracted, 0700, true) ||
        !mkdir($backup, 0700, true)
    ) {
        certm_fail('Unable to create pfSense update workspace.');
    }

    $targets = [
        'agent' => __FILE__,
        'command' => CERTM_PFSENSE_COMMAND,
        'command_link' => CERTM_PFSENSE_COMMAND_LINK,
    ];
    $modified = false;
    try {
        $pem = certm_pin_update_key(
            $config,
            $token,
            (string) ($update['signing_key_fingerprint'] ?? '')
        );
        certm_download_update(
            $config,
            $token,
            (string) ($update['download_path'] ?? ''),
            $archive
        );
        $actualHash = hash_file('sha256', $archive);
        if (
            !is_string($actualHash) ||
            !hash_equals((string) ($update['sha256'] ?? ''), $actualHash)
        ) {
            certm_fail('Downloaded pfSense package SHA-256 mismatch.');
        }
        $signature = base64_decode(
            (string) ($update['signature'] ?? ''),
            true
        );
        $contents = file_get_contents($archive);
        if (
            !is_string($signature) ||
            !is_string($contents) ||
            openssl_verify(
                $contents,
                $signature,
                $pem,
                OPENSSL_ALGO_SHA256
            ) !== 1
        ) {
            certm_fail('Downloaded pfSense package signature is invalid.');
        }

        certm_verify_update_package($archive, $extracted, $version);
        certm_update_report(
            $config,
            $token,
            $releaseId,
            'STARTED',
            "Installing pfSense agent {$version}"
        );

        foreach ($targets as $name => $target) {
            if (is_file($target) && !copy($target, $backup.'/'.$name)) {
                certm_fail("Unable to back up {$target}.");
            }
        }
        $modified = true;
        certm_copy_atomic(
            $extracted.'/pfsense/CertM.HAProxy.Agent.php',
            $targets['agent']
        );
        certm_copy_atomic(
            $extracted.'/pfsense/certm-haproxy',
            $targets['command']
        );
        certm_copy_atomic(
            $extracted.'/pfsense/certm-haproxy',
            $targets['command_link']
        );

        $installed = (string) file_get_contents($targets['agent']);
        if (!preg_match(
            "/CERTM_PFSENSE_AGENT_VERSION = '([^']+)'/",
            $installed,
            $match
        ) || $match[1] !== $version) {
            certm_fail('Updated pfSense agent version self-test failed.');
        }

        certm_update_report(
            $config,
            $token,
            $releaseId,
            'SUCCESS',
            "pfSense agent updated successfully to {$version}",
            $version
        );
        certm_log("CertM pfSense agent updated successfully to {$version}.");
        return true;
    } catch (Throwable $exception) {
        if ($modified) {
            foreach ($targets as $name => $target) {
                if (is_file($backup.'/'.$name)) {
                    certm_copy_atomic($backup.'/'.$name, $target);
                }
            }
        }
        try {
            certm_update_report(
                $config,
                $token,
                $releaseId,
                $modified ? 'ROLLBACK' : 'FAILED',
                $exception->getMessage()
            );
        } catch (Throwable $reportException) {
            certm_log(
                'Unable to report pfSense update failure: '.
                $reportException->getMessage(),
                'WARN'
            );
        }
        throw $exception;
    } finally {
        certm_remove_tree($working);
    }
}

function certm_client_token(array $config): string
{
    $token = trim((string) ($config['client_token'] ?? ''));
    if ($token === '') {
        certm_fail('This pfSense firewall is not enrolled with CertM.');
    }
    return $token;
}

function certm_subject(array|string|null $subject): ?string
{
    if (is_string($subject)) {
        return $subject;
    }
    if (!is_array($subject)) {
        return null;
    }
    $parts = [];
    foreach ($subject as $key => $value) {
        $parts[] = $key.'='.(is_array($value) ? implode('+', $value) : $value);
    }
    return implode(', ', $parts);
}

function certm_fingerprint(string $certificate): string
{
    $fingerprint = openssl_x509_fingerprint($certificate, 'sha256');
    if (!is_string($fingerprint)) {
        certm_fail('Unable to calculate certificate SHA-256 fingerprint.');
    }
    return strtolower(str_replace(':', '', $fingerprint));
}

function certm_pem_blocks(string $pem): array
{
    preg_match_all(
        '/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----\s*/s',
        $pem,
        $matches
    );
    return array_values(array_filter(array_map('trim', $matches[0] ?? [])));
}

function certm_certificate_domains(string $certificate): array
{
    $parsed = openssl_x509_parse($certificate, false);
    if (!is_array($parsed)) {
        return [];
    }
    $domains = [];
    $san = (string) ($parsed['extensions']['subjectAltName'] ?? '');
    foreach (explode(',', $san) as $entry) {
        $entry = trim($entry);
        if (stripos($entry, 'DNS:') === 0) {
            $domains[] = strtolower(rtrim(substr($entry, 4), '.'));
        }
    }
    $cn = strtolower(rtrim((string) (
        $parsed['subject']['CN'] ??
        $parsed['subject']['commonName'] ??
        ''
    ), '.'));
    if ($cn !== '') {
        $domains[] = $cn;
    }
    return array_values(array_unique(array_filter($domains)));
}

function certm_domain_matches(string $domain, array $patterns): bool
{
    $domain = strtolower(rtrim($domain, '.'));
    foreach ($patterns as $pattern) {
        $pattern = strtolower(rtrim($pattern, '.'));
        if ($pattern === $domain) {
            return true;
        }
        if (str_starts_with($pattern, '*.')) {
            $base = substr($pattern, 2);
            if (str_ends_with($domain, '.'.$base)) {
                $prefix = substr($domain, 0, -strlen('.'.$base));
                if ($prefix !== '' && !str_contains($prefix, '.')) {
                    return true;
                }
            }
        }
    }
    return false;
}

function certm_acl_domains(array $frontend): array
{
    $domains = [];
    foreach (($frontend['ha_acls']['item'] ?? []) as $acl) {
        if (($acl['expression'] ?? '') !== 'host_matches') {
            continue;
        }
        preg_match_all(
            '/(?<![A-Za-z0-9_-])(?:\*\.)?[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?(?::\d+)?/',
            (string) ($acl['value'] ?? ''),
            $matches
        );
        foreach ($matches[0] ?? [] as $value) {
            $value = strtolower(preg_replace('/:\d+$/', '', $value));
            if (str_contains($value, '.') && strlen($value) <= 253) {
                $domains[] = $value;
            }
        }
    }
    return array_values(array_unique($domains));
}

function certm_frontend_ports(array $frontend): array
{
    $ports = [];
    foreach (($frontend['a_extaddr']['item'] ?? []) as $address) {
        if (!in_array((string) ($address['extaddr_ssl'] ?? ''), ['1', 'on', 'yes'], true)) {
            continue;
        }
        foreach (explode(',', (string) ($address['extaddr_port'] ?? '443')) as $port) {
            $port = trim($port);
            if (ctype_digit($port) && (int) $port >= 1 && (int) $port <= 65535) {
                $ports[] = (int) $port;
            }
        }
    }
    return array_values(array_unique($ports ?: [443]));
}

function certm_frontend_certificate_refs(array $frontend): array
{
    $refs = [];
    $primary = trim((string) ($frontend['ssloffloadcert'] ?? ''));
    if ($primary !== '') {
        $refs[$primary] = true;
    }
    foreach (($frontend['ha_certificates']['item'] ?? []) as $item) {
        $ref = trim((string) ($item['ssl_certificate'] ?? ''));
        if ($ref !== '') {
            $refs[$ref] = false;
        }
    }
    return $refs;
}

function certm_discover_bindings(): array
{
    $bindings = [];
    $frontends = config_get_path('installedpackages/haproxy/ha_backends/item', []);
    foreach ($frontends as $frontendIndex => $frontend) {
        if (($frontend['status'] ?? '') !== 'active') {
            continue;
        }
        $name = trim((string) ($frontend['name'] ?? ''));
        if ($name === '') {
            continue;
        }
        $secondary = ($frontend['secondary'] ?? '') === 'yes';
        $primaryName = $secondary
            ? trim((string) ($frontend['primary_frontend'] ?? ''))
            : $name;
        if ($primaryName === '') {
            certm_log("Skipping HAProxy frontend {$name}: primary frontend is unknown.", 'WARN');
            continue;
        }
        $aclDomains = certm_acl_domains($frontend);
        $coveredAclDomains = [];
        foreach (certm_frontend_certificate_refs($frontend) as $refid => $primary) {
            $lookup = lookup_cert($refid);
            $cert = $lookup['item'] ?? null;
            if (!is_array($cert) || empty($cert['crt']) || empty($cert['prv'])) {
                certm_log("Skipping HAProxy certificate {$refid}: certificate or private key is missing.", 'WARN');
                continue;
            }
            $pem = base64_decode((string) $cert['crt'], true);
            if (!is_string($pem) || openssl_x509_read($pem) === false) {
                certm_log("Skipping HAProxy certificate {$refid}: invalid certificate data.", 'WARN');
                continue;
            }
            $patterns = certm_certificate_domains($pem);
            $domains = array_values(array_filter(
                $aclDomains,
                fn (string $domain) => certm_domain_matches($domain, $patterns)
            ));
            foreach ($domains as $domain) {
                $coveredAclDomains[$domain] = true;
            }
            if ($domains === []) {
                $domains = $patterns;
            }
            $parsed = openssl_x509_parse($pem, false) ?: [];
            foreach (certm_frontend_ports($frontend) as $port) {
                foreach ($domains as $domain) {
                    $bindings[] = [
                        'site_name' => $name,
                        'site_state' => 'Started',
                        'domain' => $domain,
                        'port' => $port,
                        'protocol' => 'https',
                        'subject' => certm_subject($parsed['subject'] ?? null),
                        'issuer' => certm_subject($parsed['issuer'] ?? null),
                        'serial_number' => (string) ($parsed['serialNumberHex'] ?? $parsed['serialNumber'] ?? ''),
                        'fingerprint_sha256' => certm_fingerprint($pem),
                        'served_fingerprint_sha256' => null,
                        'not_before' => isset($parsed['validFrom_time_t'])
                            ? gmdate(DATE_ATOM, (int) $parsed['validFrom_time_t'])
                            : null,
                        'not_after' => isset($parsed['validTo_time_t'])
                            ? gmdate(DATE_ATOM, (int) $parsed['validTo_time_t'])
                            : null,
                        'cert_path' => 'config.xml:cert/'.$refid,
                        'key_path' => 'config.xml:cert/'.$refid,
                        'binding_id' => sprintf(
                            'pfsense-haproxy:%s:%d:%s:%s',
                            $name,
                            $port,
                            $refid,
                            $domain
                        ),
                        '_cert_ref' => $refid,
                        '_group_key' => 'certificate:'.$refid,
                        '_cert_index' => $lookup['idx'],
                        '_primary' => $primary,
                        '_frontend_index' => (int) $frontendIndex,
                        '_frontend_name' => $name,
                        '_primary_frontend_name' => $primaryName,
                        '_secondary' => $secondary,
                        '_pem_path' => (!$secondary && $primary)
                            ? '/var/etc/haproxy/'.$name.'.pem'
                            : '/var/etc/haproxy/'.$primaryName.'/'.$name.'_'.$refid.'.pem',
                    ];
                }
            }
        }

        foreach ($aclDomains as $domain) {
            if (isset($coveredAclDomains[$domain])) {
                continue;
            }
            foreach (certm_frontend_ports($frontend) as $port) {
                $bindings[] = [
                    'site_name' => $name,
                    'site_state' => 'Started',
                    'domain' => $domain,
                    'port' => $port,
                    'protocol' => 'https',
                    'subject' => null,
                    'issuer' => null,
                    'serial_number' => null,
                    'fingerprint_sha256' => null,
                    'served_fingerprint_sha256' => null,
                    'not_before' => null,
                    'not_after' => null,
                    'cert_path' => 'config.xml:haproxy/'.$name.'/pending/'.$domain,
                    'key_path' => null,
                    'binding_id' => sprintf(
                        'pfsense-haproxy:%s:%d:pending:%s',
                        $name,
                        $port,
                        $domain
                    ),
                    '_cert_ref' => null,
                    '_group_key' => 'pending:'.$domain,
                    '_cert_index' => null,
                    '_primary' => false,
                    '_frontend_index' => (int) $frontendIndex,
                    '_frontend_name' => $name,
                    '_primary_frontend_name' => $primaryName,
                    '_secondary' => $secondary,
                    '_pem_path' => null,
                ];
            }
        }
    }
    if ($bindings === []) {
        certm_fail('No active pfSense HAProxy SSL certificate binding was discovered.');
    }
    return $bindings;
}

function certm_public_binding(array $binding): array
{
    return array_filter(
        $binding,
        fn (string $key) => !str_starts_with($key, '_'),
        ARRAY_FILTER_USE_KEY
    );
}

function certm_identity(array $config): array
{
    $token = certm_client_token($config);
    $identity = certm_api($config, 'GET', 'client/preflight', $token);
    if (($identity['status'] ?? '') !== 'active') {
        certm_fail('CertM client is not ACTIVE: '.($identity['status'] ?? 'unknown'));
    }
    $status = certm_api($config, 'GET', 'client/status', $token);
    if (($status['status'] ?? '') !== 'active') {
        certm_fail('CertM client status is not ACTIVE.');
    }
    return [$token, $identity];
}

function certm_push_inventory(array $config, string $token, array $bindings): array
{
    $items = array_map('certm_public_binding', $bindings);
    $result = certm_api($config, 'POST', 'client/inventory', $token, null, [
        'service' => CERTM_PFSENSE_SERVICE,
        'hostname' => gethostname() ?: 'pfsense',
        'display_name' => trim((string) ($config['display_name'] ?? '')),
        'agent_version' => CERTM_PFSENSE_AGENT_VERSION,
        'os_name' => 'pfSense',
        'os_version' => certm_pfsense_version(),
        'items' => $items,
    ]);
    certm_log('Inventory sent; '.count($items).' HAProxy HTTPS binding(s) discovered.');
    return $result;
}

function certm_desired(array $config, string $token, array $binding): ?array
{
    try {
        $result = certm_api($config, 'GET', 'cert/desired', $token, [
            'domain' => $binding['domain'],
        ]);
    } catch (RuntimeException $exception) {
        if ($exception->getCode() === 404) {
            return null;
        }
        throw $exception;
    }
    return ($result['status'] ?? '') === 'ok' ? $result : null;
}

function certm_desired_key(array $desired): string
{
    return implode(':', [
        (int) $desired['certificate_id'],
        (int) $desired['certificate_version_id'],
        (string) $desired['deployment_revision'],
        strtolower((string) $desired['fingerprint_sha256']),
    ]);
}

function certm_decode_package(array $response, array $desired, array $domains): array
{
    if (($response['status'] ?? '') !== 'ok') {
        certm_fail('CertM returned an invalid certificate package status.');
    }
    $files = $response['files'] ?? [];
    $leaf = base64_decode((string) ($files['certificate.pem'] ?? ''), true);
    $key = base64_decode((string) ($files['privkey.pem'] ?? ''), true);
    $fullchain = base64_decode((string) ($files['fullchain.pem'] ?? ''), true);
    if (!is_string($leaf) || !is_string($key) || !is_string($fullchain)) {
        certm_fail('CertM package contains invalid base64 data.');
    }
    $leafResource = openssl_x509_read($leaf);
    $keyResource = openssl_pkey_get_private($key);
    if ($leafResource === false || $keyResource === false || !openssl_x509_check_private_key($leafResource, $keyResource)) {
        certm_fail('CertM package certificate and private key do not match.');
    }
    $expected = strtolower(str_replace(':', '', (string) ($desired['fingerprint_sha256'] ?? '')));
    if (!preg_match('/^[a-f0-9]{64}$/', $expected) || !hash_equals($expected, certm_fingerprint($leaf))) {
        certm_fail('Downloaded certificate fingerprint does not match desired metadata.');
    }
    $blocks = certm_pem_blocks($fullchain);
    if ($blocks === [] || !hash_equals(certm_fingerprint($leaf), certm_fingerprint($blocks[0]))) {
        certm_fail('Downloaded full chain does not start with the leaf certificate.');
    }
    $patterns = certm_certificate_domains($leaf);
    foreach ($domains as $domain) {
        if (!certm_domain_matches($domain, $patterns)) {
            certm_fail("Downloaded certificate does not cover {$domain}.");
        }
    }
    return [
        'deployment_id' => (int) ($response['deployment_id'] ?? 0),
        'leaf' => $leaf,
        'key' => $key,
        'chain' => array_slice($blocks, 1),
        'expected' => $expected,
    ];
}

function certm_find_ca_by_fingerprint(string $fingerprint): ?array
{
    foreach (config_get_path('ca', []) as $index => $ca) {
        $pem = base64_decode((string) ($ca['crt'] ?? ''), true);
        if (is_string($pem) && openssl_x509_read($pem) !== false) {
            if (hash_equals($fingerprint, certm_fingerprint($pem))) {
                return ['idx' => $index, 'item' => $ca];
            }
        }
    }
    return null;
}

function certm_import_chain(array $chain): ?string
{
    $issuerRef = null;
    foreach (array_reverse($chain) as $pem) {
        $fingerprint = certm_fingerprint($pem);
        $existing = certm_find_ca_by_fingerprint($fingerprint);
        $parsed = openssl_x509_parse($pem, false) ?: [];
        $ca = $existing['item'] ?? [
            'refid' => uniqid(),
            'descr' => 'CertM CA '.($parsed['subject']['CN'] ?? substr($fingerprint, 0, 12)),
            'serial' => 0,
        ];
        $ca['crt'] = base64_encode($pem);
        if ($issuerRef !== null) {
            $ca['caref'] = $issuerRef;
        } else {
            unset($ca['caref']);
        }
        if ($existing !== null) {
            config_set_path('ca/'.$existing['idx'], $ca);
        } else {
            config_set_path('ca/', $ca);
        }
        $issuerRef = (string) $ca['refid'];
    }
    return $issuerRef;
}

function certm_install_package(string $refid, array $package): void
{
    $lookup = lookup_cert($refid);
    $cert = $lookup['item'] ?? null;
    if (!is_array($cert) || $lookup['idx'] === null) {
        certm_fail("pfSense certificate {$refid} no longer exists.");
    }
    $caref = certm_import_chain($package['chain']);
    $cert['crt'] = base64_encode($package['leaf']);
    $cert['prv'] = base64_encode($package['key']);
    if ($caref !== null) {
        $cert['caref'] = $caref;
    } else {
        unset($cert['caref']);
    }
    config_set_path('cert/'.$lookup['idx'], $cert);
}

function certm_create_certificate(array $package, array $domains): string
{
    $caref = certm_import_chain($package['chain']);
    $refid = uniqid();
    $cert = [
        'refid' => $refid,
        'descr' => substr('CertM '.implode(', ', $domains), 0, 255),
        'crt' => base64_encode($package['leaf']),
        'prv' => base64_encode($package['key']),
    ];
    if ($caref !== null) {
        $cert['caref'] = $caref;
    }
    config_set_path('cert/', $cert);
    return $refid;
}

function certm_attach_certificate(array $bindings, string $refid): array
{
    $paths = [];
    $attached = [];
    foreach ($bindings as $binding) {
        $frontendIndex = (int) $binding['_frontend_index'];
        if (!isset($attached[$frontendIndex])) {
            $path = 'installedpackages/haproxy/ha_backends/item/'.$frontendIndex;
            $frontend = config_get_path($path);
            if (!is_array($frontend)) {
                certm_fail('HAProxy frontend disappeared while attaching a new certificate.');
            }
            $items = $frontend['ha_certificates']['item'] ?? [];
            if (!is_array($items)) {
                $items = [];
            }
            $exists = false;
            foreach ($items as $item) {
                if (($item['ssl_certificate'] ?? '') === $refid) {
                    $exists = true;
                    break;
                }
            }
            if (!$exists) {
                $items[] = ['ssl_certificate' => $refid];
                $frontend['ha_certificates']['item'] = $items;
                config_set_path($path, $frontend);
            }
            $attached[$frontendIndex] = true;
        }
        $paths[] = '/var/etc/haproxy/'.
            $binding['_primary_frontend_name'].'/'.
            $binding['_frontend_name'].'_'.$refid.'.pem';
    }
    return array_values(array_unique($paths));
}

function certm_verify_installed(string $refid, string $expected): void
{
    $lookup = lookup_cert($refid);
    $pem = base64_decode((string) ($lookup['item']['crt'] ?? ''), true);
    if (!is_string($pem) || !hash_equals($expected, certm_fingerprint($pem))) {
        certm_fail("Installed pfSense certificate {$refid} has the wrong fingerprint.");
    }
}

function certm_verify_haproxy_pem(string $path, string $expected): void
{
    if (!is_file($path)) {
        certm_fail("HAProxy did not generate the expected certificate file: {$path}");
    }
    $contents = file_get_contents($path);
    if (!is_string($contents) || openssl_x509_read($contents) === false) {
        certm_fail("HAProxy generated an invalid certificate file: {$path}");
    }
    if (!hash_equals($expected, certm_fingerprint($contents))) {
        certm_fail("HAProxy generated certificate {$path} has the wrong fingerprint.");
    }
}

function certm_report(
    array $config,
    string $token,
    int $deploymentId,
    string $status,
    ?string $fingerprint,
    string $message
): void {
    $body = [
        'deployment_id' => $deploymentId,
        'status' => $status,
        'message' => $message,
    ];
    if ($status === 'SUCCESS' && $fingerprint !== null) {
        $body['installed_fingerprint'] = $fingerprint;
        $body['served_fingerprint'] = $fingerprint;
    }
    certm_api($config, 'POST', 'deployment/report', $token, null, $body);
}

function certm_preflight(bool $online = true): array
{
    certm_load_pfsense();
    $config = certm_load_config();
    if (!function_exists('haproxy_check_run')) {
        certm_fail('The pfSense HAProxy package API is unavailable.');
    }
    if (!function_exists('install_cron_job')) {
        certm_fail('The pfSense cron configuration API is unavailable.');
    }
    $bindings = certm_discover_bindings();
    certm_log('PREFLIGHT OK: pfSense HAProxy package and configuration API are available.');
    certm_log('PREFLIGHT OK: '.count($bindings).' active HTTPS binding(s) discovered.');
    if ($online) {
        $token = trim((string) ($config['client_token'] ?? $config['enrollment_token'] ?? ''));
        if ($token === '') {
            certm_fail('No enrollment or client token is configured.');
        }
        $response = certm_api($config, 'GET', 'client/preflight', $token);
        certm_log('PREFLIGHT OK: CertM API status='.(string) ($response['status'] ?? 'unknown'));
    }
    return [$config, $bindings];
}

function certm_enroll(): void
{
    [$config] = certm_preflight(true);
    if (!empty($config['client_token'])) {
        certm_log('This pfSense firewall is already enrolled.');
        return;
    }
    $token = trim((string) ($config['enrollment_token'] ?? ''));
    if ($token === '') {
        certm_fail('The enrollment token is missing.');
    }
    $response = certm_api($config, 'POST', 'client/enroll', $token, null, [
        'machine_id' => certm_machine_id(),
        'hostname' => gethostname() ?: 'pfsense',
        'display_name' => trim((string) ($config['display_name'] ?? '')),
        'agent_type' => CERTM_PFSENSE_AGENT_TYPE,
        'agent_version' => CERTM_PFSENSE_AGENT_VERSION,
        'os_name' => 'pfSense',
        'os_version' => certm_pfsense_version(),
    ]);
    $clientToken = trim((string) ($response['client_token'] ?? ''));
    if ($clientToken === '') {
        certm_fail('CertM enrollment did not return a client token.');
    }
    $config['client_token'] = $clientToken;
    unset($config['enrollment_token']);
    certm_save_config($config);
    certm_log('Enrolled as client '.(string) ($response['client_id'] ?? '?').'; waiting for administrator approval.');
}

function certm_inventory(): void
{
    certm_load_pfsense();
    $config = certm_load_config();
    [$token] = certm_identity($config);
    certm_push_inventory($config, $token, certm_discover_bindings());
}

function certm_renew(bool $dryRun = false): void
{
    certm_load_pfsense();
    $config = certm_load_config();
    [$token] = certm_identity($config);
    $bindings = certm_discover_bindings();
    certm_push_inventory($config, $token, $bindings);

    $groups = [];
    foreach ($bindings as $binding) {
        $groups[$binding['_group_key']][] = $binding;
    }
    $deployments = [];
    $pendingTargets = [];
    foreach ($groups as $groupKey => $group) {
        $refid = $group[0]['_cert_ref'];
        $desired = [];
        foreach ($group as $binding) {
            $value = certm_desired($config, $token, $binding);
            if ($value !== null) {
                $desired[certm_desired_key($value)] = $value;
            }
        }
        if ($desired === []) {
            if ($refid === null) {
                certm_log(
                    'No CertM assignment for new HAProxy domain '.
                    $group[0]['domain'].'; keeping it unmanaged.'
                );
            } else {
                certm_log("No CertM assignment for pfSense certificate {$refid}; keeping it unchanged.");
            }
            continue;
        }
        if (count($desired) !== 1) {
            certm_fail(
                $refid === null
                    ? 'New HAProxy domain '.$group[0]['domain'].' resolves to multiple CertM assignments.'
                    : "pfSense certificate {$refid} resolves to multiple CertM assignments."
            );
        }
        $target = array_values($desired)[0];
        if ($refid === null) {
            $targetKey = certm_desired_key($target);
            if (!isset($pendingTargets[$targetKey])) {
                $pendingTargets[$targetKey] = [
                    'target' => $target,
                    'bindings' => [],
                ];
            }
            $pendingTargets[$targetKey]['bindings'] = array_merge(
                $pendingTargets[$targetKey]['bindings'],
                $group
            );
            continue;
        }
        $expected = strtolower((string) $target['fingerprint_sha256']);
        if (hash_equals($expected, (string) $group[0]['fingerprint_sha256'])) {
            certm_log("pfSense certificate {$refid} is already current.");
            continue;
        }
        $domains = array_values(array_unique(array_column($group, 'domain')));
        if ($dryRun) {
            certm_log(
                'DRY RUN would deploy '.(string) $target['deployment_revision'].
                " to pfSense certificate {$refid} for ".implode(', ', $domains)
            );
            continue;
        }
        $download = certm_api($config, 'GET', 'cert/download', $token, [
            'domain' => $group[0]['domain'],
            'service' => CERTM_PFSENSE_SERVICE,
            'port' => (int) $group[0]['port'],
        ]);
        $deployments[] = [
            'refid' => $refid,
            'create' => false,
            'bindings' => $group,
            'domains' => $domains,
            'pem_paths' => array_values(array_unique(array_column($group, '_pem_path'))),
            'package' => certm_decode_package($download, $target, $domains),
        ];
    }

    foreach ($pendingTargets as $pending) {
        $target = $pending['target'];
        $pendingBindings = $pending['bindings'];
        $domains = array_values(array_unique(array_column($pendingBindings, 'domain')));
        $frontends = array_values(array_unique(array_column($pendingBindings, '_frontend_name')));
        if ($dryRun) {
            certm_log(
                'DRY RUN would create and attach '.(string) $target['deployment_revision'].
                ' for '.implode(', ', $domains).' on HAProxy frontend(s) '.implode(', ', $frontends)
            );
            continue;
        }
        $download = certm_api($config, 'GET', 'cert/download', $token, [
            'domain' => $domains[0],
            'service' => CERTM_PFSENSE_SERVICE,
            'port' => (int) $pendingBindings[0]['port'],
        ]);
        $deployments[] = [
            'refid' => null,
            'create' => true,
            'bindings' => $pendingBindings,
            'domains' => $domains,
            'pem_paths' => [],
            'package' => certm_decode_package($download, $target, $domains),
        ];
    }

    if ($dryRun || $deployments === []) {
        certm_log('Renew completed; no pfSense HAProxy certificate change was required.');
        return;
    }

    $oldCerts = config_get_path('cert', []);
    $oldCas = config_get_path('ca', []);
    $oldFrontends = config_get_path('installedpackages/haproxy/ha_backends/item', []);
    try {
        foreach ($deployments as &$deployment) {
            if ($deployment['create']) {
                $deployment['refid'] = certm_create_certificate(
                    $deployment['package'],
                    $deployment['domains']
                );
                $deployment['pem_paths'] = certm_attach_certificate(
                    $deployment['bindings'],
                    $deployment['refid']
                );
            } else {
                certm_install_package($deployment['refid'], $deployment['package']);
            }
        }
        unset($deployment);
        write_config('CertM updated pfSense HAProxy certificate material');
        $result = haproxy_check_run(1);
        if ((int) $result !== 0) {
            certm_fail('pfSense HAProxy rejected the regenerated configuration.');
        }
        foreach ($deployments as $deployment) {
            $package = $deployment['package'];
            certm_verify_installed($deployment['refid'], $package['expected']);
            foreach ($deployment['pem_paths'] as $pemPath) {
                certm_verify_haproxy_pem($pemPath, $package['expected']);
            }
            certm_report(
                $config,
                $token,
                $package['deployment_id'],
                'SUCCESS',
                $package['expected'],
                'Certificate imported into pfSense Certificate Manager and HAProxy reloaded successfully.'
            );
            certm_log(
                'CERTIFICATE UPDATE SUCCESSFUL: '.$deployment['refid'].' for '.
                implode(', ', $deployment['domains'])
            );
        }
    } catch (Throwable $exception) {
        config_set_path('cert', $oldCerts);
        config_set_path('ca', $oldCas);
        config_set_path('installedpackages/haproxy/ha_backends/item', $oldFrontends);
        write_config('CertM rolled back pfSense HAProxy certificate material');
        $rollback = (int) haproxy_check_run(1) === 0
            ? 'Rollback completed successfully.'
            : 'Rollback reload failed; inspect the pfSense HAProxy log immediately.';
        foreach ($deployments as $deployment) {
            try {
                certm_report(
                    $config,
                    $token,
                    $deployment['package']['deployment_id'],
                    'FAILED',
                    null,
                    $exception->getMessage().' '.$rollback
                );
            } catch (Throwable $reportException) {
                certm_log('Unable to report failed deployment: '.$reportException->getMessage(), 'WARN');
            }
        }
        certm_fail($exception->getMessage().' '.$rollback);
    }
    certm_push_inventory($config, $token, certm_discover_bindings());
}

function certm_install_cron(bool $active): void
{
    certm_load_pfsense();
    $legacyPhpCommand = '/usr/local/bin/php -f /conf/certm/CertM.HAProxy.Agent.php run';
    $legacyWrapperCommand = '/conf/certm/certm-haproxy run';
    $command = '/bin/sh /conf/certm/certm-haproxy run';
    install_cron_job($legacyPhpCommand, false, '21', '*/6', '*', '*', '*', 'root', true);
    install_cron_job($legacyWrapperCommand, false, '21', '*/6', '*', '*', '*', 'root', true);
    install_cron_job($command, $active, '21', '*/6', '*', '*', '*', 'root', true);
    certm_log($active ? 'Installed six-hour pfSense cron job.' : 'Removed pfSense cron job.');
}

function certm_status(): void
{
    certm_load_pfsense();
    $localConfig = certm_load_config();
    $enrolled = trim((string) ($localConfig['client_token'] ?? '')) !== '';
    $cronEnabled = false;
    $cronCommands = [
        '/bin/sh /conf/certm/certm-haproxy run',
        '/conf/certm/certm-haproxy run',
        '/usr/local/bin/php -f /conf/certm/CertM.HAProxy.Agent.php run',
    ];

    foreach (config_get_path('cron/item', []) as $item) {
        $command = trim((string) ($item['command'] ?? ''));
        if (in_array($command, $cronCommands, true)) {
            $cronEnabled = true;
            break;
        }
    }

    $bindingStatus = 'unavailable';
    try {
        $bindingStatus = (string) count(certm_discover_bindings());
    } catch (Throwable $exception) {
        $bindingStatus = 'error: '.$exception->getMessage();
    }

    $apiStatus = $enrolled ? 'unreachable' : 'not enrolled';
    if ($enrolled) {
        try {
            $response = certm_api(
                $localConfig,
                'GET',
                'client/status',
                certm_client_token($localConfig)
            );
            $apiStatus = (string) ($response['status'] ?? 'unknown');
        } catch (Throwable $exception) {
            $apiStatus = 'error: '.$exception->getMessage();
        }
    }

    $lastLog = 'none';
    if (is_file(CERTM_PFSENSE_LOG)) {
        $lines = file(CERTM_PFSENSE_LOG, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (is_array($lines) && $lines !== []) {
            $lastLog = (string) end($lines);
        }
    }

    echo 'CertM pfSense HAProxy Agent'.PHP_EOL;
    echo 'Version: '.CERTM_PFSENSE_AGENT_VERSION.PHP_EOL;
    echo 'Machine ID: '.certm_machine_id().PHP_EOL;
    echo 'Display name: '.trim((string) ($localConfig['display_name'] ?? '')).PHP_EOL;
    echo 'Enrollment: '.($enrolled ? 'configured' : 'missing').PHP_EOL;
    echo 'CertM API status: '.$apiStatus.PHP_EOL;
    echo 'Active HTTPS bindings: '.$bindingStatus.PHP_EOL;
    echo 'Six-hour cron: '.($cronEnabled ? 'enabled (minute 21)' : 'disabled').PHP_EOL;
    echo 'Last log: '.$lastLog.PHP_EOL;
}

function certm_with_lock(callable $operation): void
{
    $handle = fopen(CERTM_PFSENSE_LOCK, 'c');
    if ($handle === false || !flock($handle, LOCK_EX | LOCK_NB)) {
        certm_fail('Another CertM pfSense agent run is already active.');
    }
    try {
        $operation();
    } finally {
        flock($handle, LOCK_UN);
        fclose($handle);
    }
}

function certm_scheduled_run(): void
{
    try {
        certm_run_update(false);
    } catch (Throwable $exception) {
        certm_log(
            'Agent update check failed; certificate work will continue: '.
            $exception->getMessage(),
            'WARN'
        );
    }
    certm_renew(false);
}

function certm_main(array $argv): int
{
    $command = strtolower((string) ($argv[1] ?? 'run'));
    try {
        certm_with_lock(function () use ($command): void {
            match ($command) {
                'preflight' => certm_preflight(true),
                'status' => certm_status(),
                'enroll' => certm_enroll(),
                'inventory' => certm_inventory(),
                'renew' => certm_renew(false),
                'run' => certm_scheduled_run(),
                'update' => certm_run_update(true),
                'dry-run' => certm_renew(true),
                'install-cron' => certm_install_cron(true),
                'remove-cron' => certm_install_cron(false),
                default => certm_fail(
                    'Usage: CertM.HAProxy.Agent.php status|preflight|enroll|inventory|dry-run|renew|run|update|install-cron|remove-cron'
                ),
            };
        });
        return 0;
    } catch (Throwable $exception) {
        certm_log($exception->getMessage(), 'ERROR');
        return 1;
    }
}

if (PHP_SAPI === 'cli' && realpath((string) ($_SERVER['SCRIPT_FILENAME'] ?? '')) === __FILE__) {
    exit(certm_main($argv));
}
