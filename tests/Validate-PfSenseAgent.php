<?php

declare(strict_types=1);

$testConfig = [];

function config_get_path(string $path, mixed $default = null): mixed
{
    global $testConfig;
    $value = $testConfig;
    foreach (explode('/', trim($path, '/')) as $part) {
        if ($part === '') {
            continue;
        }
        if (!is_array($value) || !array_key_exists($part, $value)) {
            return $default;
        }
        $value = $value[$part];
    }
    return $value;
}

function config_set_path(string $path, mixed $value): void
{
    global $testConfig;
    $parts = array_values(array_filter(explode('/', $path), 'strlen'));
    $leaf = array_pop($parts);
    if ($leaf === null) {
        return;
    }
    $cursor =& $testConfig;
    foreach ($parts as $part) {
        if (!isset($cursor[$part]) || !is_array($cursor[$part])) {
            $cursor[$part] = [];
        }
        $cursor =& $cursor[$part];
    }
    $cursor[$leaf] = $value;
}

function lookup_cert(string $refid): array
{
    global $testConfig;
    foreach (($testConfig['cert'] ?? []) as $cert) {
        if (($cert['refid'] ?? '') === $refid) {
            return $cert;
        }
    }
    return [];
}

require dirname(__DIR__).'/pfsense/CertM.HAProxy.Agent.php';

function test_certificate(string $commonName): array
{
    $keyPath = tempnam(sys_get_temp_dir(), 'certm-key-');
    $certificatePath = tempnam(sys_get_temp_dir(), 'certm-crt-');
    if ($keyPath === false || $certificatePath === false) {
        throw new RuntimeException('Unable to create temporary certificate paths.');
    }
    try {
        $command = sprintf(
            'openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj %s -keyout %s -out %s 2>/dev/null',
            escapeshellarg('/CN='.$commonName),
            escapeshellarg($keyPath),
            escapeshellarg($certificatePath)
        );
        exec($command, $output, $status);
        $certificatePem = file_get_contents($certificatePath);
        $privateKeyPem = file_get_contents($keyPath);
        if ($status !== 0 || !is_string($certificatePem) || !is_string($privateKeyPem)) {
            throw new RuntimeException('Unable to create test certificate.');
        }
        return [$certificatePem, $privateKeyPem];
    } finally {
        @unlink($keyPath);
        @unlink($certificatePath);
    }
}

[$certificatePem, $privateKeyPem] = test_certificate('*.pmr.vn');
$certificateDomains = certm_certificate_domains($certificatePem);
if (!in_array('*.pmr.vn', $certificateDomains, true)) {
    throw new RuntimeException('Test certificate domains: '.json_encode($certificateDomains));
}
if (!preg_match(
    '/-----BEGIN CERTIFICATE-----\\s*([A-Za-z0-9+\\/=\\s]+?)\\s*-----END CERTIFICATE-----/s',
    $certificatePem,
    $certificateMatch
)) {
    throw new RuntimeException('Unable to extract DER certificate test data.');
}
$certificateDer = base64_decode(
    preg_replace('/\\s+/', '', $certificateMatch[1]),
    true
);
$expectedFingerprint = hash('sha256', $certificateDer);
if (certm_fingerprint($certificatePem) !== $expectedFingerprint) {
    throw new RuntimeException('Portable certificate fingerprint does not match DER SHA-256.');
}
$certificateFile = tempnam(sys_get_temp_dir(), 'certm-fingerprint-');
if (
    $certificateFile === false ||
    file_put_contents($certificateFile, $certificatePem) === false
) {
    throw new RuntimeException('Unable to create certificate normalization test file.');
}
try {
    if (certm_fingerprint('file://'.$certificateFile) !== $expectedFingerprint) {
        throw new RuntimeException('Portable certificate fingerprint cannot normalize OpenSSL certificate data.');
    }
} finally {
    @unlink($certificateFile);
}
if (certm_fingerprint($privateKeyPem."\n".$certificatePem) !== $expectedFingerprint) {
    throw new RuntimeException('Portable certificate fingerprint cannot locate PEM certificate data.');
}
$haproxyPemFile = tempnam(sys_get_temp_dir(), 'certm-haproxy-');
if (
    $haproxyPemFile === false ||
    file_put_contents(
        $haproxyPemFile,
        $privateKeyPem."\n".$certificatePem
    ) === false
) {
    throw new RuntimeException('Unable to create combined HAProxy PEM test file.');
}
try {
    if (certm_fingerprint_file($haproxyPemFile) !== $expectedFingerprint) {
        throw new RuntimeException('HAProxy PEM file fingerprint does not match DER SHA-256.');
    }
} finally {
    @unlink($haproxyPemFile);
}
try {
    certm_fingerprint('not a certificate');
    throw new RuntimeException('Malformed certificate unexpectedly produced a fingerprint.');
} catch (RuntimeException $exception) {
    if (!str_contains($exception->getMessage(), 'Unable to normalize certificate data using PHP or the OpenSSL command')) {
        throw $exception;
    }
}
$testConfig = [
    'ca' => [[
        'refid' => 'existing-ca',
        'descr' => 'Existing CA',
        'crt' => base64_encode($certificatePem),
    ]],
    'cert' => [[
        'refid' => 'existing-ref',
        'descr' => 'Existing wildcard',
        'crt' => base64_encode($certificatePem),
        'prv' => base64_encode($privateKeyPem),
    ]],
    'installedpackages' => [
        'haproxy' => [
            'ha_backends' => [
                'item' => [[
                    'name' => '443',
                    'status' => 'active',
                    'a_extaddr' => ['item' => [[
                        'extaddr_ssl' => 'yes',
                        'extaddr_port' => '443',
                    ]]],
                    'ha_acls' => ['item' => [
                        ['expression' => 'host_matches', 'value' => 'app.pmr.vn'],
                        ['expression' => 'host_matches', 'value' => 'be.abp.pmr.vn'],
                    ]],
                    'ha_certificates' => ['item' => [[
                        'ssl_certificate' => 'existing-ref',
                    ]]],
                ], [
                    'name' => '80',
                    'status' => 'active',
                    'a_extaddr' => ['item' => [[
                        'extaddr_ssl' => 'no',
                        'extaddr_port' => '80',
                    ]]],
                    'ha_acls' => ['item' => [[
                        'expression' => 'host_matches',
                        'value' => 'http-only.pmr.vn',
                    ]]],
                    'ssloffloadcert' => 'existing-ref',
                ]],
            ],
        ],
    ],
];

certm_append_config_item('ca', [
    'refid' => 'new-ca',
    'descr' => 'New CA',
    'crt' => base64_encode($certificatePem),
]);
$cas = config_get_path('ca');
if (count($cas) !== 2 || $cas[0]['refid'] !== 'existing-ca' || $cas[1]['refid'] !== 'new-ca') {
    throw new RuntimeException('pfSense 2.7.2-compatible CA append did not preserve the collection.');
}

$newCertificateRef = certm_create_certificate([
    'leaf' => $certificatePem,
    'key' => $privateKeyPem,
    'chain' => [],
], ['new.pmr.vn']);
$certificates = config_get_path('cert');
if (count($certificates) !== 2 || $certificates[0]['refid'] !== 'existing-ref' || $certificates[1]['refid'] !== $newCertificateRef) {
    throw new RuntimeException('pfSense 2.7.2-compatible certificate append did not preserve the collection.');
}
$newCertificateLookup = certm_lookup_certificate($newCertificateRef);
if (
    $newCertificateLookup['idx'] !== 1 ||
    ($newCertificateLookup['item']['refid'] ?? null) !== $newCertificateRef
) {
    throw new RuntimeException('Internal certificate lookup did not normalize pfSense 2.7.2 configuration.');
}

$httpFrontend = config_get_path('installedpackages/haproxy/ha_backends/item/1');
if (certm_frontend_ports($httpFrontend) !== []) {
    throw new RuntimeException('HTTP-only HAProxy frontend was treated as HTTPS.');
}

$bindings = certm_discover_bindings();
if (count($bindings) !== 2) {
    throw new RuntimeException('Expected one covered and one pending binding.');
}
$pending = array_values(array_filter(
    $bindings,
    fn (array $binding): bool => $binding['_cert_ref'] === null
));
if (count($pending) !== 1 || $pending[0]['domain'] !== 'be.abp.pmr.vn') {
    throw new RuntimeException('Pending bindings: '.json_encode($bindings));
}
if ($pending[0]['fingerprint_sha256'] !== null || $pending[0]['_group_key'] !== 'pending:be.abp.pmr.vn') {
    throw new RuntimeException('Pending binding metadata is unsafe or unstable.');
}

$paths = certm_attach_certificate($pending, 'new-ref');
$frontend = config_get_path('installedpackages/haproxy/ha_backends/item/0');
$refs = array_column($frontend['ha_certificates']['item'], 'ssl_certificate');
if ($refs !== ['existing-ref', 'new-ref']) {
    throw new RuntimeException('New certificate was not attached as an additional certificate.');
}
if (($frontend['ssloffloadcert'] ?? null) !== null) {
    throw new RuntimeException('Onboarding unexpectedly replaced the primary certificate.');
}
if ($paths !== ['/var/etc/haproxy/443/443_new-ref.pem']) {
    throw new RuntimeException('Unexpected generated HAProxy PEM path.');
}

echo "pfSense onboarding contract OK\n";
