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
    $append = str_ends_with($path, '/');
    $parts = array_values(array_filter(explode('/', trim($path, '/')), 'strlen'));
    $cursor =& $testConfig;
    foreach ($parts as $part) {
        if (!isset($cursor[$part]) || !is_array($cursor[$part])) {
            $cursor[$part] = [];
        }
        $cursor =& $cursor[$part];
    }
    if ($append) {
        $cursor[] = $value;
    } else {
        $cursor = $value;
    }
}

function lookup_cert(string $refid): array
{
    global $testConfig;
    foreach (($testConfig['cert'] ?? []) as $index => $cert) {
        if (($cert['refid'] ?? '') === $refid) {
            return ['idx' => $index, 'item' => $cert];
        }
    }
    return ['idx' => null, 'item' => null];
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
$testConfig = [
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
                ]],
            ],
        ],
    ],
];

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
