<?php
declare(strict_types=1);

const WHOIS_TIMEOUT = 10;

function normalize_query(string $input): ?string
{
    $q = strtolower(trim($input));
    $q = preg_replace('#^[a-z][a-z0-9+.-]*://#', '', $q);   // strip scheme
    $q = preg_replace('#[/?\#].*$#', '', $q);                // strip path/query
    $q = preg_replace('#^[^@]*@#', '', $q);                  // strip user@
    $q = preg_replace('#:\d+$#', '', $q);                    // strip port
    $q = rtrim($q, '.');

    if ($q === '') {
        return null;
    }
    if (filter_var($q, FILTER_VALIDATE_IP)) {
        return $q;
    }
    if (function_exists('idn_to_ascii')) {
        $ascii = idn_to_ascii($q, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
        if ($ascii !== false) {
            $q = $ascii;
        }
    }
    // Basic domain syntax check (also protects against injection into the raw socket)
    if (preg_match('/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/', $q)) {
        return $q;
    }
    return null;
}

function whois_query(string $server, string $query): string
{
    $errno = 0;
    $errstr = '';
    $fp = @fsockopen($server, 43, $errno, $errstr, WHOIS_TIMEOUT);
    if (!$fp) {
        throw new RuntimeException("Cannot connect to $server: $errstr ($errno)");
    }
    stream_set_timeout($fp, WHOIS_TIMEOUT);
    fwrite($fp, $query . "\r\n");

    $response = '';
    while (!feof($fp)) {
        $chunk = fread($fp, 8192);
        if ($chunk === false || $chunk === '') {
            break;
        }
        $response .= $chunk;
        if (strlen($response) > 1_000_000) { // safety cap
            break;
        }
    }
    fclose($fp);
    return $response;
}

function find_referral(string $text): ?string
{
    // IANA: "refer: whois.x" / "whois: whois.x"; registries: "Registrar WHOIS Server: whois.x"
    if (preg_match('/^\s*(?:refer|whois|registrar whois server)\s*:\s*(?:r?whois:\/\/)?([a-z0-9.-]+)/im', $text, $m)) {
        $host = strtolower($m[1]);
        if (preg_match('/^[a-z0-9.-]+\.[a-z]{2,}$/', $host)) {
            return $host;
        }
    }
    return null;
}

function do_whois(string $query): array
{
    $steps = [];
    $server = 'whois.iana.org';
    $seen = [];

    for ($i = 0; $i < 3; $i++) {
        $seen[] = $server;
        $result = whois_query($server, $query);
        $steps[] = ['server' => $server, 'result' => $result];

        $next = find_referral($result);
        if ($next === null || in_array($next, $seen, true)) {
            break;
        }
        $server = $next;
    }
    return $steps;
}

/**
 * Pull a few key fields out of the raw responses (most specific server first).
 * Returns [label => [values...]].
 */
function extract_summary(array $steps): array
{
    $fields = [
        'Registrar'     => ['registrar', 'sponsoring registrar'],
        'Created'       => ['creation date', 'created', 'registered', 'registration time'],
        'Updated'       => ['updated date', 'last updated', 'last-modified', 'changed'],
        'Expires'       => ['registry expiry date', 'registrar registration expiration date', 'expiration date', 'expires', 'paid-till', 'expiry date'],
        'Status'        => ['domain status', 'status'],
        'Name servers'  => ['name server', 'nserver', 'nameserver'],
        'Network'       => ['netname'],
        'Organization'  => ['orgname', 'organization', 'org-name', 'org'],
        'Range'         => ['cidr', 'inetnum', 'netrange'],
        'Country'       => ['country'],
    ];

    $summary = [];
    foreach (array_reverse($steps) as $step) {
        $found = [];
        foreach (preg_split('/\r?\n/', $step['result']) as $line) {
            if (!preg_match('/^\s*([^:]{2,40}):\s*(.+?)\s*$/', $line, $m)) {
                continue;
            }
            $key = strtolower(trim($m[1]));
            foreach ($fields as $label => $keys) {
                if (in_array($key, $keys, true)) {
                    $val = $m[2];
                    if ($label === 'Status') {
                        $val = trim(explode(' ', $val)[0]); // drop the ICANN URL suffix
                    }
                    if ($label === 'Name servers') {
                        $val = strtolower($val);
                    }
                    $found[$label][] = $val;
                }
            }
        }
        foreach ($found as $label => $vals) {
            if (!isset($summary[$label])) {
                $summary[$label] = array_values(array_unique($vals));
            }
        }
    }

    // keep a stable, readable order
    $ordered = [];
    foreach (array_keys($fields) as $label) {
        if (isset($summary[$label])) {
            $ordered[$label] = $summary[$label];
        }
    }
    return $ordered;
}

$input = $_POST['query'] ?? '';
$steps = [];
$summary = [];
$searched = null;
$error = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $query = normalize_query((string)$input);
    if ($query === null) {
        $error = 'Please enter a valid domain name or IP address.';
    } else {
        $searched = $query;
        try {
            $steps = do_whois($query);
            $summary = extract_summary($steps);
        } catch (Throwable $e) {
            $error = $e->getMessage();
        }
    }
}

function h(string $s): string
{
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
?>
<!doctype html>
<html lang="en" class="scroll-smooth">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>WHOIS Lookup</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>tailwind.config = { darkMode: 'media' };</script>
</head>
<body class="min-h-screen bg-gradient-to-b from-indigo-50 via-slate-50 to-slate-100 text-slate-800 antialiased dark:from-slate-950 dark:via-slate-900 dark:to-slate-900 dark:text-slate-100">

<main class="mx-auto max-w-3xl px-4 py-10 sm:py-16">

    <!-- Header -->
    <header class="mb-8 text-center">
        <div class="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-indigo-600 text-white shadow-lg shadow-indigo-600/30">
            <svg class="h-7 w-7" fill="none" stroke="currentColor" stroke-width="1.8" viewBox="0 0 24 24" aria-hidden="true">
                <circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.7 3.8 5.7 3.8 9s-1.3 6.3-3.8 9c-2.5-2.7-3.8-5.7-3.8-9S9.5 5.7 12 3z"/>
            </svg>
        </div>
        <h1 class="text-3xl font-bold tracking-tight sm:text-4xl">WHOIS Lookup</h1>
        <p class="mt-2 text-slate-500 dark:text-slate-400">Find out who owns a domain or IP address.</p>
    </header>

    <!-- Search form -->
    <form id="whois-form" method="post" class="rounded-2xl bg-white p-3 shadow-xl shadow-slate-900/5 ring-1 ring-slate-200 dark:bg-slate-800 dark:ring-slate-700">
        <div class="flex flex-col gap-2 sm:flex-row">
            <div class="relative flex-1">
                <svg class="pointer-events-none absolute left-3.5 top-1/2 h-5 w-5 -translate-y-1/2 text-slate-400" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" aria-hidden="true">
                    <circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/>
                </svg>
                <input id="query" type="text" name="query" required autofocus autocomplete="off" spellcheck="false"
                       placeholder="example.com or 8.8.8.8"
                       value="<?= h((string)$input) ?>"
                       class="w-full rounded-xl border-0 bg-slate-50 py-3 pl-11 pr-3 text-base text-slate-900 placeholder-slate-400 ring-1 ring-inset ring-slate-200 focus:bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500 dark:bg-slate-900 dark:text-slate-100 dark:ring-slate-700 dark:focus:ring-indigo-400">
            </div>
            <button id="submit-btn" type="submit"
                    class="inline-flex items-center justify-center gap-2 rounded-xl bg-indigo-600 px-6 py-3 font-semibold text-white shadow-sm transition hover:bg-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-70 dark:focus:ring-offset-slate-800">
                <svg id="spinner" class="hidden h-5 w-5 animate-spin" fill="none" viewBox="0 0 24 24" aria-hidden="true">
                    <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"/>
                    <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 0 1 8-8v4a4 4 0 0 0-4 4H4z"/>
                </svg>
                <span id="btn-label">Lookup</span>
            </button>
        </div>
        <div class="mt-3 flex flex-wrap items-center gap-2 px-1 text-sm text-slate-500 dark:text-slate-400">
            <span>Try:</span>
            <?php foreach (['example.com', 'wikipedia.org', 'github.com', '8.8.8.8'] as $ex): ?>
                <button type="button" data-example="<?= h($ex) ?>"
                        class="rounded-full bg-slate-100 px-3 py-1 text-slate-600 transition hover:bg-indigo-100 hover:text-indigo-700 dark:bg-slate-700 dark:text-slate-300 dark:hover:bg-indigo-500/20 dark:hover:text-indigo-300">
                    <?= h($ex) ?>
                </button>
            <?php endforeach; ?>
        </div>
    </form>

    <!-- Error -->
    <?php if ($error): ?>
        <div role="alert" class="mt-6 flex items-start gap-3 rounded-xl border border-red-200 bg-red-50 p-4 text-red-800 dark:border-red-900/60 dark:bg-red-950/40 dark:text-red-200">
            <svg class="mt-0.5 h-5 w-5 shrink-0" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" aria-hidden="true">
                <circle cx="12" cy="12" r="9"/><path d="M12 8v5m0 3h.01"/>
            </svg>
            <p class="text-sm"><?= h($error) ?></p>
        </div>
    <?php endif; ?>

    <!-- Results -->
    <?php if ($steps): ?>
        <section class="mt-8 space-y-6">

            <?php if ($summary): ?>
                <div class="overflow-hidden rounded-2xl bg-white shadow-lg shadow-slate-900/5 ring-1 ring-slate-200 dark:bg-slate-800 dark:ring-slate-700">
                    <div class="border-b border-slate-100 px-5 py-4 dark:border-slate-700">
                        <p class="text-xs font-medium uppercase tracking-wider text-slate-400">Summary</p>
                        <h2 class="break-all text-xl font-semibold"><?= h((string)$searched) ?></h2>
                    </div>
                    <dl class="divide-y divide-slate-100 dark:divide-slate-700">
                        <?php foreach ($summary as $label => $values): ?>
                            <div class="grid gap-1 px-5 py-3 sm:grid-cols-3 sm:gap-4">
                                <dt class="text-sm font-medium text-slate-500 dark:text-slate-400"><?= h($label) ?></dt>
                                <dd class="text-sm sm:col-span-2">
                                    <?php if (in_array($label, ['Status', 'Name servers'], true)): ?>
                                        <div class="flex flex-wrap gap-1.5">
                                            <?php foreach ($values as $v): ?>
                                                <span class="rounded-md bg-indigo-50 px-2 py-0.5 font-mono text-xs text-indigo-700 dark:bg-indigo-500/15 dark:text-indigo-300"><?= h($v) ?></span>
                                            <?php endforeach; ?>
                                        </div>
                                    <?php else: ?>
                                        <?= h(implode(', ', $values)) ?>
                                    <?php endif; ?>
                                </dd>
                            </div>
                        <?php endforeach; ?>
                    </dl>
                </div>
            <?php endif; ?>

            <div>
                <h3 class="mb-3 px-1 text-sm font-semibold uppercase tracking-wider text-slate-400">Raw responses</h3>
                <div class="space-y-3">
                    <?php $last = count($steps) - 1; ?>
                    <?php foreach ($steps as $i => $step): ?>
                        <details <?= ($i === $last || !$summary) ? 'open' : '' ?> class="group overflow-hidden rounded-xl bg-white shadow-sm ring-1 ring-slate-200 dark:bg-slate-800 dark:ring-slate-700">
                            <summary class="flex cursor-pointer list-none items-center justify-between gap-3 px-4 py-3 text-sm font-medium hover:bg-slate-50 dark:hover:bg-slate-700/50">
                                <span class="flex items-center gap-2">
                                    <svg class="h-4 w-4 text-slate-400 transition group-open:rotate-90" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" aria-hidden="true"><path d="m9 6 6 6-6 6"/></svg>
                                    <span class="font-mono"><?= h($step['server']) ?></span>
                                </span>
                                <button type="button" data-copy
                                        class="rounded-lg bg-slate-100 px-2.5 py-1 text-xs font-medium text-slate-600 transition hover:bg-slate-200 dark:bg-slate-700 dark:text-slate-300 dark:hover:bg-slate-600">
                                    Copy
                                </button>
                            </summary>
                            <pre class="max-h-96 overflow-auto whitespace-pre-wrap break-words border-t border-slate-100 bg-slate-50 p-4 font-mono text-xs leading-relaxed text-slate-700 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300"><?= h($step['result']) ?></pre>
                        </details>
                    <?php endforeach; ?>
                </div>
            </div>
        </section>
    <?php endif; ?>

    <footer class="mt-12 text-center text-xs text-slate-400">
        Queries go to whois.iana.org and follow referrals to the registry and registrar.
    </footer>
</main>

<script>
    const form = document.getElementById('whois-form');
    const input = document.getElementById('query');
    const btn = document.getElementById('submit-btn');

    // Example chips
    document.querySelectorAll('[data-example]').forEach(chip => {
        chip.addEventListener('click', () => {
            input.value = chip.dataset.example;
            form.requestSubmit();
        });
    });

    // Loading state
    form.addEventListener('submit', () => {
        btn.disabled = true;
        document.getElementById('spinner').classList.remove('hidden');
        document.getElementById('btn-label').textContent = 'Looking up…';
    });

    // Copy buttons (inside <summary>, so don't toggle the <details>)
    document.querySelectorAll('[data-copy]').forEach(b => {
        b.addEventListener('click', async e => {
            e.preventDefault();
            e.stopPropagation();
            const text = b.closest('details').querySelector('pre').textContent;
            try {
                await navigator.clipboard.writeText(text);
                b.textContent = 'Copied!';
            } catch {
                b.textContent = 'Failed';
            }
            setTimeout(() => (b.textContent = 'Copy'), 1500);
        });
    });
</script>
</body>
</html>
