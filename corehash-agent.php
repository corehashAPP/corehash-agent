<?php
/**
 * Plugin Name: Corehash Agent
 * Plugin URI:  https://corehash.app
 * Description: Connects this site to Corehash. Exposes one secured REST endpoint with an inventory of versions, plugins and file hashes.
 * Version:     0.4.0
 * Author:      Corehash
 * Author URI:  https://corehash.app
 * License:     GPL-2.0-or-later
 * Text Domain: corehash-agent
 */

if (!defined('ABSPATH')) exit;

final class Corehash_Agent
{
    const VERSION      = '0.4.0';
    const OPTION_TOKEN = 'corehash_token';
    const OPTION_SEEN  = 'corehash_last_contact';
    const TRANSIENT    = 'corehash_inventory';
    const CACHE_TTL    = 50 * MINUTE_IN_SECONDS;
    const NAMESPACE    = 'corehash/v1';
    const UPDATE_URL   = 'https://corehash.app/agent/update.json';
    const ALLOWED_IPS  = ['35.214.231.225']; // Corehash-server. Uitbreiden met een filter: corehash_allowed_ips

    public static function init(): void
    {
        register_activation_hook(__FILE__, [__CLASS__, 'activate']);
        add_action('rest_api_init', [__CLASS__, 'routes']);
        add_action('admin_menu', [__CLASS__, 'menu']);
        add_action('admin_post_corehash_regenerate', [__CLASS__, 'regenerate']);
        add_action('upgrader_process_complete', [__CLASS__, 'flush']);
        add_action('activated_plugin', [__CLASS__, 'flush']);
        add_action('deactivated_plugin', [__CLASS__, 'flush']);
        add_action('switch_theme', [__CLASS__, 'flush']);

        // self-hosted updates + "View details"
        add_filter('pre_set_site_transient_update_plugins', [__CLASS__, 'check_update']);
        add_filter('plugins_api', [__CLASS__, 'plugin_info'], 20, 3);
        add_filter('auto_update_plugin', [__CLASS__, 'auto_update'], 10, 2);
        add_action('upgrader_process_complete', [__CLASS__, 'flush_update_cache'], 10, 2);
    }

    /* ---------- updates ---------- */

    private static function remote_info(): ?object
    {
        // "Check again" op de Updates-pagina forceert ook onze cache
        if (!empty($_GET['force-check'])) delete_site_transient('corehash_agent_update');

        $cached = get_site_transient('corehash_agent_update');

        if (is_object($cached)) return $cached;

        $res = wp_remote_get(self::UPDATE_URL, ['timeout' => 10, 'headers' => ['Accept' => 'application/json']]);

        if (is_wp_error($res) || wp_remote_retrieve_response_code($res) !== 200) return null;

        $info = json_decode(wp_remote_retrieve_body($res));

        if (!is_object($info) || empty($info->version)) return null;

        set_site_transient('corehash_agent_update', $info, HOUR_IN_SECONDS);

        return $info;
    }

    public static function check_update($transient)
    {
        if (empty($transient->checked)) return $transient;

        $info = self::remote_info();
        $file = plugin_basename(__FILE__);

        if (!$info) return $transient;

        $item = (object) [
            'id'            => 'corehash.app/agent',
            'slug'          => 'corehash-agent',
            'plugin'        => $file,
            'new_version'   => $info->version,
            'url'           => 'https://corehash.app',
            'package'       => $info->download_url,
            'tested'        => $info->tested ?? '',
            'requires_php'  => $info->requires_php ?? '8.0',
            'icons'         => (array) ($info->icons ?? []),
        ];

        if (version_compare($info->version, self::VERSION, '>')) {
            $transient->response[$file] = $item;
        } else {
            $transient->no_update[$file] = $item;
        }

        return $transient;
    }

    public static function plugin_info($result, $action, $args)
    {
        if ($action !== 'plugin_information' || ($args->slug ?? '') !== 'corehash-agent') return $result;

        $info = self::remote_info();

        if (!$info) return $result;

        return (object) [
            'name'            => 'Corehash Agent',
            'slug'            => 'corehash-agent',
            'version'         => $info->version,
            'author'          => '<a href="https://corehash.app">Corehash</a>',
            'homepage'        => 'https://corehash.app',
            'requires'        => $info->requires ?? '6.0',
            'tested'          => $info->tested ?? '',
            'requires_php'    => $info->requires_php ?? '8.0',
            'last_updated'    => $info->last_updated ?? '',
            'download_link'   => $info->download_url,
            'sections'        => (array) ($info->sections ?? []),
            'banners'         => (array) ($info->banners ?? []),
            'icons'           => (array) ($info->icons ?? []),
        ];
    }

    /** Agent altijd automatisch bijwerken: het is een monitoring-component, geen site-functionaliteit. */
    public static function auto_update($update, $item)
    {
        if (($item->slug ?? '') === 'corehash-agent') return true;

        return $update;
    }

    public static function flush_update_cache($upgrader, $options): void
    {
        if (($options['type'] ?? '') === 'plugin') delete_site_transient('corehash_agent_update');
    }

    /* ---------- token ---------- */

    public static function activate(): void
    {
        if (!get_option(self::OPTION_TOKEN)) {
            update_option(self::OPTION_TOKEN, self::new_token(), false);
        }
    }

    private static function new_token(): string
    {
        return bin2hex(random_bytes(32));
    }

    public static function regenerate(): void
    {
        if (!current_user_can('manage_options')) wp_die('Access denied.');
        check_admin_referer('corehash_regenerate');
        update_option(self::OPTION_TOKEN, self::new_token(), false);
        delete_option(self::OPTION_SEEN);
        self::flush();
        wp_safe_redirect(admin_url('options-general.php?page=corehash&regenerated=1'));
        exit;
    }

    public static function flush(): void
    {
        delete_transient(self::TRANSIENT);
    }

    /* ---------- REST ---------- */

    public static function routes(): void
    {
        register_rest_route(self::NAMESPACE, '/inventory', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'inventory'],
            'permission_callback' => [__CLASS__, 'auth'],
        ]);

        register_rest_route(self::NAMESPACE, '/ping', [
            'methods'             => 'GET',
            'callback'            => fn() => ['ok' => true, 'agent' => self::VERSION],
            'permission_callback' => [__CLASS__, 'auth'],
        ]);
    }

    public static function auth(WP_REST_Request $request): bool
    {
        if (!self::ip_allowed()) return false;

        $given  = (string) $request->get_header('x-corehash-token');
        $stored = (string) get_option(self::OPTION_TOKEN);

        if ($given === '' || $stored === '') return false;

        if (!hash_equals($stored, $given)) return false;

        update_option(self::OPTION_SEEN, time(), false);

        return true;
    }

    private static function ip_allowed(): bool
    {
        $allowed = apply_filters('corehash_allowed_ips', self::ALLOWED_IPS);

        if (empty($allowed)) return true; // allowlist uitgeschakeld

        $ip = $_SERVER['REMOTE_ADDR'] ?? '';

        // achter Cloudflare / proxy: eerste IP uit X-Forwarded-For alleen vertrouwen als
        // de directe verbinding zelf van een bekende proxy komt; anders REMOTE_ADDR.
        return in_array($ip, $allowed, true);
    }

    public static function inventory(WP_REST_Request $request): WP_REST_Response
    {
        $fresh = $request->get_param('fresh') === '1';
        $data  = $fresh ? false : get_transient(self::TRANSIENT);

        if ($data === false) {
            $data = self::collect();
            set_transient(self::TRANSIENT, $data, self::CACHE_TTL);
        }

        return new WP_REST_Response($data, 200);
    }

    /* ---------- collectors ---------- */

    private static function collect(): array
    {
        require_once ABSPATH . 'wp-admin/includes/plugin.php';
        require_once ABSPATH . 'wp-admin/includes/update.php';

        global $wp_version;

        $start = microtime(true);

        return [
            'agent'        => self::VERSION,
            'generated_at' => gmdate('c'),
            'site'         => [
                'url'        => home_url(),
                'name'       => get_bloginfo('name'),
                'multisite'  => is_multisite(),
                'ssl'        => is_ssl(),
                'debug'      => defined('WP_DEBUG') && WP_DEBUG,
                'file_edit'  => !(defined('DISALLOW_FILE_EDIT') && DISALLOW_FILE_EDIT),
                'auto_update_core' => (bool) get_site_option('auto_update_core_major', false),
            ],
            'versions'     => [
                'wordpress' => $wp_version,
                'wordpress_latest' => self::core_latest(),
                'php'       => PHP_VERSION,
                'mysql'     => $GLOBALS['wpdb']->db_version(),
                'server'    => $_SERVER['SERVER_SOFTWARE'] ?? null,
            ],
            'plugins'      => self::plugins(),
            'themes'       => self::themes(),
            'users'        => self::users(),
            'core'         => self::core_integrity(),
            'content'      => self::content_hashes(),
            'suspicious'   => self::suspicious(),
            'took_ms'      => (int) round((microtime(true) - $start) * 1000),
        ];
    }

    private static function core_latest(): ?string
    {
        wp_version_check();

        $u = get_site_transient('update_core');

        foreach ($u->updates ?? [] as $upd) {
            if (($upd->response ?? '') === 'upgrade') return $upd->current;
        }

        return null;
    }

    private static function plugins(): array
    {
        wp_update_plugins();

        $all     = get_plugins();
        $active  = (array) get_option('active_plugins', []);
        $network = is_multisite() ? array_keys((array) get_site_option('active_sitewide_plugins', [])) : [];
        $mu      = get_mu_plugins();
        $updates = get_site_transient('update_plugins');
        $out     = [];

        foreach ($all as $file => $p) {
            $upd = $updates->response[$file] ?? null;

            $out[] = [
                'file'        => $file,
                'slug'        => dirname($file) === '.' ? basename($file, '.php') : dirname($file),
                'name'        => $p['Name'],
                'version'     => $p['Version'],
                'active'      => in_array($file, $active, true) || in_array($file, $network, true),
                'mu'          => false,
                'author'      => wp_strip_all_tags($p['Author'] ?? ''),
                'uri'         => $p['PluginURI'] ?: null,
                'description' => mb_substr(wp_strip_all_tags($p['Description'] ?? ''), 0, 200),
                'new_version' => $upd->new_version ?? null,
                'wporg'       => isset($updates->response[$file]) || isset($updates->no_update[$file]),
                'requires_php'=> $p['RequiresPHP'] ?: null,
            ];
        }

        foreach ($mu as $file => $p) {
            $out[] = [
                'file'    => $file,
                'slug'    => basename($file, '.php'),
                'name'    => $p['Name'],
                'version' => $p['Version'],
                'active'  => true,
                'mu'      => true,
            ];
        }

        return $out;
    }

    private static function themes(): array
    {
        wp_update_themes();

        $current = wp_get_theme();
        $updates = get_site_transient('update_themes');
        $out     = [];

        foreach (wp_get_themes() as $slug => $t) {
            $out[] = [
                'slug'        => $slug,
                'name'        => $t->get('Name'),
                'version'     => $t->get('Version'),
                'parent'      => $t->parent() ? $t->parent()->get_stylesheet() : null,
                'active'      => $slug === $current->get_stylesheet(),
                'new_version' => $updates->response[$slug]['new_version'] ?? null,
            ];
        }

        return $out;
    }

    private static function users(): array
    {
        $counts = count_users();

        return [
            'total'  => $counts['total_users'],
            'admins' => $counts['avail_roles']['administrator'] ?? 0,
            'admin_logins' => array_map(
                fn($u) => $u->user_login,
                get_users(['role' => 'administrator', 'fields' => ['user_login']])
            ),
        ];
    }

    /**
     * Compares core files against the official wordpress.org checksums.
     */
    private static function core_integrity(): array
    {
        global $wp_version;

        $checksums = get_core_checksums($wp_version, get_locale());

        if (!is_array($checksums)) {
            return ['checked' => false, 'reason' => 'checksums unavailable'];
        }

        $modified = [];
        $missing  = [];

        foreach ($checksums as $file => $md5) {
            if (str_starts_with($file, 'wp-content/')) continue;

            $path = ABSPATH . $file;

            if (!file_exists($path)) {
                $missing[] = $file;
                continue;
            }

            if (md5_file($path) !== $md5) {
                $modified[] = $file;
            }
        }

        $extra = self::extra_core_files($checksums);

        return [
            'checked'  => true,
            'files'    => count($checksums),
            'modified' => $modified,
            'missing'  => $missing,
            'extra'    => $extra,
        ];
    }

    /**
     * PHP files in wp-admin and wp-includes that are not in the checksums.
     */
    private static function extra_core_files(array $checksums): array
    {
        $known = array_flip(array_keys($checksums));
        $extra = [];

        foreach (['wp-admin', 'wp-includes'] as $dir) {
            foreach (self::php_files(ABSPATH . $dir) as $path) {
                $rel = ltrim(str_replace(ABSPATH, '', $path), '/');
                if (!isset($known[$rel])) $extra[] = $rel;
            }
        }

        $ignore = ['wp-config.php', 'wp-config-sample.php'];

        foreach (glob(ABSPATH . '*.php') ?: [] as $path) {
            $rel = basename($path);
            if (!isset($known[$rel]) && !in_array($rel, $ignore, true)) $extra[] = $rel;
        }

        return $extra;
    }

    /**
     * Hash per PHP file in wp-content. Corehash diffs this against the previous run.
     */
    private static function content_hashes(): array
    {
        $files = [];
        $base  = WP_CONTENT_DIR;

        foreach (self::php_files($base) as $path) {
            $rel = ltrim(str_replace($base, '', $path), '/');
            $files[$rel] = [
                'h' => md5_file($path),
                'm' => filemtime($path),
                's' => filesize($path),
            ];
        }

        return [
            'count' => count($files),
            'files' => $files,
        ];
    }

    /**
     * Quick signals that are almost always bad.
     */
    private static function suspicious(): array
    {
        $upload_dir = wp_upload_dir()['basedir'];
        $htaccess   = $upload_dir . '/.htaccess';
        $out        = [
            'php_in_uploads' => [],
            'obfuscated'     => [],
            'uploads_htaccess' => file_exists($htaccess)
                ? ['h' => md5_file($htaccess), 's' => filesize($htaccess)]
                : null,
        ];

        foreach (self::php_files($upload_dir) as $path) {
            $out['php_in_uploads'][] = ltrim(str_replace(WP_CONTENT_DIR, '', $path), '/');
        }

        $patterns = [
            '/eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|strrev)\s*\(/i',
            '/\$[a-z_]+\s*=\s*[\'"][a-z0-9+\/=]{200,}[\'"]\s*;/i',
            '/(preg_replace)\s*\(\s*[\'"][^\'"]*\/e[\'"]/i',
            '/\bassert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i',
            '/\b(system|passthru|shell_exec|exec)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i',
            '/\bmove_uploaded_file\s*\(\s*\$_FILES/i',
        ];

        foreach (self::php_files(WP_CONTENT_DIR) as $path) {
            if (filesize($path) > 2 * MB_IN_BYTES) continue;

            $src = file_get_contents($path);

            foreach ($patterns as $i => $re) {
                if (preg_match($re, $src)) {
                    $out['obfuscated'][] = [
                        'file'    => ltrim(str_replace(WP_CONTENT_DIR, '', $path), '/'),
                        'pattern' => $i,
                    ];
                    break;
                }
            }
        }

        return $out;
    }

    /* ---------- helpers ---------- */

    private static function php_files(string $dir): array
    {
        if (!is_dir($dir)) return [];

        $files = [];
        $skip  = ['node_modules', 'vendor', 'cache', '.git'];

        $it = new RecursiveIteratorIterator(
            new RecursiveCallbackFilterIterator(
                new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
                fn($f) => !($f->isDir() && in_array($f->getFilename(), $skip, true))
            )
        );

        foreach ($it as $f) {
            if (preg_match('/\.(php|phtml|php[0-9]|phar|inc)$/i', $f->getFilename())) {
                $files[] = $f->getPathname();
            }
        }

        return $files;
    }

    /* ---------- admin ---------- */

    public static function menu(): void
    {
        add_options_page('Corehash', 'Corehash', 'manage_options', 'corehash', [__CLASS__, 'page']);
    }

    public static function page(): void
    {
        $token    = get_option(self::OPTION_TOKEN);
        $endpoint = rest_url(self::NAMESPACE . '/inventory');
        ?>
        <div class="wrap">
            <h1>Corehash Agent</h1>

            <?php if (!empty($_GET['regenerated'])): ?>
                <div class="notice notice-success"><p>New token generated. Update it in your Corehash dashboard.</p></div>
            <?php endif; ?>

            <?php $seen = (int) get_option(self::OPTION_SEEN); $ok = $seen && $seen > time() - 2 * HOUR_IN_SECONDS; ?>
            <p style="display:flex;align-items:center;gap:8px;font-size:14px">
                <span style="width:10px;height:10px;border-radius:50%;background:<?= $ok ? '#16a34a' : ($seen ? '#d97706' : '#bbb') ?>"></span>
                <?php if (!$seen): ?>
                    Not connected yet. Add this site in your Corehash dashboard.
                <?php elseif ($ok): ?>
                    Connected. Last contacted by Corehash <?= human_time_diff($seen) ?> ago.
                <?php else: ?>
                    No contact for <?= human_time_diff($seen) ?>. Check the site in your Corehash dashboard.
                <?php endif; ?>
            </p>

            <p>Add this site to your Corehash dashboard using the details below.</p>

            <table class="form-table">
                <tr>
                    <th>Site URL</th>
                    <td><code><?= home_url() ?></code></td>
                </tr>
                <tr>
                    <th>Endpoint</th>
                    <td><code><?= $endpoint ?></code></td>
                </tr>
                <tr>
                    <th>Token</th>
                    <td>
                        <input type="text" readonly value="<?= $token ?>" class="regular-text code" onclick="this.select()">
                        <p class="description">Header: <code>X-Corehash-Token</code></p>
                    </td>
                </tr>
            </table>

            <form method="post" action="<?= admin_url('admin-post.php') ?>" onsubmit="return confirm('Generate a new token? The old one will stop working.')">
                <input type="hidden" name="action" value="corehash_regenerate">
                <?php wp_nonce_field('corehash_regenerate') ?>
                <?php submit_button('Generate new token', 'secondary') ?>
            </form>
        </div>
        <?php
    }
}

Corehash_Agent::init();
