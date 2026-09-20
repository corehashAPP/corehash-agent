<?php
/**
 * Plugin Name: Corehash Agent
 * Plugin URI:  https://corehash.app
 * Description: Connects this site to Corehash. Exposes one secured REST endpoint with an inventory of versions, plugins and file hashes.
 * Version:     0.2.0
 * Author:      Corehash
 * Author URI:  https://corehash.app
 * License:     GPL-2.0-or-later
 * Text Domain: corehash-agent
 */

if (!defined('ABSPATH')) exit;

final class Corehash_Agent
{
    const VERSION      = '0.2.0';
    const OPTION_TOKEN = 'corehash_token';
    const TRANSIENT    = 'corehash_inventory';
    const CACHE_TTL    = 50 * MINUTE_IN_SECONDS;
    const NAMESPACE    = 'corehash/v1';

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
        $given  = (string) $request->get_header('x-corehash-token');
        $stored = (string) get_option(self::OPTION_TOKEN);

        if ($given === '' || $stored === '') return false;

        return hash_equals($stored, $given);
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

            <h2>Test</h2>
            <pre>curl -H "X-Corehash-Token: <?= $token ?>" "<?= $endpoint ?>?fresh=1"</pre>
        </div>
        <?php
    }
}

Corehash_Agent::init();
