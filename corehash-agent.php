<?php
/**
 * Plugin Name: Corehash Agent
 * Plugin URI:  https://corehash.app
 * Description: Connects this site to Corehash. Exposes one secured REST endpoint with an inventory of versions, plugins and file hashes.
 * Version:     0.6.0
 * Author:      Corehash
 * Author URI:  https://corehash.app
 * License:     GPL-2.0-or-later
 * Text Domain: corehash-agent
 */

if (!defined('ABSPATH')) exit;

final class Corehash_Agent
{
    const VERSION      = '0.6.0';
    const OPTION_TOKEN = 'corehash_token';
    const OPTION_SEEN  = 'corehash_last_contact';
    const OPTION_EVENTS = 'corehash_events';
    const OPTION_FIXES  = 'corehash_fixes';
    const MAX_EVENTS    = 300;
    const OPTION_QUEUE  = 'corehash_queue';
    const OPTION_HOT    = 'corehash_hot';
    const PUSH_URL      = 'https://corehash.app/agent/event';
    const HOT_INTERVAL  = 300; // seconden tussen twee hot scans
    const ROOT_FILES    = ['index.php', 'wp-config.php', '.htaccess', 'wp-login.php'];
    const TRANSIENT    = 'corehash_inventory';
    const CACHE_TTL    = 50 * MINUTE_IN_SECONDS;
    const NAMESPACE    = 'corehash/v1';
    const UPDATE_URL   = 'https://corehash.app/agent/update.json';
    const ALLOWED_IPS  = ['35.214.231.225']; // Corehash-server. Uitbreiden met een filter: corehash_allowed_ips

    public static function init(): void
    {
        register_activation_hook(__FILE__, [__CLASS__, 'activate']);
        register_deactivation_hook(__FILE__, [__CLASS__, 'deactivate']);
        add_action('rest_api_init', [__CLASS__, 'routes']);
        add_filter('rest_post_dispatch', [__CLASS__, 'no_cache_response'], 10, 3);
        add_action('admin_menu', [__CLASS__, 'menu']);
        add_action('admin_post_corehash_regenerate', [__CLASS__, 'regenerate']);
        add_action('upgrader_process_complete', [__CLASS__, 'flush']);
        add_action('activated_plugin', [__CLASS__, 'flush']);
        add_action('deactivated_plugin', [__CLASS__, 'flush']);
        add_action('switch_theme', [__CLASS__, 'flush']);

        // security events (login monitoring)
        add_action('wp_login_failed', [__CLASS__, 'ev_login_failed']);
        add_action('wp_login', [__CLASS__, 'ev_login'], 10, 2);
        add_action('after_password_reset', fn($u) => self::event('password_reset', ['user' => $u->user_login]));
        add_action('profile_update', [__CLASS__, 'ev_profile_update'], 10, 2);
        add_action('set_user_role', [__CLASS__, 'ev_role'], 10, 3);
        add_action('user_register', fn($id) => self::event('user_created', ['user' => get_userdata($id)->user_login ?? $id, 'role' => implode(',', get_userdata($id)->roles ?? [])]));
        add_action('deleted_user', fn($id, $r, $u) => self::event('user_deleted', ['user' => $u->user_login ?? $id]), 10, 3);
        add_action('activated_plugin', fn($f) => self::event('plugin_activated', ['plugin' => $f]));
        add_action('deactivated_plugin', fn($f) => self::event('plugin_deactivated', ['plugin' => $f]));

        // real-time: wijzigingen die vrijwel nooit vanzelf gebeuren
        add_action('upgrader_process_complete', [__CLASS__, 'ev_upgrade'], 10, 2);
        add_action('updated_option', [__CLASS__, 'ev_option'], 10, 3);
        add_action('wp_ajax_edit-theme-plugin-file', [__CLASS__, 'ev_editor'], 1);

        // push + periodieke scan van de gevoelige paden
        add_filter('cron_schedules', [__CLASS__, 'cron_interval']);
        add_action('corehash_hot_scan', [__CLASS__, 'hot_scan']);
        add_action('shutdown', [__CLASS__, 'flush_queue']);

        if (!wp_next_scheduled('corehash_hot_scan')) {
            wp_schedule_event(time() + 60, 'corehash_5min', 'corehash_hot_scan');
        }

        // self-hosted updates + "View details"
        add_filter('pre_set_site_transient_update_plugins', [__CLASS__, 'check_update']);
        add_filter('plugins_api', [__CLASS__, 'plugin_info'], 20, 3);
        add_filter('auto_update_plugin', [__CLASS__, 'auto_update'], 10, 2);
        add_action('upgrader_process_complete', [__CLASS__, 'flush_update_cache'], 10, 2);
    }

    public static function no_cache_response($response, $server, $request)
    {
        if (str_starts_with((string) $request->get_route(), '/' . self::NAMESPACE) && $response instanceof WP_HTTP_Response) {
            $response->header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
            $response->header('Pragma', 'no-cache');
            $response->header('Expires', 'Wed, 11 Jan 1984 05:00:00 GMT');
            $response->header('X-Accel-Expires', '0');
        }

        return $response;
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

        if (!wp_next_scheduled('corehash_hot_scan')) {
            wp_schedule_event(time() + 60, 'corehash_5min', 'corehash_hot_scan');
        }
    }

    public static function deactivate(): void
    {
        $ts = wp_next_scheduled('corehash_hot_scan');
        if ($ts) wp_unschedule_event($ts, 'corehash_hot_scan');
    }

    public static function cron_interval(array $schedules): array
    {
        $schedules['corehash_5min'] = ['interval' => self::HOT_INTERVAL, 'display' => 'Every 5 minutes (Corehash)'];

        return $schedules;
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

        register_rest_route(self::NAMESPACE, '/fix', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'fix'],
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
        // nooit door host-caches (SiteGround, Kinsta, LiteSpeed, Varnish) laten cachen
        if (!defined('DONOTCACHEPAGE')) define('DONOTCACHEPAGE', true);
        if (!defined('DONOTCACHEOBJECT')) define('DONOTCACHEOBJECT', true);
        nocache_headers();
        header('X-Accel-Expires: 0');
        header('X-LiteSpeed-Cache-Control: no-cache');
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');

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
            'integrity'    => self::wporg_integrity(),
            'realtime'     => [
                'hot'    => count((array) get_option(self::OPTION_HOT, [])),
                'queued' => count((array) get_option(self::OPTION_QUEUE, [])),
                'next'   => wp_next_scheduled('corehash_hot_scan') ?: null,
            ],
            'events'       => self::events(),
            'backup'       => self::backup(),
            'fixes'        => file_exists(WPMU_PLUGIN_DIR . '/corehash-hardening.php') ? (array) get_option(self::OPTION_FIXES, []) : [],
            'mu_writable'  => is_dir(WPMU_PLUGIN_DIR) ? wp_is_writable(WPMU_PLUGIN_DIR) : wp_is_writable(WP_CONTENT_DIR),
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

    /* ---------- events ---------- */

    private static function ip(): string
    {
        foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_X_REAL_IP'] as $h) {
            if (!empty($_SERVER[$h]) && filter_var($_SERVER[$h], FILTER_VALIDATE_IP)) return $_SERVER[$h];
        }

        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $first = trim(explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0]);
            if (filter_var($first, FILTER_VALIDATE_IP)) return $first;
        }

        return $_SERVER['REMOTE_ADDR'] ?? '';
    }

    private static function event(string $type, array $data = []): void
    {
        $row = ['t' => time(), 'type' => $type, 'ip' => self::ip(), 'ua' => mb_substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 120)] + $data;

        // Wie deed dit? Een wijziging zonder ingelogde gebruiker weegt zwaarder.
        $user = function_exists('wp_get_current_user') ? wp_get_current_user() : null;

        if ($user && $user->ID) {
            $row['by']   = $user->user_login;
            $row['role'] = implode(',', (array) $user->roles);
        }

        $events   = (array) get_option(self::OPTION_EVENTS, []);
        $events[] = $row;

        if (count($events) > self::MAX_EVENTS) {
            $events = array_slice($events, -self::MAX_EVENTS);
        }

        update_option(self::OPTION_EVENTS, $events, false);

        if (self::urgent($type, $row)) self::queue($row);
    }

    /* ---------- real-time push ---------- */

    /**
     * Gebeurtenissen die niet kunnen wachten op de volgende uurlijkse check.
     */
    private static function urgent(string $type, array $d): bool
    {
        if (in_array($type, ['plugin_installed', 'theme_installed', 'plugin_activated', 'file_edited', 'option_changed', 'file_new', 'file_changed', 'file_removed', 'user_deleted'], true)) {
            return true;
        }

        if ($type === 'user_created' && str_contains((string) ($d['role'] ?? ''), 'administrator')) return true;
        if ($type === 'role_changed' && (string) ($d['to'] ?? '') === 'administrator') return true;

        return false;
    }

    private static function queue(array $event): void
    {
        $q   = (array) get_option(self::OPTION_QUEUE, []);
        $q[] = $event;

        if (count($q) > 50) $q = array_slice($q, -50);

        update_option(self::OPTION_QUEUE, $q, false);
    }

    /**
     * Stuurt de wachtrij naar Corehash. Draait op shutdown, dus na het
     * antwoord aan de bezoeker. Lukt het niet, dan blijft de rij staan
     * en probeert de volgende scan het opnieuw.
     */
    public static function flush_queue(): void
    {
        $q = (array) get_option(self::OPTION_QUEUE, []);

        if (!$q) return;

        $token = get_option(self::OPTION_TOKEN);

        if (!$token) return;

        $res = wp_remote_post(apply_filters('corehash_push_url', self::PUSH_URL), [
            'timeout'     => 8,
            'redirection' => 0,
            'headers'     => ['X-Corehash-Token' => $token, 'Content-Type' => 'application/json'],
            'body'        => wp_json_encode(['site' => home_url(), 'agent' => self::VERSION, 'events' => array_values($q)]),
        ]);

        $code = is_wp_error($res) ? 0 : (int) wp_remote_retrieve_response_code($res);

        // 2xx: aangekomen. 401/403/404: dit endpoint kent ons niet, dus
        // blijven proberen heeft geen zin. Al het andere: bewaren.
        if (($code >= 200 && $code < 300) || in_array($code, [401, 403, 404], true)) {
            update_option(self::OPTION_QUEUE, [], false);
        }
    }

    /* ---------- hot scan: de plekken waar hacks landen ---------- */

    public static function hot_scan(): void
    {
        $prev = (array) get_option(self::OPTION_HOT, []);
        $now  = [];

        foreach (self::hot_paths() as $rel => $path) {
            if (!is_readable($path)) continue;
            $now[$rel] = md5_file($path);
        }

        // Eerste keer: alleen vastleggen, anders meldt hij de hele site.
        if ($prev) {
            $changes = 0;

            foreach ($now as $rel => $hash) {
                if ($changes >= 25) break;

                if (!isset($prev[$rel])) {
                    self::event('file_new', ['file' => $rel, 'class' => self::classify($rel)]);
                    $changes++;
                } elseif ($prev[$rel] !== $hash) {
                    self::event('file_changed', ['file' => $rel, 'class' => self::classify($rel)]);
                    $changes++;
                }
            }

            foreach ($prev as $rel => $hash) {
                if ($changes >= 25) break;

                if (!isset($now[$rel])) {
                    self::event('file_removed', ['file' => $rel, 'class' => self::classify($rel)]);
                    $changes++;
                }
            }
        }

        update_option(self::OPTION_HOT, $now, false);

        self::flush_queue();
    }

    /**
     * De gevoelige set: klein genoeg om elke vijf minuten te hashen.
     * Het maatwerk van de developer zit hier bewust niet in.
     */
    private static function hot_paths(): array
    {
        $out     = [];
        $uploads = wp_upload_dir()['basedir'] ?? null;

        if ($uploads && is_dir($uploads)) {
            foreach (self::php_files($uploads) as $p) {
                $out['uploads/' . ltrim(str_replace($uploads, '', $p), '/')] = $p;
            }

            if (file_exists($uploads . '/.htaccess')) $out['uploads/.htaccess'] = $uploads . '/.htaccess';
        }

        if (defined('WPMU_PLUGIN_DIR') && is_dir(WPMU_PLUGIN_DIR)) {
            foreach (self::php_files(WPMU_PLUGIN_DIR) as $p) {
                $out['mu-plugins/' . ltrim(str_replace(WPMU_PLUGIN_DIR, '', $p), '/')] = $p;
            }
        }

        foreach (self::ROOT_FILES as $f) {
            $path = ABSPATH . $f;

            // wp-config.php mag één map boven de installatie staan
            if ($f === 'wp-config.php' && !file_exists($path)) {
                $path = dirname(ABSPATH) . '/wp-config.php';
            }

            if (file_exists($path)) $out[$f] = $path;
        }

        return $out;
    }

    private static function classify(string $rel): string
    {
        if (str_starts_with($rel, 'uploads/'))     return 'uploads';
        if (str_starts_with($rel, 'mu-plugins/'))  return 'mu';
        if (in_array($rel, self::ROOT_FILES, true)) return 'root';

        return 'other';
    }

    /* ---------- integriteit van wordpress.org plugins ---------- */

    /**
     * wordpress.org publiceert per plugin per versie de md5 van elk bestand.
     * Wijkt er iets af, dan is dat altijd een signaal: developers horen niet
     * in plugincode van derden te zitten, aanvallers wel.
     */
    private static function wporg_integrity(): array
    {
        $out     = [];
        $checked = 0;

        foreach (self::plugins() as $p) {
            if ($checked >= 15) break;
            if (empty($p['wporg']) || empty($p['slug']) || empty($p['version'])) continue;
            if (!is_dir(WP_PLUGIN_DIR . '/' . $p['slug'])) continue;

            $sums = self::checksums($p['slug'], $p['version']);
            $checked++;

            if (!$sums) continue;

            $dir = WP_PLUGIN_DIR . '/' . $p['slug'];
            $bad = [];

            foreach ($sums as $file => $hashes) {
                if (count($bad) >= 10) break;

                $path = $dir . '/' . $file;
                $list = array_values(array_filter((array) $hashes, 'is_string'));

                if (!$list) continue;

                if (!file_exists($path)) {
                    $bad[] = ['file' => $file, 'why' => 'missing'];
                    continue;
                }

                if (!in_array(md5_file($path), $list, true)) {
                    $bad[] = ['file' => $file, 'why' => 'modified'];
                }
            }

            if ($bad) {
                $out[$p['slug']] = ['name' => $p['name'], 'version' => $p['version'], 'files' => $bad];
            }
        }

        return $out;
    }

    private static function checksums(string $slug, string $version): array
    {
        $key  = 'corehash_sums_' . md5($slug . '@' . $version);
        $sums = get_transient($key);

        if (is_array($sums)) return $sums;

        $res  = wp_remote_get('https://api.wordpress.org/plugins/checksums/1.0/?slug=' . rawurlencode($slug) . '&version=' . rawurlencode($version), ['timeout' => 12]);
        $body = is_wp_error($res) ? null : json_decode(wp_remote_retrieve_body($res), true);
        $sums = (is_array($body) && !empty($body['files']) && is_array($body['files'])) ? $body['files'] : [];

        set_transient($key, $sums, DAY_IN_SECONDS);

        return $sums;
    }

    /**
     * Zet een gewijzigd bestand terug naar de versie van wordpress.org.
     * Het oude bestand wordt bewaard naast het origineel.
     */
    private static function restore(string $slug, string $file): array
    {
        $plugins = self::plugins();
        $version = null;

        foreach ($plugins as $p) {
            if (($p['slug'] ?? '') === $slug) {
                $version = $p['version'];
                break;
            }
        }

        if (!$version) return ['ok' => false, 'error' => 'Plugin not installed'];

        $file = ltrim(str_replace('\\', '/', $file), '/');

        if (str_contains($file, '..') || !preg_match('#^[A-Za-z0-9._/-]+$#', $file)) {
            return ['ok' => false, 'error' => 'Invalid path'];
        }

        $sums = self::checksums($slug, $version);

        if (!isset($sums[$file])) return ['ok' => false, 'error' => 'File is not part of the official release'];

        $url = 'https://plugins.svn.wordpress.org/' . rawurlencode($slug) . '/tags/' . rawurlencode($version) . '/' . $file;
        $res = wp_remote_get($url, ['timeout' => 20]);

        if (is_wp_error($res) || (int) wp_remote_retrieve_response_code($res) !== 200) {
            return ['ok' => false, 'error' => 'Could not download the original file'];
        }

        $clean = wp_remote_retrieve_body($res);
        $list  = array_values(array_filter((array) $sums[$file], 'is_string'));

        if ($list && !in_array(md5($clean), $list, true)) {
            return ['ok' => false, 'error' => 'Downloaded file does not match the official checksum'];
        }

        $path = WP_PLUGIN_DIR . '/' . $slug . '/' . $file;

        if (file_exists($path) && !@copy($path, $path . '.corehash-bak')) {
            return ['ok' => false, 'error' => 'Could not back up the current file'];
        }

        if (@file_put_contents($path, $clean) === false) {
            return ['ok' => false, 'error' => 'Could not write to ' . $file . ' (permissions)'];
        }

        self::event('file_restored', ['file' => $slug . '/' . $file, 'class' => 'wporg_plugin']);
        self::flush();

        return ['ok' => true, 'error' => null, 'backup' => $file . '.corehash-bak'];
    }

    /* ---------- extra events ---------- */

    public static function ev_upgrade($upgrader, $options): void
    {
        $action = $options['action'] ?? '';
        $type   = $options['type'] ?? '';

        if ($action !== 'install' || !in_array($type, ['plugin', 'theme'], true)) return;

        $name = '';

        if ($type === 'plugin') {
            $name = $upgrader->plugin_info ? $upgrader->plugin_info() : ($options['plugins'][0] ?? '');
        } else {
            $name = $upgrader->theme_info() ? $upgrader->theme_info()->get_stylesheet() : ($options['themes'][0] ?? '');
        }

        self::event($type . '_installed', [$type => (string) $name]);
    }

    /**
     * Instellingen waarmee een site wordt overgenomen: de URL omleggen,
     * registratie openzetten of iedereen beheerder maken.
     */
    public static function ev_option($option, $old, $new): void
    {
        $watch = ['siteurl', 'home', 'users_can_register', 'default_role', 'admin_email', 'template', 'stylesheet'];

        if (!in_array($option, $watch, true)) return;
        if ($old === $new) return;

        self::event('option_changed', [
            'option' => $option,
            'from'   => is_scalar($old) ? mb_substr((string) $old, 0, 120) : '',
            'to'     => is_scalar($new) ? mb_substr((string) $new, 0, 120) : '',
        ]);
    }

    public static function ev_editor(): void
    {
        $file = isset($_POST['file']) ? sanitize_text_field(wp_unslash($_POST['file'])) : '';

        self::event('file_edited', [
            'file'   => mb_substr($file, 0, 200),
            'target' => isset($_POST['plugin']) ? 'plugin' : (isset($_POST['theme']) ? 'theme' : 'unknown'),
        ]);
    }

    public static function ev_login_failed($username): void
    {
        self::event('login_failed', ['user' => mb_substr((string) $username, 0, 60)]);
    }

    public static function ev_login($login, $user): void
    {
        self::event('login', ['user' => $login, 'admin' => in_array('administrator', (array) $user->roles, true)]);
    }

    public static function ev_profile_update($id, $old): void
    {
        $new = get_userdata($id);
        if (!$new) return;

        $changes = [];
        if ($old->user_email !== $new->user_email) $changes[] = 'email';
        if ($old->user_pass !== $new->user_pass)   $changes[] = 'password';

        if ($changes) {
            self::event('profile_changed', ['user' => $new->user_login, 'changed' => implode(',', $changes), 'admin' => in_array('administrator', (array) $new->roles, true)]);
        }
    }

    public static function ev_role($id, $role, $old): void
    {
        self::event('role_changed', ['user' => get_userdata($id)->user_login ?? $id, 'from' => implode(',', (array) $old), 'to' => $role]);
    }

    private static function events(): array
    {
        return (array) get_option(self::OPTION_EVENTS, []);
    }

    /* ---------- backup ---------- */

    private static function backup(): array
    {
        // UpdraftPlus
        $u = get_option('updraft_last_backup');
        if (is_array($u) && !empty($u['backup_time'])) {
            return ['plugin' => 'UpdraftPlus', 'last' => (int) $u['backup_time'], 'ok' => !empty($u['success'])];
        }

        // BackWPup
        $jobs = get_option('backwpup_jobs');
        if (is_array($jobs) && $jobs) {
            $last = max(array_map(fn($j) => (int) ($j['lastrun'] ?? 0), $jobs));
            $ok   = max(array_map(fn($j) => (int) ($j['lastruntime'] ?? 0), $jobs)) > 0;
            if ($last) return ['plugin' => 'BackWPup', 'last' => $last, 'ok' => $ok];
        }

        // WPvivid
        $w = get_option('wpvivid_last_msg');
        if (is_array($w) && !empty($w['time'])) {
            return ['plugin' => 'WPvivid', 'last' => (int) $w['time'], 'ok' => ($w['status'] ?? '') === 'completed'];
        }

        // Duplicator Pro schedules
        if (defined('DUPLICATOR_PRO_VERSION')) {
            return ['plugin' => 'Duplicator Pro', 'last' => null, 'ok' => null];
        }

        // Host-level backups (SiteGround, Kinsta, WP Engine): niet zichtbaar vanuit WP
        foreach (['sg-cachepress/sg-cachepress.php', 'kinsta-mu-plugins/kinsta-mu-plugins.php', 'wpengine-common/plugin.php'] as $host) {
            if (file_exists(WP_PLUGIN_DIR . '/' . $host) || file_exists(WPMU_PLUGIN_DIR . '/' . $host)) {
                return ['plugin' => 'host', 'last' => null, 'ok' => null];
            }
        }

        return ['plugin' => null, 'last' => null, 'ok' => null];
    }

    /* ---------- fixes (hardening via mu-plugin) ---------- */

    const FIXES = ['disable_xmlrpc', 'hide_rest_users', 'disallow_file_edit', 'security_headers'];

    public static function fix(WP_REST_Request $request)
    {
        $action = (string) $request->get_param('action');
        $enable = (bool) $request->get_param('enable');

        if ($action === 'restore_file') {
            $result = self::restore((string) $request->get_param('slug'), (string) $request->get_param('file'));

            return new WP_REST_Response($result, 200);
        }

        if (!in_array($action, self::FIXES, true)) {
            return new WP_REST_Response(['ok' => false, 'error' => 'unknown action'], 400);
        }

        $previous = (array) get_option(self::OPTION_FIXES, []);
        $fixes    = $previous;
        $fixes[$action] = $enable;
        $fixes = array_filter($fixes);

        $written = self::write_mu_plugin($fixes);

        if (!$written) {
            return new WP_REST_Response(['ok' => false, 'fixes' => $previous, 'error' => 'Cannot write to ' . WPMU_PLUGIN_DIR . ' (permissions). Create the folder and make it writable, or apply this fix manually.'], 200);
        }

        update_option(self::OPTION_FIXES, $fixes, false);
        self::flush();
        self::purge_host_cache();

        return new WP_REST_Response(['ok' => true, 'fixes' => $fixes, 'error' => null]);
    }

    /**
     * Pagecaches legen zodat een hardening-wijziging direct zichtbaar is.
     */
    private static function purge_host_cache(): void
    {
        try {
            if (function_exists('sg_cachepress_purge_cache')) sg_cachepress_purge_cache();          // SiteGround
            if (function_exists('rocket_clean_domain'))       rocket_clean_domain();                // WP Rocket
            if (function_exists('w3tc_flush_all'))            w3tc_flush_all();                     // W3 Total Cache
            if (function_exists('wp_cache_clear_cache'))      wp_cache_clear_cache();               // WP Super Cache
            if (function_exists('wpfc_clear_all_cache'))      wpfc_clear_all_cache(true);           // WP Fastest Cache
            if (class_exists('\\LiteSpeed\\Purge'))           do_action('litespeed_purge_all');     // LiteSpeed
            if (function_exists('kinsta_cache_purge') || class_exists('Kinsta\\Cache')) do_action('kinsta_cache_purge_all'); // Kinsta
            if (class_exists('WpeCommon') && method_exists('WpeCommon', 'purge_varnish_cache')) WpeCommon::purge_varnish_cache(); // WP Engine
            if (function_exists('wp_cache_flush')) wp_cache_flush();
        } catch (\Throwable) {
        }
    }

    private static function write_mu_plugin(array $fixes): bool
    {
        $dir  = WPMU_PLUGIN_DIR;
        $file = $dir . '/corehash-hardening.php';

        if (empty($fixes)) {
            return !file_exists($file) || @unlink($file);
        }

        if (!is_dir($dir) && !@mkdir($dir, 0755, true)) return false;
        if (!wp_is_writable($dir)) @chmod($dir, 0755);
        if (!wp_is_writable($dir)) return false;

        $php = "<?php\n/**\n * Plugin Name: Corehash Hardening\n * Description: Managed by the Corehash Agent. Do not edit; change settings in your Corehash dashboard.\n */\nif (!defined('ABSPATH')) exit;\n";

        if (!empty($fixes['disable_xmlrpc'])) {
            $php .= "add_filter('xmlrpc_enabled', '__return_false');\nadd_filter('wp_headers', function (\$h) { unset(\$h['X-Pingback']); return \$h; });\n";
        }
        if (!empty($fixes['hide_rest_users'])) {
            $php .= "add_filter('rest_endpoints', function (\$e) { if (!is_user_logged_in()) { foreach (array_keys(\$e) as \$k) { if (str_starts_with(\$k, '/wp/v2/users')) unset(\$e[\$k]); } } return \$e; });\nadd_filter('rest_pre_dispatch', function (\$r, \$s, \$req) { if (!is_user_logged_in() && str_starts_with(\$req->get_route(), '/wp/v2/users')) { return new WP_Error('rest_no_route', 'No route was found matching the URL and request method.', ['status' => 404]); } return \$r; }, 10, 3);\nadd_action('init', function () { if (!is_admin() && isset(\$_GET['author']) && !is_user_logged_in()) { wp_redirect(home_url(), 301); exit; } });\nadd_filter('oembed_response_data', function (\$d) { unset(\$d['author_name'], \$d['author_url']); return \$d; });\n";
        }
        if (!empty($fixes['disallow_file_edit'])) {
            $php .= "if (!defined('DISALLOW_FILE_EDIT')) define('DISALLOW_FILE_EDIT', true);\n";
        }
        if (!empty($fixes['security_headers'])) {
            $php .= "add_action('send_headers', function () { if (is_ssl()) header('Strict-Transport-Security: max-age=31536000'); header('X-Content-Type-Options: nosniff'); header('X-Frame-Options: SAMEORIGIN'); header('Referrer-Policy: strict-origin-when-cross-origin'); });\n";
        }

        return (bool) @file_put_contents($file, $php);
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
