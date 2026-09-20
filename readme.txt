=== Corehash Agent ===
Contributors: corehash
Tags: security, monitoring, malware, vulnerability, integrity
Requires at least: 6.0
Tested up to: 7.1
Requires PHP: 8.0
Stable tag: 0.5.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Connects this site to Corehash, security monitoring for WordPress agencies.

== Description ==

The Corehash Agent exposes one secured REST endpoint that returns an inventory of this site: WordPress, PHP and plugin versions, core file checksums, hashes of PHP files in wp-content, and a few quick malware signals. Corehash polls this endpoint hourly and alerts your agency when something changes.

The plugin does nothing on normal page views. It only responds to requests carrying the site's secret token.

No data is sent anywhere by the plugin itself; Corehash pulls it.

== Installation ==

1. Upload and activate the plugin.
2. Go to Settings › Corehash and copy the token.
3. Add the site in your Corehash dashboard with the site URL and token.

== Frequently Asked Questions ==

= Does this slow down my site? =

No. The inventory is only built when Corehash asks for it, roughly once an hour, and the result is cached.

= What data leaves the site? =

Version numbers, plugin and theme names, file hashes and admin usernames. Never file contents, never database content.

== Changelog ==

= 0.5.0 =
* Login and account event log (failed logins, admin logins, password/email/role changes)
* Backup status detection (UpdraftPlus, BackWPup, WPvivid)
* One-click hardening from the Corehash dashboard (XML-RPC, REST user enumeration, file editor, security headers)

= 0.4.0 =
* Only accept requests from the Corehash server (IP allowlist, filter `corehash_allowed_ips`)

= 0.3.2 =
* Connection status on the settings page

= 0.3.1 =
* Remove test snippet from settings page

= 0.3.0 =
* Self-hosted updates from corehash.app, with plugin details and automatic updates

= 0.2.0 =
* Report available updates for plugins, themes and core
* Plugin author, URI and description in inventory

= 0.1.2 =
* English admin page

= 0.1.1 =
* Ignore wp-config.php in core check, report uploads/.htaccess as hash

= 0.1.0 =
* Initial release
