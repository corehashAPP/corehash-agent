=== Corehash Agent ===
Contributors: corehash
Tags: security, monitoring, malware, vulnerability, integrity
Requires at least: 6.0
Tested up to: 7.1
Requires PHP: 8.0
Stable tag: 0.7.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Connects this site to Corehash, security monitoring for WordPress agencies.

== Description ==

The Corehash Agent exposes one secured REST endpoint that returns an inventory of this site: WordPress, PHP and plugin versions, core file checksums, hashes of PHP files in wp-content, and a few quick malware signals. Corehash polls this endpoint hourly and alerts your agency when something changes.

Since 0.6.0 the plugin also pushes: when something happens that almost never happens by itself (a new administrator, a plugin installed, a file edited through the editor, the site URL changed, PHP appearing in the uploads folder) it notifies Corehash immediately instead of waiting for the next hourly check. A small scan every five minutes covers the folders where hacks land.

Apart from those notifications the plugin does nothing on normal page views, and it only answers requests carrying the site's secret token.

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

= 0.7.0 =
* Sites can add themselves to a Corehash account with an enrollment key, for rolling out across many sites at once
* Key can come from wp-config.php (COREHASH_ENROLL_KEY), a filter, or the settings screen

= 0.6.1 =
* Reports the last login per administrator, so Corehash can spot dormant accounts
* Sends registration settings, used to judge whether a vulnerability is reachable on this site

= 0.6.0 =
* Real-time notifications for high-risk changes, pushed to Corehash as they happen
* Five-minute integrity scan of uploads, mu-plugins and the root files
* Verifies plugins from wordpress.org against the official per-file checksums
* Restore a modified plugin file from the official source, keeping a backup
* Every event now records who was logged in, or that nobody was

= 0.5.3 =
* Purge host page cache after a hardening change (SiteGround, LiteSpeed, WP Rocket, W3TC, Super Cache, Kinsta, WP Engine)

= 0.5.2 =
* Prevent host page caches (SiteGround, LiteSpeed, Varnish) from caching agent responses

= 0.5.1 =
* Hardening: report when mu-plugins is not writable instead of pretending the fix applied
* Hardening: block user enumeration at dispatch level too, and strip author from oEmbed

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
