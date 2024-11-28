<?php
/**
 * Plugin Name: OAuth Page Protector
 * Plugin URI: https://yourwebsite.com/
 * Description: Protect specific pages with OAuth/OIDC authentication and pass tokens to Chrome browser.
 * Version: 1.0.0
 * Author: Your Name
 * Author URI: https://yourwebsite.com/
 * License: GPL-2.0+
 * License URI: http://www.gnu.org/licenses/gpl-2.0.txt
 */

// If this file is called directly, abort.
if (!defined('ABSPATH')) {
    exit;
}

// Define plugin constants
define('OPP_PLUGIN_URL', plugin_dir_url(__FILE__));
define('OPP_PLUGIN_PATH', plugin_dir_path(__FILE__));
define('OPP_VERSION', '1.0.0');

// Include the main class file
require_once plugin_dir_path(__FILE__) . 'class-oauth-page-protector.php';

// Include the admin class file
require_once plugin_dir_path(__FILE__) . 'class-oauth-page-protector-admin.php';

// Initialize the main class
function init_oauth_page_protector() {
    // Wait for init hook to avoid "too early" issues
    add_action('init', function() {
        $protector = new OAuth_Page_Protector();
        $protector->run();
    });
}
add_action('plugins_loaded', 'init_oauth_page_protector');

// Initialize the admin class
function init_oauth_page_protector_admin() {
    $admin = new OAuth_Page_Protector_Admin();
    $admin->run();
}
add_action('plugins_loaded', 'init_oauth_page_protector_admin');

add_action('init', function() {
    add_rewrite_rule('^oauth-callback/?', 'index.php?oauth_callback=1', 'top');
});

add_filter('query_vars', function($vars) {
    $vars[] = 'oauth_callback';
    return $vars;
});

add_action('template_redirect', function() {
    if (get_query_var('oauth_callback')) {
        $protector = new OAuth_Page_Protector();
        $protector->handle_oauth_callback();
    }
});

// Near the top of your main plugin file
register_deactivation_hook(__FILE__, 'opp_deactivate_plugin');
register_uninstall_hook(__FILE__, 'opp_uninstall_plugin');

function opp_deactivate_plugin() {
    error_log('OAuth Page Protector plugin is being deactivated');
    
    // Clear all transients
    global $wpdb;
    $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_opp_%'");
    $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_timeout_opp_%'");
    
    // Clear any authentication cookies
    if (isset($_COOKIE['opp_access_token'])) {
        setcookie('opp_access_token', '', time() - 3600, COOKIEPATH, COOKIE_DOMAIN);
    }
    if (isset($_COOKIE['opp_oauth_state'])) {
        setcookie('opp_oauth_state', '', time() - 3600, COOKIEPATH, COOKIE_DOMAIN);
    }
    
    // Force garbage collection to release file handles
    gc_collect_cycles();
    
    // Clear any PHP opcache
    if (function_exists('opcache_reset')) {
        opcache_reset();
    }
}

function opp_uninstall_plugin() {
    error_log('OAuth Page Protector plugin is being uninstalled');
    // This function is a fallback. The uninstall.php file should handle most uninstallation tasks.
}
