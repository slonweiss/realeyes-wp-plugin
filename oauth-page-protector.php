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
    $protector = new OAuth_Page_Protector();
    $protector->run();
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
    // Perform any necessary cleanup on deactivation
    delete_transient('opp_oauth_state');
}

function opp_uninstall_plugin() {
    error_log('OAuth Page Protector plugin is being uninstalled');
    // This function is a fallback. The uninstall.php file should handle most uninstallation tasks.
}

// In your enqueue function or in a function hooked to wp_enqueue_scripts
function opp_enqueue_scripts() {
    wp_enqueue_script(
        'oauth-page-protector', 
        OPP_PLUGIN_URL . 'assets/js/oauth-page-protector.js', 
        array('jquery'), 
        OPP_VERSION, 
        true
    );
    // ... other enqueue code ...
}
add_action('wp_enqueue_scripts', 'opp_enqueue_scripts');
