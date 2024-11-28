<?php
// If uninstall not called from WordPress, then exit
if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

// Remove all plugin transients
global $wpdb;
$wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_opp_%'");
$wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_timeout_opp_%'");

// Remove plugin directories
$upload_dir = wp_upload_dir();
$plugin_upload_dir = $upload_dir['basedir'] . '/oauth-page-protector';
if (file_exists($plugin_upload_dir)) {
    recursive_rmdir($plugin_upload_dir);
}

// Remove upgrade directory
$upgrade_dir = WP_CONTENT_DIR . '/upgrade/oauth-page-protector';
if (file_exists($upgrade_dir)) {
    recursive_rmdir($upgrade_dir);
}

// Helper function to recursively remove directories
function recursive_rmdir($dir) {
    if (is_dir($dir)) {
        $objects = scandir($dir);
        foreach ($objects as $object) {
            if ($object != "." && $object != "..") {
                if (is_dir($dir . "/" . $object)) {
                    recursive_rmdir($dir . "/" . $object);
                } else {
                    unlink($dir . "/" . $object);
                }
            }
        }
        rmdir($dir);
    }
}

// Log the uninstallation process
error_log('OAuth Page Protector plugin has been uninstalled (settings preserved)');
