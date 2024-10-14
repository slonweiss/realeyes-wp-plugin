<?php
// If uninstall not called from WordPress, then exit
if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

// Optional: Remove any options or transients your plugin has created
// delete_option('opp_some_option');
// delete_transient('opp_some_transient');

// Log the uninstallation process
error_log('OAuth Page Protector plugin is being uninstalled');
