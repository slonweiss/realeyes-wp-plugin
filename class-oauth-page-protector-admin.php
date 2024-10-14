<?php

class OAuth_Page_Protector_Admin {

    public function run() {
        add_action('admin_menu', array($this, 'add_plugin_menu'));
        add_action('admin_init', array($this, 'register_settings'));
    }

    public function add_plugin_menu() {
        add_options_page(
            'OAuth Page Protector Settings',
            'OAuth Page Protector',
            'manage_options',
            'oauth-page-protector',
            array($this, 'display_settings_page')
        );
    }

    public function register_settings() {
        register_setting('opp_settings', 'opp_client_id');
        register_setting('opp_settings', 'opp_client_secret');
        register_setting('opp_settings', 'opp_auth_endpoint');
        register_setting('opp_settings', 'opp_token_endpoint');
        register_setting('opp_settings', 'opp_redirect_uri');
        register_setting('opp_settings', 'opp_protected_pages', array(
            'sanitize_callback' => array($this, 'sanitize_protected_pages')
        ));
        register_setting('opp_settings', 'opp_token_verify_endpoint');
    }

    public function sanitize_protected_pages($input) {
        if (!is_array($input)) {
            return array();
        }
        return array_map('intval', $input);
    }

    public function display_settings_page() {
        ?>
        <div class="wrap">
            <h1>OAuth Page Protector Settings</h1>
            <form method="post" action="options.php">
                <?php
                settings_fields('opp_settings');
                do_settings_sections('opp_settings');
                ?>
                <table class="form-table">
                    <tr>
                        <th scope="row">Client ID</th>
                        <td><input type="text" name="opp_client_id" value="<?php echo esc_attr(get_option('opp_client_id')); ?>" /></td>
                    </tr>
                    <tr>
                        <th scope="row">Client Secret</th>
                        <td><input type="password" name="opp_client_secret" value="<?php echo esc_attr(get_option('opp_client_secret')); ?>" /></td>
                    </tr>
                    <tr>
                        <th scope="row">Auth Endpoint</th>
                        <td><input type="text" name="opp_auth_endpoint" value="<?php echo esc_attr(get_option('opp_auth_endpoint')); ?>" /></td>
                    </tr>
                    <tr>
                        <th scope="row">Token Endpoint</th>
                        <td><input type="text" name="opp_token_endpoint" value="<?php echo esc_attr(get_option('opp_token_endpoint')); ?>" /></td>
                    </tr>
                    <tr>
                        <th scope="row">Redirect URI</th>
                        <td><input type="text" name="opp_redirect_uri" value="<?php echo esc_attr(get_option('opp_redirect_uri')); ?>" /></td>
                    </tr>
                    <tr>
                        <th scope="row">Token Verify Endpoint</th>
                        <td><input type="text" name="opp_token_verify_endpoint" value="<?php echo esc_attr(get_option('opp_token_verify_endpoint')); ?>" /></td>
                    </tr>
                    <tr>
                        <th scope="row">Protected Pages</th>
                        <td>
                            <?php
                            $pages = get_pages();
                            $protected_pages = get_option('opp_protected_pages', array());
                            // Ensure $protected_pages is always an array
                            if (!is_array($protected_pages)) {
                                $protected_pages = array();
                            }
                            foreach ($pages as $page) {
                                $checked = in_array($page->ID, $protected_pages) ? 'checked' : '';
                                echo '<label><input type="checkbox" name="opp_protected_pages[]" value="' . $page->ID . '" ' . $checked . '> ' . $page->post_title . '</label><br>';
                            }
                            ?>
                        </td>
                    </tr>
                </table>
                <?php submit_button(); ?>
            </form>
        </div>
        <?php
    }
}
