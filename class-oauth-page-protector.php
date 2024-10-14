<?php

class OAuth_Page_Protector {

    public function run() {
        add_action('template_redirect', array($this, 'check_page_protection'));
        add_action('wp_enqueue_scripts', array($this, 'enqueue_scripts'));
    }

    public function check_page_protection() {
        $protected_pages = get_option('opp_protected_pages', array());
        $current_page_id = get_the_ID();

        error_log("OPP: Checking protection for page ID: " . $current_page_id);
        error_log("OPP: Protected pages: " . print_r($protected_pages, true));

        if (in_array($current_page_id, $protected_pages)) {
            error_log("OPP: Page is protected. Checking authentication.");
            if (!$this->is_user_authenticated()) {
                error_log("OPP: User is not authenticated. Redirecting to OAuth login.");
                $this->redirect_to_oauth_login();
            } else {
                error_log("OPP: User is authenticated.");
            }
        } else {
            error_log("OPP: Page is not protected.");
        }
    }

    private function is_user_authenticated() {
        $access_token = $this->get_auth_token();
        error_log("OPP: Checking authentication. Access token exists: " . ($access_token ? 'Yes' : 'No'));

        if (!$access_token) {
            return false;
        }

        // Fetch the JWKS
        $jwks_url = 'https://cognito-idp.us-east-2.amazonaws.com/us-east-2_1jhX1tAKk/.well-known/jwks.json';
        $response = wp_remote_get($jwks_url);

        if (is_wp_error($response)) {
            error_log("OPP: Failed to fetch JWKS: " . $response->get_error_message());
            return false;
        }

        $jwks = json_decode(wp_remote_retrieve_body($response), true);

        // Decode the access token
        $token_parts = explode('.', $access_token);
        if (count($token_parts) != 3) {
            error_log("OPP: Invalid token format");
            return false;
        }

        $header = json_decode(base64_decode($token_parts[0]), true);
        $payload = json_decode(base64_decode($token_parts[1]), true);

        // Check if token is expired
        if (isset($payload['exp']) && $payload['exp'] < time()) {
            error_log("OPP: Token has expired");
            return false;
        }

        // Verify token signature (this is a simplified version, you might want to use a JWT library for production)
        foreach ($jwks['keys'] as $key) {
            if ($key['kid'] == $header['kid']) {
                // Here you would verify the signature using the public key
                // For simplicity, we're just checking if the key exists
                error_log("OPP: Found matching key for token");
                return true;
            }
        }

        error_log("OPP: No matching key found for token");
        return false;
    }

    private function redirect_to_oauth_login() {
        $client_id = get_option('opp_client_id');
        $auth_endpoint = get_option('opp_auth_endpoint');
        $redirect_uri = get_option('opp_redirect_uri');

        $state = wp_create_nonce('oauth_state_' . time());
        set_transient('opp_oauth_state', $state, 3600); // Set for 1 hour

        error_log("OPP: Setting state: " . $state);

        $auth_url = add_query_arg(array(
            'client_id' => $client_id,
            'redirect_uri' => $redirect_uri,
            'response_type' => 'code',
            'scope' => 'openid profile email',
            'state' => $state
        ), $auth_endpoint);

        wp_redirect($auth_url);
        exit;
    }

    public function enqueue_scripts() {
        wp_enqueue_script('oauth-page-protector', OPP_PLUGIN_URL . 'assets/js/oauth-page-protector.js', array('jquery'), OPP_VERSION, true);
        wp_localize_script('oauth-page-protector', 'oppData', array(
            'authToken' => $this->get_auth_token(),
        ));
    }

    private function get_auth_token() {
        if (isset($_COOKIE['opp_access_token'])) {
            return $_COOKIE['opp_access_token'];
        }

        if (isset($_GET['code']) && isset($_GET['state'])) {
            $saved_state = get_transient('opp_oauth_state');
            error_log("OPP: Retrieving state. Received: " . $_GET['state'] . ", Saved: " . $saved_state);

            if (!$saved_state || $_GET['state'] !== $saved_state) {
                error_log("OPP: Invalid state. Received: " . $_GET['state'] . ", Saved: " . $saved_state);
                wp_die('Invalid state parameter. Please try again.');
            }

            delete_transient('opp_oauth_state'); // Clear the used state

            $token = $this->exchange_code_for_token($_GET['code']);
            if ($token) {
                setcookie('opp_access_token', $token, time() + 3600, '/', '', true, true);
                return $token;
            }
        }

        return false;
    }

    private function exchange_code_for_token($code) {
        $token_endpoint = get_option('opp_token_endpoint');
        $client_id = get_option('opp_client_id');
        $client_secret = get_option('opp_client_secret');
        $redirect_uri = get_option('opp_redirect_uri');

        $response = wp_remote_post($token_endpoint, array(
            'body' => array(
                'grant_type' => 'authorization_code',
                'client_id' => $client_id,
                'client_secret' => $client_secret,
                'code' => $code,
                'redirect_uri' => $redirect_uri
            )
        ));

        if (is_wp_error($response)) {
            return false;
        }

        $body = json_decode(wp_remote_retrieve_body($response), true);
        if (isset($body['access_token'])) {
            return $body['access_token'];
        }

        error_log("OPP: No access token in response: " . print_r($body, true));
        return false;
    }

    public function handle_oauth_callback() {
        if (isset($_GET['code'])) {
            $token = $this->exchange_code_for_token($_GET['code']);
            if ($token) {
                $this->set_auth_token($token);
                wp_redirect(home_url()); // Redirect to home page or desired location
                exit;
            }
        }
        wp_redirect(home_url()); // Redirect even if there's an error
        exit;
    }
}
