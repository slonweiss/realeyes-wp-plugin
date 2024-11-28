<?php

/**
 * Main plugin class
 *
 * @package OAuth_Page_Protector
 * @since 1.0.0
 */

class OAuth_Page_Protector {

    public function run() {
        add_action('template_redirect', array($this, 'check_page_protection'));
        add_action('template_redirect', function() {
            $current_id = get_queried_object_id();
            $protected_pages = get_option('opp_protected_pages', array());
            
            error_log("Debug - Current Page/Post ID: " . $current_id);
            error_log("Debug - Protected IDs: " . print_r($protected_pages, true));
            error_log("Debug - Current URL: " . $_SERVER['REQUEST_URI']);
        }, 1);
    }

    public function check_page_protection() {
        // Get current page ID
        $current_page_id = get_queried_object_id();
        
        if (!$current_page_id) {
            error_log("OPP: No valid post/page ID found");
            return;
        }
        
        // Get protected pages array
        $protected_pages = get_option('opp_protected_pages', array());
        
        // Ensure protected_pages is an array
        if (!is_array($protected_pages)) {
            $protected_pages = array();
        }
        
        error_log("OPP: Checking protection for content ID: " . $current_page_id);
        error_log("OPP: Protected content IDs: " . print_r($protected_pages, true));

        // Only check authentication for protected content
        if (in_array($current_page_id, $protected_pages)) {
            error_log("OPP: Content is protected. Checking authentication.");
            if (!$this->check_authentication()) {
                error_log("OPP: User is not authenticated. Redirecting to OAuth login.");
                $this->redirect_to_oauth_login();
            } else {
                error_log("OPP: User is authenticated.");
            }
        } else {
            error_log("OPP: Content is not protected.");
        }
    }

    private function check_authentication() {
        error_log("OPP: Checking authentication");
        
        // First check for existing token
        if (isset($_COOKIE['opp_access_token'])) {
            error_log("OPP: Access token found in cookie");
            return true;
        }
        
        // Then check if we're handling an OAuth callback
        if (isset($_GET['code']) && isset($_GET['state'])) {
            error_log("OPP: Processing OAuth callback");
            return $this->handle_oauth_callback();
        }
        
        error_log("OPP: No valid authentication found");
        return false;
    }

    private function handle_oauth_callback() {
        $received_state = $_GET['state'];
        error_log("OPP: - Received state: " . $received_state);
        
        // Validate state
        $valid_state = get_transient('opp_state_' . $received_state);
        if (!$valid_state) {
            error_log("OPP: Invalid state in callback");
            return false;
        }

        // Clean up state storage
        delete_transient('opp_state_' . $received_state);
        setcookie('opp_oauth_state', '', time() - 3600, '/', COOKIE_DOMAIN);
        
        // Exchange code for token
        $token = $this->exchange_code_for_token($_GET['code']);
        if ($token) {
            // Set the token cookie
            setcookie(
                'opp_access_token',
                $token,
                [
                    'expires' => time() + 3600,
                    'path' => '/',
                    'domain' => COOKIE_DOMAIN,
                    'secure' => is_ssl(),
                    'httponly' => true,
                    'samesite' => 'Lax'
                ]
            );
            error_log("OPP: Token obtained and set in cookie");
            
            // Redirect to clean URL
            wp_redirect(remove_query_arg(array('code', 'state')));
            exit;
        }
        
        return false;
    }

    private function redirect_to_oauth_login() {
        // Only check for opp_oauth_state cookie if we're not processing a callback
        if (!isset($_GET['code']) && isset($_COOKIE['opp_oauth_state'])) {
            error_log("OPP: Preventing redirect loop - OAuth flow already in progress");
            wp_die('Authentication in progress. Please try again in a few moments.');
            return;
        }

        error_log("OPP: Setting up new OAuth login");
        $state = bin2hex(random_bytes(16));
        
        // Store state in both cookie and transient
        set_transient('opp_state_' . $state, true, 300);
        
        $cookie_options = array(
            'expires' => time() + 300,
            'path' => '/',
            'domain' => COOKIE_DOMAIN,
            'secure' => is_ssl(),
            'httponly' => true,
            'samesite' => 'Lax'
        );
        
        setcookie('opp_oauth_state', $state, $cookie_options);
        
        $params = array(
            'client_id' => get_option('opp_client_id'),
            'redirect_uri' => get_option('opp_redirect_uri'),
            'response_type' => 'code',
            'scope' => 'openid profile email',
            'state' => $state
        );
        
        $auth_url = get_option('opp_auth_endpoint') . '?' . http_build_query($params);
        
        error_log("OPP: Redirecting to auth URL: " . $auth_url);
        wp_redirect($auth_url);
        exit;
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
}
