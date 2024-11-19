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
        add_action('wp_enqueue_scripts', array($this, 'enqueue_scripts'));
    }

    public function check_page_protection() {
        // Get current page ID
        $current_page_id = get_the_ID();
        
        // Get protected pages array
        $protected_pages = get_option('opp_protected_pages', array());
        
        // Ensure protected_pages is an array
        if (!is_array($protected_pages)) {
            $protected_pages = array();
        }
        
        error_log("OPP: Checking protection for page ID: " . $current_page_id);
        error_log("OPP: Protected pages: " . print_r($protected_pages, true));

        // Only check authentication for protected pages
        if (in_array($current_page_id, $protected_pages)) {
            error_log("OPP: Page is protected. Checking authentication.");
            if (!$this->check_authentication()) {
                error_log("OPP: User is not authenticated. Redirecting to OAuth login.");
                $this->redirect_to_oauth_login();
            } else {
                error_log("OPP: User is authenticated.");
            }
        } else {
            error_log("OPP: Page is not protected.");
            return; // Exit early for unprotected pages
        }
    }

    private function check_authentication() {
        // First check for existing token
        if (isset($_COOKIE['opp_access_token'])) {
            error_log("OPP: Access token found in cookie");
            return true;
        }
        
        // Then check if we're handling an OAuth callback
        if (isset($_GET['code']) && isset($_GET['state'])) {
            return $this->handle_oauth_callback();
        }
        
        error_log("OPP: No valid token found");
        return false;
    }

    private function handle_oauth_callback() {
        $received_state = $_GET['state'];
        
        error_log("OPP: Processing OAuth callback");
        error_log("OPP: - Received state: " . $received_state);
        error_log("OPP: - Cookie exists: " . (isset($_COOKIE['opp_oauth_state']) ? 'yes' : 'no'));
        error_log("OPP: - Cookie value: " . (isset($_COOKIE['opp_oauth_state']) ? $_COOKIE['opp_oauth_state'] : 'not set'));
        error_log("OPP: - Transient exists: " . (get_transient('opp_state_' . $received_state) ? 'yes' : 'no'));

        // Check both cookie and transient
        $valid_cookie_state = isset($_COOKIE['opp_oauth_state']) && $_COOKIE['opp_oauth_state'] === $received_state;
        $valid_transient_state = get_transient('opp_state_' . $received_state);
        
        if (!$valid_cookie_state && !$valid_transient_state) {
            error_log("OPP: State validation failed");
            return false;
        }

        // Clean up state storage
        delete_transient('opp_state_' . $received_state);
        setcookie('opp_oauth_state', '', time() - 3600, COOKIEPATH, COOKIE_DOMAIN, is_ssl(), true);
        
        $token = $this->exchange_code_for_token($_GET['code']);
        if ($token) {
            setcookie(
                'opp_access_token',
                $token,
                [
                    'expires' => time() + 3600,
                    'path' => COOKIEPATH,
                    'domain' => COOKIE_DOMAIN,
                    'secure' => is_ssl(),
                    'httponly' => true,
                    'samesite' => 'Lax'
                ]
            );
            error_log("OPP: Token obtained and set in cookie");
            
            // Redirect to remove the code and state from URL
            wp_redirect(remove_query_arg(array('code', 'state')));
            exit;
        }
        
        return false;
    }

    private function redirect_to_oauth_login() {
        $client_id = get_option('opp_client_id');
        $auth_endpoint = get_option('opp_auth_endpoint');
        $redirect_uri = get_option('opp_redirect_uri');

        // Generate a new state
        $state = bin2hex(random_bytes(16));
        
        error_log("OPP: Setting up new OAuth login");
        error_log("OPP: - Generated state: " . $state);
        
        // Store state in a transient with longer expiry
        $transient_set = set_transient('opp_state_' . $state, true, 900); // 15 minutes expiry
        error_log("OPP: - Transient set: " . ($transient_set ? 'Yes' : 'No'));
        
        // Check for headers
        if (headers_sent($file, $line)) {
            error_log("OPP: Headers already sent in $file:$line");
        } else {
            error_log("OPP: Headers not sent yet");
        }
        
        // Set the cookie with SameSite=Lax
        setcookie(
            'opp_oauth_state',
            $state,
            [
                'expires' => time() + 900,
                'path' => COOKIEPATH,
                'domain' => COOKIE_DOMAIN,
                'secure' => is_ssl(),
                'httponly' => true,
                'samesite' => 'Lax' // Allow cookie to be sent with top-level navigation
            ]
        );
        
        error_log("OPP: - Cookie settings:");
        error_log("OPP: -- Path: " . COOKIEPATH);
        error_log("OPP: -- Domain: " . COOKIE_DOMAIN);
        error_log("OPP: -- Secure: " . (is_ssl() ? 'Yes' : 'No'));
        
        // Clear any existing access token
        if (isset($_COOKIE['opp_access_token'])) {
            setcookie(
                'opp_access_token',
                '',
                [
                    'expires' => time() - 3600,
                    'path' => COOKIEPATH,
                    'domain' => COOKIE_DOMAIN,
                    'secure' => is_ssl(),
                    'httponly' => true,
                    'samesite' => 'Lax'
                ]
            );
        }

        $auth_url = add_query_arg(array(
            'client_id' => $client_id,
            'redirect_uri' => $redirect_uri,
            'response_type' => 'code',
            'scope' => 'openid profile email',
            'state' => $state
        ), $auth_endpoint);

        error_log("OPP: About to redirect to auth URL: " . $auth_url);
        error_log("OPP: - Final state value: " . $state);
        
        // Force the cookie to be available immediately for debugging
        $_COOKIE['opp_oauth_state'] = $state;
        
        error_log("OPP: - Current cookie value: " . (isset($_COOKIE['opp_oauth_state']) ? $_COOKIE['opp_oauth_state'] : 'not set'));
        error_log("OPP: - Transient exists: " . (get_transient('opp_state_' . $state) ? 'yes' : 'no'));

        // Ensure the redirect happens after cookie is set
        wp_redirect($auth_url);
        exit;
    }

    public function enqueue_scripts() {
        // Only enqueue scripts and check auth token for protected pages
        $current_page_id = get_the_ID();
        $protected_pages = get_option('opp_protected_pages', array());
        
        if (!is_array($protected_pages)) {
            $protected_pages = array();
        }

        wp_enqueue_script('oauth-page-protector', OPP_PLUGIN_URL . 'assets/js/oauth-page-protector.js', array('jquery'), OPP_VERSION, true);
        
        // Only pass auth token if page is protected
        wp_localize_script('oauth-page-protector', 'oppData', array(
            'authToken' => in_array($current_page_id, $protected_pages) ? $this->get_auth_token() : null,
        ));
    }

    private function get_auth_token() {
        if (isset($_COOKIE['opp_access_token'])) {
            error_log("OPP: Access token found in cookie");
            return $_COOKIE['opp_access_token'];
        }

        // Only proceed with OAuth flow if we're handling a callback
        if (isset($_GET['code']) && isset($_GET['state'])) {
            $received_state = $_GET['state'];
            
            error_log("OPP: Processing OAuth callback");
            error_log("OPP: - Received state: " . $received_state);
            error_log("OPP: - Cookie exists: " . (isset($_COOKIE['opp_oauth_state']) ? 'yes' : 'no'));
            error_log("OPP: - Cookie value: " . (isset($_COOKIE['opp_oauth_state']) ? $_COOKIE['opp_oauth_state'] : 'not set'));
            error_log("OPP: - Transient exists: " . (get_transient('opp_state_' . $received_state) ? 'yes' : 'no'));
            error_log("OPP: - All cookies: " . print_r($_COOKIE, true));

            // Check both cookie and transient
            $valid_cookie_state = isset($_COOKIE['opp_oauth_state']) && $_COOKIE['opp_oauth_state'] === $received_state;
            $valid_transient_state = get_transient('opp_state_' . $received_state);
            
            error_log("OPP: - Cookie state valid: " . ($valid_cookie_state ? 'yes' : 'no'));
            error_log("OPP: - Transient state valid: " . ($valid_transient_state ? 'yes' : 'no'));

            // If state validation fails, start a new OAuth flow instead of showing an error
            if (!$valid_cookie_state && !$valid_transient_state) {
                error_log("OPP: State validation failed - starting new OAuth flow");
                $this->redirect_to_oauth_login();
                exit;
            }

            error_log("OPP: State validated successfully");

            // Clean up state storage
            delete_transient('opp_state_' . $received_state);
            setcookie(
                'opp_oauth_state',
                '',
                [
                    'expires' => time() - 3600,
                    'path' => COOKIEPATH,
                    'domain' => COOKIE_DOMAIN,
                    'secure' => is_ssl(),
                    'httponly' => true,
                    'samesite' => 'Lax'
                ]
            );
            
            $token = $this->exchange_code_for_token($_GET['code']);
            if ($token) {
                setcookie(
                    'opp_access_token',
                    $token,
                    [
                        'expires' => time() + 3600,
                        'path' => COOKIEPATH,
                        'domain' => COOKIE_DOMAIN,
                        'secure' => is_ssl(),
                        'httponly' => true,
                        'samesite' => 'Lax'
                    ]
                );
                error_log("OPP: Token obtained and set in cookie");
                
                // Redirect to the original page without query parameters
                $redirect_url = remove_query_arg(array('code', 'state'));
                error_log("OPP: Redirecting to: " . $redirect_url);
                wp_redirect($redirect_url);
                exit;
            }
        }

        // Instead of automatically starting OAuth flow, return false
        error_log("OPP: No valid token found");
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
}
