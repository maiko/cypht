<?php

/**
 * Oauth2 manager
 * @package framework
 * @subpackage oauth2
 */

/**
 * Class for dealing with Oauth2
 */
class Hm_Oauth2 {

    private $client_id;
    private $client_secret;
    private $redirect_uri;
    private $api;

    /**
     * Load default settings
     * @param string $id Oath2 client id
     * @param string $secret Oath2 client secret
     * @param string $uri URI to redirect to from the remote site
     */
    public function __construct($id, $secret, $uri) {
        $this->client_id = $id;
        $this->client_secret = $secret;
        $this->redirect_uri = $uri;
        $this->api = new Hm_API_Curl();
    }

    /**
     * Build a URL to request an authorization
     * @param string $url host to request authorization from
     * @param string $scope oauth2 scope
     * @param string $state current state of the oauth2 flow
     * @param string $login_hint optional username
     * @return string
     */
    public function request_authorization_url($url, $scope, $state, $login_hint = false) {
        $res = sprintf('%s?response_type=code&amp;scope=%s&amp;state=%s&amp;'.
            'approval_prompt=force&amp;access_type=offline&amp;client_id=%s&amp;redirect_uri=%s',
            $url, $scope, $state, $this->client_id, $this->redirect_uri);
        if ($login_hint !== false) {
            $res .= '&amp;login_hint='.$login_hint;
        }
        return $res;
    }

    /**
     * Use curl to exchange an authorization code for a token
     * @param string $url url to post to
     * @param string $authorization_code oauth2 auth code
     * @param array $headers HTTP headers to add to the request
     * @return array
     */
    public function request_token($url, $authorization_code, $headers = []) {
        return $this->api->command($url, $headers, array('code' => $authorization_code, 'client_id' => $this->client_id,
            'client_secret' => $this->client_secret, 'redirect_uri' => $this->redirect_uri, 'grant_type' => 'authorization_code'));
    }

    /**
     * Use curl to refresh an access token
     * @param string $url url to to post to
     * @param string $refresh_token oauth2 refresh token
     * @return array
     */
    public function refresh_token($url, $refresh_token) {
        return $this->api->command($url, [], array('client_id' => $this->client_id, 'client_secret' => $this->client_secret,
            'refresh_token' => $refresh_token, 'grant_type' => 'refresh_token'));
    }

    /**
     * Resolve a configured OAuth provider for a stored mail server.
     *
     * Legacy Microsoft records using shared hostnames are intentionally not
     * guessed. They must be reconnected once so the provider can be persisted.
     *
     * @param array $server mail server details
     * @return string provider identifier or an empty string
     */
    private static function server_provider($server) {
        if (!empty($server['oauth2_provider']) && is_string($server['oauth2_provider'])) {
            return mb_strtolower($server['oauth2_provider']);
        }
        $host = mb_strtolower(trim((string) ($server['server'] ?? '')));
        $legacy_hosts = array(
            'imap.gmail.com' => 'gmail',
            'smtp.gmail.com' => 'gmail',
            'imap-mail.outlook.com' => 'outlook',
            'smtp-mail.outlook.com' => 'outlook',
            'imap-mail.office365.com' => 'office365',
        );
        return $legacy_hosts[$host] ?? '';
    }

    /**
     * Parse a provider expires_in value without accepting booleans or floats.
     *
     * @param mixed $value expiry duration returned by the provider
     * @return int|false positive seconds or false
     */
    private static function expiry_seconds($value) {
        if (is_int($value)) {
            return $value > 0 ? $value : false;
        }
        if (!is_string($value) || !preg_match('/^[1-9][0-9]*$/D', $value)) {
            return false;
        }
        $seconds = (int) $value;
        if ($seconds <= 0 || (string) $seconds !== $value) {
            return false;
        }
        return $seconds;
    }

    /**
     * Refresh an expired mail access token using its persisted provider.
     *
     * @param array $server mail server details
     * @param object $config site configuration
     * @param int|null $now current Unix timestamp, injectable for tests
     * @return array expiration, access token and retained or rotated refresh token
     */
    public static function refresh_server($server, $config, $now = null) {
        $now = $now ?? time();
        if (!array_key_exists('expiration', $server) || (int) $server['expiration'] > $now) {
            return array();
        }

        $provider = self::server_provider($server);
        $details = $provider !== '' ? $config->get($provider, array()) : array();
        $refresh_token = $server['refresh_token'] ?? '';
        if (!is_array($details) || empty($details['client_id']) || empty($details['client_secret']) ||
            empty($details['client_uri']) || empty($details['refresh_uri']) ||
            !is_string($refresh_token) || $refresh_token === '') {
            Hm_Msgs::add('Mail authorization is missing. Reconnect the account.', 'danger');
            return array();
        }

        $oauth2 = new self($details['client_id'], $details['client_secret'], $details['client_uri']);
        $result = $oauth2->refresh_token($details['refresh_uri'], $refresh_token);
        $seconds = is_array($result) ? self::expiry_seconds($result['expires_in'] ?? null) : false;
        if (!is_array($result) || !isset($result['access_token']) ||
            !is_string($result['access_token']) || $result['access_token'] === '' ||
            $seconds === false || $seconds > PHP_INT_MAX - $now) {
            Hm_Msgs::add('Could not refresh mail authorization. Reconnect the account.', 'danger');
            return array();
        }
        if (array_key_exists('refresh_token', $result)) {
            if (!is_string($result['refresh_token']) || $result['refresh_token'] === '') {
                Hm_Msgs::add('Could not refresh mail authorization. Reconnect the account.', 'danger');
                return array();
            }
            $refresh_token = $result['refresh_token'];
        }
        return array($now + $seconds, $result['access_token'], $refresh_token, $provider);
    }
}
