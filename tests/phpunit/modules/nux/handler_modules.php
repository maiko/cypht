<?php

use PHPUnit\Framework\TestCase;

require_once __DIR__.'/../../helpers.php';
require_once APP_PATH.'modules/nux/modules.php';

class Hm_Nux_Mock_Session extends Hm_Mock_Session {
    public $cookies = array();

    public function secure_cookie($request, $name, $value, $path='', $domain='') {
        $this->cookies[$name] = $value;
        return parent::secure_cookie($request, $name, $value, $path, $domain);
    }
}

class Hm_Test_Nux_Handler_Modules extends TestCase {

    private function oauth_details($id = 'test-oauth') {
        return array(
            'id' => $id,
            'email' => 'user@example.com',
            'name' => 'Test OAuth',
            'auth' => 'oauth2',
            'auth_uri' => 'https://provider.example/authorize',
            'token_uri' => 'https://provider.example/token',
            'client_id' => 'client-id',
            'client_secret' => 'client-secret',
            'redirect_uri' => 'https://cypht.example/',
            'scope' => 'mail',
            'server' => 'imap.example.com',
            'port' => 993,
            'tls' => true,
            'type' => 'imap',
        );
    }

    private function parent_with_session($session = null) {
        $parent = build_parent_mock();
        $parent->session = $session ?: new Hm_Mock_Session();
        $parent->cache = new Hm_Cache($parent->session, $parent->site_config);
        Hm_Server_Wrapper::init($parent->user_config, $parent->session);
        return $parent;
    }

    private function run_callback($session, $get) {
        $parent = $this->parent_with_session($session);
        $parent->request->get = $get;
        $handler = new Hm_Handler_process_oauth2_authorization($parent, 'home');
        $handler->process();
        return $parent;
    }

    /**
     * @preserveGlobalState disabled
     * @runInSeparateProcess
     */
    public function test_oauth_selection_creates_transaction_but_password_selection_does_not() {
        Nux_Quick_Services::add('test-oauth', $this->oauth_details());
        Nux_Quick_Services::add('test-password', array(
            'id' => 'test-password',
            'name' => 'Password service',
            'auth' => 'login',
        ));
        $parent = $this->parent_with_session();
        $parent->request->post = array('nux_service' => 'test-oauth', 'nux_email' => 'user@example.com');
        $oauth = new Hm_Handler_process_nux_service($parent, 'test');
        $oauth->process();

        $details = $oauth->get('nux_add_service_details');
        $this->assertArrayHasKey('oauth2_state', $details);
        $this->assertCount(1, $parent->session->get('nux_oauth_transactions'));

        $parent->request->post = array('nux_service' => 'test-password', 'nux_email' => 'user@example.com');
        $password = new Hm_Handler_process_nux_service($parent, 'test');
        $password->process();

        $this->assertArrayNotHasKey('oauth2_state', $password->get('nux_add_service_details'));
        $this->assertCount(1, $parent->session->get('nux_oauth_transactions'));
    }

    /**
     * @preserveGlobalState disabled
     * @runInSeparateProcess
     */
    public function test_service_details_route_does_not_start_oauth_transaction() {
        Nux_Quick_Services::add('test-oauth-details', $this->oauth_details('test-oauth-details'));
        $parent = $this->parent_with_session();
        $parent->request->post = array('nux_service' => 'test-oauth-details');

        $handler = new Hm_Handler_get_nux_service_details($parent, 'test');
        $handler->process();

        $this->assertFalse($parent->session->get('nux_oauth_transactions', false));
        $this->assertArrayNotHasKey('oauth2_state', $handler->get('nux_add_service_details'));
    }

    /**
     * @preserveGlobalState disabled
     * @runInSeparateProcess
     */
    public function test_unrelated_callback_state_is_ignored() {
        $session = new Hm_Mock_Session();
        nux_oauth2_create_transaction($this->oauth_details(), $session);

        $this->run_callback($session, array('state' => 'another-module-state', 'code' => 'code'));

        $this->assertCount(1, $session->get('nux_oauth_transactions'));
        $this->assertTrue($session->loaded);
        $this->assertFalse($session->cookie_set);
    }

    /**
     * @preserveGlobalState disabled
     * @runInSeparateProcess
     * @dataProvider valid_expiries
     */
    public function test_success_uses_transaction_account_and_persists_consumption($expires_in) {
        $session = new Hm_Mock_Session();
        $state = nux_oauth2_create_transaction($this->oauth_details(), $session);
        $session->set('nux_add_service_details', array(
            'id' => 'other-provider',
            'email' => 'other@example.com',
        ));
        Hm_Functions::$exec_res = json_encode(array(
            'access_token' => 'access-token',
            'refresh_token' => 'refresh-token',
            'expires_in' => $expires_in,
        ));

        $this->run_callback($session, array('state' => $state, 'code' => 'authorization-code'));

        $this->assertSame(array(), $session->get('nux_oauth_transactions'));
        $servers = Hm_IMAP_List::dump();
        $this->assertCount(1, $servers);
        $server = reset($servers);
        $this->assertSame('user@example.com', $server['user']);
        $this->assertSame('other-provider', $session->get('nux_add_service_details')['id']);
        $this->assertFalse($session->loaded);
        $this->assertTrue($session->cookie_set);
    }

    public static function valid_expiries() {
        return array(
            'native integer' => array(3600),
            'canonical integer string' => array('3600'),
        );
    }

    /**
     * @preserveGlobalState disabled
     * @runInSeparateProcess
     */
    public function test_expired_callback_consumes_and_persists_transaction() {
        $session = new Hm_Mock_Session();
        $state = nux_oauth2_create_transaction(
            $this->oauth_details(),
            $session,
            time() - NUX_OAUTH2_TRANSACTION_TTL - 1
        );

        $this->run_callback($session, array('state' => $state, 'code' => 'authorization-code'));

        $this->assertSame(array(), $session->get('nux_oauth_transactions'));
        $this->assertFalse($session->loaded);
        $this->assertTrue($session->cookie_set);
    }

    /**
     * @preserveGlobalState disabled
     * @runInSeparateProcess
     */
    public function test_denial_consumes_and_persists_transaction() {
        $session = new Hm_Mock_Session();
        $state = nux_oauth2_create_transaction($this->oauth_details(), $session);

        $this->run_callback($session, array('state' => $state, 'error' => 'access_denied'));

        $this->assertSame(array(), $session->get('nux_oauth_transactions'));
        $this->assertFalse($session->loaded);
        $this->assertTrue($session->cookie_set);
    }

    /**
     * @preserveGlobalState disabled
     * @runInSeparateProcess
     * @dataProvider invalid_token_responses
     */
    public function test_token_failure_consumes_transaction_without_adding_servers($result) {
        $session = new Hm_Nux_Mock_Session();
        $details = $this->oauth_details();
        $details['smtp'] = array(
            'server' => 'smtp.example.com',
            'port' => 465,
            'tls' => true,
        );
        $state = nux_oauth2_create_transaction($details, $session);
        Hm_Functions::$exec_res = json_encode($result, JSON_PRESERVE_ZERO_FRACTION);

        $this->run_callback($session, array('state' => $state, 'code' => 'authorization-code'));

        $this->assertSame(array(), $session->get('nux_oauth_transactions'));
        $this->assertSame(array(), Hm_IMAP_List::dump());
        $this->assertSame(array(), Hm_SMTP_List::dump());
        $this->assertFalse($session->loaded);
        $this->assertTrue($session->cookie_set);
        $messages = json_decode(base64_decode($session->cookies['hm_msgs']), true);
        $failure_messages = array_values(array_filter($messages, function($message) {
            return $message['text'] === 'An Error Occurred';
        }));
        $this->assertCount(1, $failure_messages);
        $this->assertSame('danger', $failure_messages[0]['type']);
    }

    public static function invalid_token_responses() {
        return array(
            'empty response' => array(array()),
            'access token only' => array(array('access_token' => 'access-token')),
            'empty access token' => array(array(
                'access_token' => '',
                'expires_in' => 3600,
                'refresh_token' => 'refresh-token',
            )),
            'zero expiry' => array(array(
                'access_token' => 'access-token',
                'expires_in' => 0,
                'refresh_token' => 'refresh-token',
            )),
            'missing refresh token' => array(array(
                'access_token' => 'access-token',
                'expires_in' => 3600,
            )),
            'empty refresh token' => array(array(
                'access_token' => 'access-token',
                'expires_in' => 3600,
                'refresh_token' => '',
            )),
            'boolean expiry' => array(array(
                'access_token' => 'access-token',
                'expires_in' => true,
                'refresh_token' => 'refresh-token',
            )),
            'float expiry' => array(array(
                'access_token' => 'access-token',
                'expires_in' => 1.0,
                'refresh_token' => 'refresh-token',
            )),
            'oversized decimal expiry' => array(array(
                'access_token' => 'access-token',
                'expires_in' => '9999999999999999999999999999999999999999',
                'refresh_token' => 'refresh-token',
            )),
            'non-string access token' => array(array(
                'access_token' => 123,
                'expires_in' => 3600,
                'refresh_token' => 'refresh-token',
            )),
            'non-string refresh token' => array(array(
                'access_token' => 'access-token',
                'expires_in' => 3600,
                'refresh_token' => array('refresh-token'),
            )),
        );
    }

    /**
     * @preserveGlobalState disabled
     * @runInSeparateProcess
     */
    public function test_mismatch_and_replay_are_terminal_and_persisted() {
        $session = new Hm_Mock_Session();
        $state = nux_oauth2_create_transaction($this->oauth_details(), $session);
        $mismatch = substr($state, 0, -1).(substr($state, -1) === 'A' ? 'B' : 'A');
        Hm_Functions::$exec_res = json_encode([
            'access_token' => 'access-token',
            'refresh_token' => 'refresh-token',
            'expires_in' => 3600,
        ]);

        $this->run_callback($session, array('state' => $mismatch, 'code' => 'authorization-code'));
        $this->assertSame(array(), $session->get('nux_oauth_transactions'));
        $this->assertFalse($session->loaded);
        $this->assertSame([], Hm_IMAP_List::dump());

        $session->loaded = true;
        $this->run_callback($session, array('state' => $state, 'code' => 'authorization-code'));
        $this->assertSame(array(), $session->get('nux_oauth_transactions'));
        $this->assertFalse($session->loaded);
        $this->assertSame([], Hm_IMAP_List::dump());
    }
}
