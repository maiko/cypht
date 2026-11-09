<?php

use PHPUnit\Framework\TestCase;


class Hm_Test_Oauth2 extends TestCase {

    public $oauth2;

    private function provider_config($id) {
        $config = new Hm_Mock_Config();
        $config->set($id, array(
            'client_id' => $id.'-client',
            'client_secret' => $id.'-secret',
            'client_uri' => 'https://cypht.example/',
            'refresh_uri' => 'https://provider.example/token',
        ));
        return $config;
    }

    public function setUp(): void {
        $this->oauth2 = new Hm_Oauth2('client_id', 'secret', 'uri');
    }
    /**
     * @preserveGlobalState disabled
     * @runInSeparateProcess
     */
    public function test_request_authorization_url() {
        $res = $this->oauth2->request_authorization_url('url', 'scope', 'state', 'hint');
        $this->assertEquals('url?response_type=code&amp;scope=scope&amp;state=state&amp;approval_prompt=force&amp;access_type=offline&amp;client_id=client_id&amp;redirect_uri=uri&amp;login_hint=hint', $res);
    }
    /**
     * @preserveGlobalState disabled
     * @runInSeparateProcess
     */
    public function test_refresh_token() {
        $res = $this->oauth2->refresh_token('url', 'refresh_token');
        $this->assertEquals(array('unit' => 'test'), $res);
    }

    public function test_refresh_server_uses_provider_identity_and_rotates_refresh_token() {
        Hm_Functions::$exec_res = json_encode(array(
            'access_token' => 'new-access-token',
            'expires_in' => 3600,
            'refresh_token' => 'new-refresh-token',
        ));
        $server = array(
            'server' => 'outlook.office365.com',
            'expiration' => 1,
            'oauth2_provider' => 'outlook',
            'refresh_token' => 'old-refresh-token',
        );

        $this->assertSame(
            array(4600, 'new-access-token', 'new-refresh-token', 'outlook'),
            Hm_Oauth2::refresh_server($server, $this->provider_config('outlook'), 1000)
        );
    }

    public function test_refresh_server_retains_existing_refresh_token_when_omitted() {
        Hm_Functions::$exec_res = json_encode(array(
            'access_token' => 'new-access-token',
            'expires_in' => '3600',
        ));
        $server = array(
            'server' => 'imap.gmail.com',
            'expiration' => 1,
            'refresh_token' => 'existing-refresh-token',
        );

        $this->assertSame(
            array(4600, 'new-access-token', 'existing-refresh-token', 'gmail'),
            Hm_Oauth2::refresh_server($server, $this->provider_config('gmail'), 1000)
        );
    }

    public function test_refresh_server_refuses_ambiguous_legacy_microsoft_record() {
        $server = array(
            'server' => 'outlook.office365.com',
            'expiration' => 1,
            'refresh_token' => 'refresh-token',
        );

        $this->assertSame(array(), Hm_Oauth2::refresh_server(
            $server,
            $this->provider_config('office365'),
            1000
        ));
    }

    public function test_refresh_server_does_not_fallback_from_unknown_explicit_provider() {
        $config = $this->provider_config('gmail');
        $server = array(
            'server' => 'imap.gmail.com',
            'expiration' => 1,
            'oauth2_provider' => 'missing-provider',
            'refresh_token' => 'refresh-token',
        );

        $this->assertSame(array(), Hm_Oauth2::refresh_server($server, $config, 1000));
    }

    public function test_refresh_server_rejects_malformed_token_response() {
        Hm_Functions::$exec_res = json_encode(array(
            'access_token' => 'new-access-token',
            'expires_in' => true,
        ));
        $server = array(
            'server' => 'imap.gmail.com',
            'expiration' => 1,
            'refresh_token' => 'refresh-token',
        );

        $this->assertSame(array(), Hm_Oauth2::refresh_server(
            $server,
            $this->provider_config('gmail'),
            1000
        ));
    }

    public function test_refresh_server_leaves_unexpired_token_unchanged() {
        $server = array(
            'server' => 'imap.gmail.com',
            'expiration' => 1001,
            'refresh_token' => 'refresh-token',
        );

        $this->assertSame(array(), Hm_Oauth2::refresh_server(
            $server,
            $this->provider_config('gmail'),
            1000
        ));
    }
    /**
     * @preserveGlobalState disabled
     * @runInSeparateProcess
     */
    public function test_request_token() {
        $res = $this->oauth2->request_token('url', 'auth_code');
        $this->assertEquals(array('unit' => 'test'), $res);
    }
    public function tearDown(): void {
        Hm_Functions::$exec_res = '{"unit":"test"}';
        unset($this->oauth2);
    }
}
