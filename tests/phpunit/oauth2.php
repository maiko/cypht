<?php

use PHPUnit\Framework\TestCase;


class Hm_Test_Oauth2 extends TestCase {

    public $oauth2;
    public function setUp(): void {
        $this->oauth2 = new Hm_Oauth2('client_id', 'secret', 'uri');
    }
    /**
     * @preserveGlobalState disabled
     * @runInSeparateProcess
     */
    public function test_request_authorization_url() {
        $res = $this->oauth2->request_authorization_url(
            'https://login.example.test/oauth',
            'mail read',
            'state+/=',
            'user+tag@example.test'
        );
        $this->assertSame(
            'https://login.example.test/oauth?response_type=code&amp;scope=mail%20read&amp;state=state%2B%2F%3D&amp;client_id=client_id&amp;redirect_uri=uri&amp;login_hint=user%2Btag%40example.test',
            $res
        );
        $this->assertStringNotContainsString('access_type', $res);
        $this->assertStringNotContainsString('prompt=', $res);
    }

    public function test_google_authorization_requests_offline_consent() {
        $res = $this->oauth2->request_authorization_url(
            'https://accounts.google.com/o/oauth2/v2/auth',
            'scope',
            'state'
        );

        $this->assertStringContainsString('&amp;prompt=consent', $res);
        $this->assertStringContainsString('&amp;access_type=offline', $res);
    }

    public function test_authorization_url_preserves_existing_query_and_fragment() {
        $res = $this->oauth2->request_authorization_url(
            'https://login.example.test/oauth?audience=mail&tenant=example&mode=login#provider-fragment',
            'scope',
            'state'
        );

        $this->assertStringStartsWith(
            'https://login.example.test/oauth?audience=mail&amp;tenant=example&amp;mode=login&amp;response_type=code',
            $res
        );
        $this->assertStringNotContainsString('&amp;amp;', $res);
        $this->assertStringEndsWith('#provider-fragment', $res);
    }

    public function test_google_parameters_require_exact_provider_host() {
        $res = $this->oauth2->request_authorization_url(
            'https://accounts.google.com.evil.test/oauth',
            'scope',
            'state'
        );

        $this->assertStringNotContainsString('access_type', $res);
        $this->assertStringNotContainsString('prompt=', $res);
    }

    public function test_missing_endpoint_preserves_legacy_query_shape() {
        $oauth2 = new Hm_Oauth2('client_id', 'secret', null);
        $res = $oauth2->request_authorization_url(null, 'scope', 'state');

        $this->assertStringStartsWith('?response_type=code', $res);
        $this->assertStringContainsString('&amp;redirect_uri=', $res);
    }
    /**
     * @preserveGlobalState disabled
     * @runInSeparateProcess
     */
    public function test_refresh_token() {
        $res = $this->oauth2->refresh_token('url', 'refresh_token');
        $this->assertEquals(array('unit' => 'test'), $res);
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
        unset($this->oauth2);
    }
}
