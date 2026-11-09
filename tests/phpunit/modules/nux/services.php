<?php

use PHPUnit\Framework\TestCase;

require_once APP_PATH.'modules/nux/modules.php';

class Hm_Test_Nux_Oauth_Services extends TestCase {

    public function test_microsoft_services_use_v2_endpoints_and_mail_scopes() {
        $providers = config('oauth2');
        $scope = 'https://outlook.office.com/IMAP.AccessAsUser.All ' .
            'https://outlook.office.com/SMTP.Send offline_access';

        foreach (array('outlook', 'office365') as $provider) {
            $this->assertSame(
                'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
                $providers[$provider]['auth_uri']
            );
            $this->assertSame(
                'https://login.microsoftonline.com/common/oauth2/v2.0/token',
                $providers[$provider]['token_uri']
            );
            $this->assertSame($providers[$provider]['token_uri'], $providers[$provider]['refresh_uri']);
            $this->assertSame($scope, Nux_Quick_Services::details($provider)['scope']);
        }
    }

    public function test_environment_example_matches_microsoft_defaults() {
        $example = file_get_contents(APP_PATH.'.env.example');
        $auth = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize';
        $token = 'https://login.microsoftonline.com/common/oauth2/v2.0/token';

        $this->assertStringContainsString('OUTLOOK_AUTH_URI='.$auth, $example);
        $this->assertStringContainsString('OUTLOOK_TOKEN_URI='.$token, $example);
        $this->assertStringContainsString('OUTLOOK_REFRESH_URI='.$token, $example);
        $this->assertStringContainsString('OFFICE365_AUTH_URI='.$auth, $example);
        $this->assertStringContainsString('OFFICE365_TOKEN_URI='.$token, $example);
        $this->assertStringContainsString('OFFICE365_REFRESH_URI='.$token, $example);
    }

    public function test_microsoft_services_keep_their_documented_mail_hosts() {
        $outlook = Nux_Quick_Services::details('outlook');
        $office365 = Nux_Quick_Services::details('office365');

        foreach (array($outlook, $office365) as $service) {
            $this->assertSame('outlook.office365.com', $service['server']);
            $this->assertSame(993, $service['port']);
            $this->assertTrue($service['tls']);
            $this->assertSame(587, $service['smtp']['port']);
            $this->assertFalse($service['smtp']['tls']);
        }
        $this->assertSame('smtp-mail.outlook.com', $outlook['smtp']['server']);
        $this->assertSame('smtp.office365.com', $office365['smtp']['server']);
    }
}
