<?php

use PHPUnit\Framework\TestCase;

require_once __DIR__.'/../../helpers.php';
require_once APP_PATH.'modules/nux/modules.php';

class Hm_Test_Nux_Oauth_Handler_Modules extends TestCase {

    private function parent_with_session($session) {
        $parent = build_parent_mock();
        $parent->session = $session;
        $parent->cache = new Hm_Cache($parent->session, $parent->site_config);
        Hm_Server_Wrapper::init($parent->user_config, $parent->session);
        return $parent;
    }

    /**
     * @preserveGlobalState disabled
     * @runInSeparateProcess
     */
    public function test_oauth_callback_stores_provider_on_paired_servers() {
        $session = new Hm_Mock_Session();
        $session->set('nux_add_service_details', array(
            'id' => 'outlook',
            'name' => 'Outlook.com',
            'server' => 'outlook.office365.com',
            'port' => 993,
            'tls' => true,
            'email' => 'user@example.com',
            'type' => 'imap',
            'client_id' => 'client-id',
            'client_secret' => 'client-secret',
            'redirect_uri' => 'https://cypht.example/',
            'token_uri' => 'https://provider.example/token',
            'smtp' => array(
                'server' => 'smtp-mail.outlook.com',
                'port' => 587,
                'tls' => false,
            ),
        ));
        Hm_Functions::$exec_res = json_encode(array(
            'access_token' => 'access-token',
            'refresh_token' => 'refresh-token',
            'expires_in' => 3600,
        ));
        $parent = $this->parent_with_session($session);
        $parent->request->get = array(
            'state' => 'nux_authorization',
            'code' => 'authorization-code',
        );
        Hm_IMAP_List::$added = array();
        Hm_SMTP_List::$added = array();

        $handler = new Hm_Handler_process_oauth2_authorization($parent, 'home');
        $handler->process();

        $this->assertCount(1, Hm_IMAP_List::$added);
        $this->assertCount(1, Hm_SMTP_List::$added);
        $this->assertSame('outlook', Hm_IMAP_List::$added[0]['oauth2_provider']);
        $this->assertSame('imap', Hm_IMAP_List::$added[0]['type']);
        $this->assertSame('outlook', Hm_SMTP_List::$added[0]['oauth2_provider']);
        $this->assertSame('smtp', Hm_SMTP_List::$added[0]['type']);
    }
}
