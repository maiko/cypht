<?php

use PHPUnit\Framework\TestCase;

require_once APP_PATH.'modules/nux/functions.php';

/**
 * Tests for nux module functions
 */
class Hm_Test_Nux_Functions extends TestCase {

    private function oauth_details($email = 'user@example.com', $id = 'gmail') {
        return array(
            'id' => $id,
            'email' => $email,
            'name' => 'Test OAuth',
            'auth' => 'oauth2',
            'auth_uri' => 'https://provider.example/authorize',
            'token_uri' => 'https://provider.example/token',
            'client_id' => 'client-id',
            'client_secret' => 'client-secret',
            'redirect_uri' => 'https://cypht.example/',
            'scope' => 'mail',
        );
    }

    public function test_convert_to_boolean() {
        $this->assertTrue(convert_to_boolean('true'));
        $this->assertTrue(convert_to_boolean('TRUE'));
        $this->assertTrue(convert_to_boolean('Yes'));
        $this->assertTrue(convert_to_boolean(' 1 '));
        $this->assertFalse(convert_to_boolean('false'));
        $this->assertFalse(convert_to_boolean('FALSE'));
        $this->assertFalse(convert_to_boolean('No'));
        $this->assertFalse(convert_to_boolean('0'));
        $this->assertSame('maybe', convert_to_boolean('maybe'));
        $this->assertSame('', convert_to_boolean(''));
        $this->assertSame(1, convert_to_boolean(1));
        $this->assertNull(convert_to_boolean(null));
    }

    public function test_parse_csv_with_headers_converts_spreadsheet_booleans() {
        $file = tempnam(sys_get_temp_dir(), 'cypht_csv');
        file_put_contents($file, "name;server;hide_from_combined_view;tls\nBox 1;imap.example.com;FALSE;TRUE\nBox 2;imap.example.com;false;true\n");
        $rows = parse_csv_with_headers($file);
        unlink($file);

        $this->assertCount(2, $rows);
        $this->assertSame('Box 1', $rows[0]['name']);
        $this->assertFalse($rows[0]['hide_from_combined_view']);
        $this->assertTrue($rows[0]['tls']);
        $this->assertFalse($rows[1]['hide_from_combined_view']);
        $this->assertTrue($rows[1]['tls']);
    }

    public function test_oauth_states_are_distinct_and_not_stored_in_plaintext() {
        $session = new Hm_Mock_Session();
        $details = $this->oauth_details();

        $first = nux_oauth2_create_transaction($details, $session, 1000);
        $second = nux_oauth2_create_transaction($details, $session, 1001);

        $this->assertMatchesRegularExpression('/^nux\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$/', $first);
        $this->assertNotSame($first, $second);
        $transactions = $session->get('nux_oauth_transactions');
        $this->assertCount(2, $transactions);
        $this->assertStringNotContainsString($first, serialize($transactions));
        $this->assertStringNotContainsString($second, serialize($transactions));
    }

    public function test_oauth_transaction_success_is_one_time() {
        $session = new Hm_Mock_Session();
        $details = $this->oauth_details();
        $state = nux_oauth2_create_transaction($details, $session, 1000);

        $result = nux_oauth2_consume_transaction($state, $session, 1001);
        $replay = nux_oauth2_consume_transaction($state, $session, 1002);

        $this->assertSame('valid', $result['status']);
        $this->assertSame($details, $result['details']);
        $this->assertSame('missing', $replay['status']);
        $this->assertSame(array(), $session->get('nux_oauth_transactions'));
    }

    public function test_oauth_transaction_mismatch_consumes_target() {
        $session = new Hm_Mock_Session();
        $state = nux_oauth2_create_transaction($this->oauth_details(), $session, 1000);
        $last = substr($state, -1);
        $mismatch = substr($state, 0, -1).($last === 'A' ? 'B' : 'A');

        $result = nux_oauth2_consume_transaction($mismatch, $session, 1001);
        $replay = nux_oauth2_consume_transaction($state, $session, 1002);

        $this->assertSame('mismatch', $result['status']);
        $this->assertSame('missing', $replay['status']);
    }

    public function test_oauth_transaction_expiry_consumes_target() {
        $session = new Hm_Mock_Session();
        $state = nux_oauth2_create_transaction($this->oauth_details(), $session, 1000);

        $result = nux_oauth2_consume_transaction($state, $session, 1000 + NUX_OAUTH2_TRANSACTION_TTL + 1);

        $this->assertSame('expired', $result['status']);
        $this->assertSame(array(), $session->get('nux_oauth_transactions'));
    }

    /**
     * @dataProvider transactionBindings
     */
    public function test_oauth_transaction_rejects_tampered_account_binding($field, $replacement) {
        $session = new Hm_Mock_Session();
        $state = nux_oauth2_create_transaction($this->oauth_details(), $session, 1000);
        $transactions = $session->get('nux_oauth_transactions');
        $id = array_key_first($transactions);
        $transactions[$id]['details'][$field] = $replacement;
        $session->set('nux_oauth_transactions', $transactions);

        $result = nux_oauth2_consume_transaction($state, $session, 1001);

        $this->assertSame('mismatch', $result['status']);
        $this->assertSame(array(), $session->get('nux_oauth_transactions'));
    }

    public static function transactionBindings() {
        return [
            'provider' => ['id', 'outlook'],
            'email' => ['email', 'other@example.com'],
        ];
    }

    public function test_oauth_transactions_support_independent_concurrent_tabs() {
        $session = new Hm_Mock_Session();
        $gmail = nux_oauth2_create_transaction($this->oauth_details('one@example.com', 'gmail'), $session, 1000);
        $outlook = nux_oauth2_create_transaction($this->oauth_details('two@example.com', 'outlook'), $session, 1001);

        $first = nux_oauth2_consume_transaction($gmail, $session, 1002);
        $this->assertSame('gmail', $first['details']['id']);
        $this->assertCount(1, $session->get('nux_oauth_transactions'));

        $second = nux_oauth2_consume_transaction($outlook, $session, 1003);
        $this->assertSame('outlook', $second['details']['id']);
        $this->assertSame(array(), $session->get('nux_oauth_transactions'));
    }

    public function test_oauth_transaction_queue_is_bounded() {
        $session = new Hm_Mock_Session();
        $states = array();
        for ($i = 0; $i <= NUX_OAUTH2_MAX_TRANSACTIONS; $i++) {
            $states[] = nux_oauth2_create_transaction(
                $this->oauth_details('user'.$i.'@example.com'),
                $session,
                1000 + $i
            );
        }

        $this->assertCount(NUX_OAUTH2_MAX_TRANSACTIONS, $session->get('nux_oauth_transactions'));
        $this->assertSame('missing', nux_oauth2_consume_transaction($states[0], $session, 1100)['status']);
        $this->assertSame('valid', nux_oauth2_consume_transaction(end($states), $session, 1100)['status']);
    }

    public function test_oauth_form_uses_transaction_state_and_fails_closed_without_it() {
        $details = $this->oauth_details();
        $details['oauth2_state'] = 'nux.test-id.test-secret';
        $mod = new Hm_Output_Test(array(), array());

        $form = oauth2_form($details, $mod);
        unset($details['oauth2_state']);

        $this->assertStringContainsString('state=nux.test-id.test-secret', $form);
        $this->assertSame('', oauth2_form($details, $mod));
    }
}
