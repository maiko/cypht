<?php

use PHPUnit\Framework\TestCase;

class Hm_IMAP_Parser_Fixture extends Hm_IMAP_Base {
    public function loadResponse(string $response, int $commandCount = 1): void {
        $this->handle = fopen('php://memory', 'r+');
        fwrite($this->handle, $response);
        rewind($this->handle);
        $this->command_count = $commandCount;
    }
}

class Hm_IMAP_Oauth_Fixture extends Hm_IMAP {
    public $sentCommands = [];
    private $queuedResponses = [];

    public function prepareResponses(array $responses, int $commandCount = 0): void {
        $this->command_count = $commandCount;
        $this->auth = 'xoauth2';
        $this->tls = true;
        $this->queuedResponses = $responses;
    }

    public function remainingResponses(): int {
        return count($this->queuedResponses);
    }

    public function get_capability() {
        return false;
    }

    public function enable() {
        return [];
    }

    public function is_supported($extension) {
        return false;
    }

    public function get_response($max=false, $chunked=false, $line_length=8192, $sort=false) {
        if (!$this->queuedResponses) {
            throw new UnderflowException('The IMAP client read an unexpected response');
        }
        return array_shift($this->queuedResponses);
    }

    public function send_command($command, $no_prefix=false) {
        if (!$no_prefix) {
            $this->command_count++;
        }
        $this->sentCommands[] = [
            'command' => $command,
            'no_prefix' => $no_prefix,
        ];
    }
}

class Hm_Test_IMAP_Oauth_Continuation extends TestCase {
    public function test_parser_stops_on_bare_continuation(): void {
        $imap = new Hm_IMAP_Parser_Fixture();
        $imap->loadResponse("+\r\nA1 NO AUTHENTICATIONFAILED\r\n");

        $this->assertSame(array('+'), $imap->get_response());
        $this->assertSame(array('A1 NO AUTHENTICATIONFAILED'), $imap->get_response());
    }

    public function test_parser_stops_on_arbitrary_continuation_payload(): void {
        $imap = new Hm_IMAP_Parser_Fixture();
        $imap->loadResponse("+ ab+c/d==\r\nA1 NO AUTHENTICATIONFAILED\r\n");

        $this->assertSame(array('+ ab+c/d=='), $imap->get_response());
        $this->assertSame(array('A1 NO AUTHENTICATIONFAILED'), $imap->get_response());
    }

    public function test_parser_does_not_treat_plus_prefixed_atom_as_continuation(): void {
        $imap = new Hm_IMAP_Parser_Fixture();
        $imap->loadResponse("+not-a-continuation\r\nA1 NO AUTHENTICATIONFAILED\r\n");

        $this->assertSame(
            array('+not-a-continuation', 'A1 NO AUTHENTICATIONFAILED'),
            $imap->get_response()
        );
    }

    public function test_authenticate_accepts_exact_current_tag_ok_at_line_start(): void {
        $imap = new Hm_IMAP_Oauth_Fixture();
        $imap->prepareResponses(array(array('A41 ok authenticated')), 40);

        $this->assertTrue($imap->authenticate('user@example.test', 'token'));
        $this->assertSame('authenticated', $imap->get_state());
    }

    public function test_authenticate_rejects_embedded_current_tag_ok(): void {
        $imap = new Hm_IMAP_Oauth_Fixture();
        $imap->prepareResponses(array(array('* OK banner includes A1 OK text')));

        $this->assertFalse($imap->authenticate('user@example.test', 'token'));
        $this->assertNotSame('authenticated', $imap->get_state());
    }

    public function test_authenticate_rejects_ok_prefix_without_status_boundary(): void {
        $imap = new Hm_IMAP_Oauth_Fixture();
        $imap->prepareResponses(array(array('A1 OKAY not-an-ok-completion')));

        $this->assertFalse($imap->authenticate('user@example.test', 'token'));
    }

    public function test_authenticate_rejects_different_command_tag(): void {
        $imap = new Hm_IMAP_Oauth_Fixture();
        $imap->prepareResponses(array(array('A2 OK wrong-command')));

        $this->assertFalse($imap->authenticate('user@example.test', 'token'));
    }

    public function test_authenticate_rejects_lowercase_client_tag(): void {
        $imap = new Hm_IMAP_Oauth_Fixture();
        $imap->prepareResponses(array(array('a1 OK wrong-tag-case')));

        $this->assertFalse($imap->authenticate('user@example.test', 'token'));
    }

    public function test_authenticate_completes_bare_oauth_continuation_once(): void {
        $this->assertOauthContinuationIsCompleted('+');
    }

    public function test_authenticate_completes_arbitrary_oauth_continuation_once(): void {
        $this->assertOauthContinuationIsCompleted('+ ab+c/d==');
    }

    public function test_authenticate_does_not_accept_ok_text_inside_continuation(): void {
        $this->assertOauthContinuationIsCompleted('+ A1 OK not-a-tag');
    }

    public function test_authenticate_ignores_plus_prefixed_non_continuation(): void {
        $imap = new Hm_IMAP_Oauth_Fixture();
        $imap->prepareResponses(array(
            array('+not-a-continuation'),
            array('A1 NO must-remain-unread'),
        ));

        $this->assertFalse($imap->authenticate('user@example.test', 'token'));
        $this->assertCount(1, $imap->sentCommands);
        $this->assertSame(1, $imap->remainingResponses());
    }

    private function assertOauthContinuationIsCompleted(string $continuation): void {
        $imap = new Hm_IMAP_Oauth_Fixture();
        $imap->prepareResponses(array(
            array($continuation),
            array('A1 NO AUTHENTICATIONFAILED'),
        ));

        $this->assertFalse($imap->authenticate('user@example.test', 'token'));
        $challenge = "user=user@example.test\x01auth=Bearer token\x01\x01";
        $this->assertSame([
            ['command' => 'AUTHENTICATE XOAUTH2 '.base64_encode($challenge)."\r\n", 'no_prefix' => false],
            ['command' => "\r\n", 'no_prefix' => true],
        ], $imap->sentCommands);
        $this->assertSame(0, $imap->remainingResponses());
    }
}
