<?php

use PHPUnit\Framework\TestCase;

/** Exercise the real response reader using only an in-memory synthetic mailbox. */
class Hm_IMAP_Message_List_Fixture extends Hm_IMAP {
    private $reply;

    public function __construct($reply) {
        parent::__construct();
        $this->reply = $reply;
        $this->handle = fopen('php://temp', 'w+');
        $this->state = 'authenticated';
        $this->use_cache = false;
    }

    public function send_command($command, $no_prefix = false) {
        if (!str_starts_with($command, 'UID FETCH ')) {
            throw new RuntimeException('Unexpected synthetic command');
        }
        $this->command_count++;
        ftruncate($this->handle, 0);
        rewind($this->handle);
        fwrite($this->handle, $this->reply.'A'.$this->command_count." OK FETCH completed\r\n");
        rewind($this->handle);
    }

    public function __destruct() {
        if (is_resource($this->handle)) {
            fclose($this->handle);
        }
    }
}

class Hm_Test_Hm_IMAP_Message_List extends TestCase {
    private function literal($content) {
        return '{'.strlen($content)."}\r\n".$content;
    }

    private function headers($subject = 'Synthetic fixture') {
        return 'BODY[HEADER.FIELDS (SUBJECT FROM DATE)] '.$this->literal(
            'Subject: '.$subject."\r\nFrom: fixture@example.invalid\r\n".
            "Date: Tue, 10 Nov 2026 00:00:00 +0000\r\n\r\n"
        );
    }

    private function preview($text) {
        return $this->literal("Content-Type: text/plain; charset=utf-8\r\n\r\n".$text);
    }

    private function fetch($attributes, $sequence = 1) {
        return '* '.$sequence.' FETCH ('.$attributes.")\r\n";
    }

    private function messages($reply, $includePreview = true) {
        $fixture = new Hm_IMAP_Message_List_Fixture($reply);
        return $fixture->get_message_list([7, 8], false, $includePreview, false, false);
    }

    public function testUidAndFlagsAfterPreviewAreRetained() {
        $rows = $this->messages($this->fetch($this->headers().
            ' BODY[TEXT]<0> '.$this->preview('Synthetic preview').' UID 7 FLAGS (\\Seen) RFC822.SIZE 200'));

        $this->assertSame([7], array_keys($rows));
        $this->assertSame('Synthetic fixture', trim($rows[7]['subject']));
        $this->assertSame('Synthetic preview', $rows[7]['preview_msg']);
        $this->assertSame('\\Seen', $rows[7]['flags']);
        $this->assertSame('200', $rows[7]['size']);
    }

    public function testPreviewBeforeHeadersDoesNotConsumeLaterAttributes() {
        $rows = $this->messages($this->fetch('BODY[TEXT]<0> '.$this->preview('Preview first').
            ' '.$this->headers().' UID 7'));

        $this->assertSame([7], array_keys($rows));
        $this->assertSame('Synthetic fixture', trim($rows[7]['subject']));
        $this->assertSame('Preview first', $rows[7]['preview_msg']);
    }

    public function testExistingUidFirstOrderIsPreserved() {
        $rows = $this->messages($this->fetch('UID 7 FLAGS (\\Seen) '.$this->headers().
            ' BODY[TEXT]<0> '.$this->preview('Preview last')));

        $this->assertSame([7], array_keys($rows));
        $this->assertSame('Preview last', $rows[7]['preview_msg']);
    }

    public function testPreviewLiteralCannotSupplyFetchAttributes() {
        $preview = 'UID 99 FLAGS (\\Deleted)';
        $rows = $this->messages($this->fetch($this->headers().
            ' BODY[TEXT]<0> '.$this->preview($preview).' UID 7 FLAGS (\\Seen)'));

        $this->assertSame([7], array_keys($rows));
        $this->assertSame($preview, $rows[7]['preview_msg']);
        $this->assertSame('\\Seen', $rows[7]['flags']);
    }

    public function testEmptyZeroAndParenthesisLiteralsPreserveUid() {
        foreach (['', '0', ')', 'UID', "Multibyte é\r\nsecond line"] as $preview) {
            $rows = $this->messages($this->fetch($this->headers().
                ' BODY[TEXT]<0> '.$this->literal($preview).' UID 7 FLAGS (\\Seen)'));

            $this->assertSame([7], array_keys($rows), 'Literal: '.json_encode($preview));
            $this->assertSame('\\Seen', $rows[7]['flags']);
        }
    }

    public function testQuotedPreviewAndMissingOriginPreserveUid() {
        foreach (['"Quoted preview"', '""', 'NIL'] as $value) {
            $rows = $this->messages($this->fetch($this->headers().' BODY[TEXT] '.$value.' UID 7'));

            $this->assertSame([7], array_keys($rows));
        }
    }

    public function testHeaderOnlyResponsePreservesUidLast() {
        $rows = $this->messages($this->fetch($this->headers().' UID 7'), false);

        $this->assertSame([7], array_keys($rows));
        $this->assertSame('Synthetic fixture', trim($rows[7]['subject']));
        $this->assertSame('', $rows[7]['preview_msg']);
    }

    public function testBodystructureEmptyAndZeroValuesDoNotChangeRowParsing() {
        $rows = $this->messages($this->fetch(
            'BODYSTRUCTURE ("TEXT" "PLAIN" ("CHARSET" "UTF-8") "" NIL "7BIT" 0 0) '.
            $this->headers().' BODY[TEXT]<0> '.$this->preview('Bodystructure fixture').' UID 7'
        ));

        $this->assertSame([7], array_keys($rows));
        $this->assertSame('Bodystructure fixture', $rows[7]['preview_msg']);
        $this->assertSame('', $rows[7]['type_msg']);
    }

    public function testMissingPreviewDoesNotReusePreviousMessageText() {
        $rows = $this->messages($this->fetch('UID 7 '.$this->headers().
            ' BODY[TEXT]<0> '.$this->preview('First preview')).
            $this->fetch('UID 8 '.$this->headers('Second fixture'), 2));

        $this->assertSame([7, 8], array_keys($rows));
        $this->assertSame('First preview', $rows[7]['preview_msg']);
        $this->assertSame('', $rows[8]['preview_msg']);
    }
}
