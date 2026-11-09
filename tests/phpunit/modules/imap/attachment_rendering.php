<?php

use PHPUnit\Framework\TestCase;

require_once __DIR__.'/../../bootstrap.php';
require_once APP_PATH.'modules/core/message_functions.php';
require_once APP_PATH.'modules/imap/functions.php';

class Hm_Attachment_Render_Output {
    private $values;

    public function __construct($values = array()) {
        $this->values = $values;
    }

    public function get($name, $default = false) {
        return $this->values[$name] ?? $default;
    }

    public function html_safe($value) {
        return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
    }

    public function trans($value) {
        return $value;
    }
}

class Hm_Test_Attachment_Rendering extends TestCase {
    private function render_output($allow_delete = false) {
        return new Hm_Attachment_Render_Output(array(
            'is_mobile' => true,
            'simple_msg_part_view' => false,
            'allow_delete_attachment' => $allow_delete,
        ));
    }

    private function render($parts, $allow_delete = false) {
        return format_msg_part_section(
            $parts,
            $this->render_output($allow_delete),
            '1',
            'page=download',
            'page=remove'
        );
    }

    private function attachment($name, $file_attributes = true) {
        return array(
            'type' => 'application',
            'subtype' => 'octet-stream',
            'size' => 101,
            'description' => $name,
            'file_attributes' => $file_attributes
                ? array('attachment' => array('filename', $name))
                : array(),
            'disposition' => array('attachment' => array('filename', $name)),
        );
    }

    public function test_mobile_view_renders_disposition_only_attachment() {
        $html = $this->render(array('1' => $this->attachment('mobile.txt', false)));

        $this->assertStringContainsString('mobile.txt', $html);
        $this->assertStringContainsString('data-src="?page=download&amp;imap_msg_part=1"', $html);
    }

    public function test_nested_attachments_append_without_hiding_preceding_rows() {
        $html = $this->render(array(
            '1' => $this->attachment('first.pdf'),
            '2' => array(
                'type' => 'multipart',
                'subs' => array('2.1' => $this->attachment('nested.txt', false)),
            ),
        ));

        $this->assertStringContainsString('first.pdf', $html);
        $this->assertStringContainsString('nested.txt', $html);
    }

    public function test_attachment_rows_close_when_delete_control_is_disabled() {
        $html = $this->render(array('1' => $this->attachment('balanced.pdf')));

        $this->assertSame(1, substr_count($html, '<tr>'));
        $this->assertSame(1, substr_count($html, '</tr>'));
        $this->assertStringNotContainsString('remove_attachment', $html);
        $this->assertStringNotContainsString('</td></td>', $html);
    }

    public function test_attachment_rows_close_with_delete_control_enabled() {
        $html = $this->render(array('1' => $this->attachment('removable.pdf')), true);

        $this->assertSame(1, substr_count($html, '<tr>'));
        $this->assertSame(1, substr_count($html, '</tr>'));
        $this->assertStringContainsString('remove_attachment', $html);
    }

    public function test_attachment_filename_is_escaped() {
        $html = $this->render(array('1' => $this->attachment('<script>.txt')));

        $this->assertStringContainsString('&lt;script&gt;.txt', $html);
        $this->assertStringNotContainsString('<script>', $html);
    }

    public function test_non_attachment_body_remains_hidden_in_simple_view() {
        $html = $this->render(array('1' => array(
            'type' => 'text',
            'subtype' => 'plain',
            'size' => 10,
            'description' => 'body.txt',
            'file_attributes' => array(),
            'disposition' => array(),
        )));

        $this->assertSame('', $html);
    }
}
