<?php

use PHPUnit\Framework\TestCase;

class Hm_Test_Hm_SMTP extends TestCase {

    public function setUp(): void {
        require_once APP_PATH.'modules/smtp/hm-smtp.php';
    }

    public function test_auth_mechanisms_are_trimmed_before_selection() {
        $smtp = new Hm_SMTP(array(
            'server' => 'smtp.example.test',
            'username' => 'fixture@example.test',
            'password' => 'fixture',
            'auth' => 'xoauth2',
        ));
        $smtp->capabilities(array(
            array('250', array('AUTH', 'PLAIN', "XOAUTH2\r\n")),
        ));

        $this->assertSame('xoauth2', $smtp->choose_auth());
    }
}
