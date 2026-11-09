<?php

/**
 * NUX modules
 * @package modules
 * @subpackage nux
 */

if (!defined('DEBUG_MODE')) { die(); }

const NUX_OAUTH2_TRANSACTION_TTL = 600;
const NUX_OAUTH2_MAX_TRANSACTIONS = 5;

/**
 * Encode random bytes for use in an OAuth state parameter.
 * @subpackage nux/functions
 * @param string $value random bytes
 * @return string
 */
if (!hm_exists('nux_oauth2_base64url')) {
function nux_oauth2_base64url($value) {
    return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
}}

/**
 * Check whether a callback state belongs to the NUX OAuth flow.
 * @subpackage nux/functions
 * @param mixed $state callback state
 * @return bool
 */
if (!hm_exists('nux_oauth2_is_state')) {
function nux_oauth2_is_state($state) {
    return is_string($state) && substr($state, 0, 4) === 'nux.';
}}

/**
 * Remove expired or malformed OAuth transactions.
 * @subpackage nux/functions
 * @param array $transactions pending transactions
 * @param int $now current Unix timestamp
 * @return array
 */
if (!hm_exists('nux_oauth2_prune_transactions')) {
function nux_oauth2_prune_transactions($transactions, $now) {
    if (!is_array($transactions)) {
        return array();
    }
    foreach ($transactions as $id => $transaction) {
        if (!is_array($transaction) || !isset($transaction['created_at']) ||
            !is_int($transaction['created_at']) ||
            $transaction['created_at'] + NUX_OAUTH2_TRANSACTION_TTL < $now) {
            unset($transactions[$id]);
        }
    }
    return $transactions;
}}

/**
 * Create a one-time OAuth transaction bound to this session and account.
 *
 * Multiple tabs are supported independently. The oldest pending transaction is
 * evicted when the bounded per-session queue is full.
 *
 * @subpackage nux/functions
 * @param array $details provider and requested account details
 * @param object $session session interface
 * @param int|null $now current Unix timestamp, injectable for tests
 * @return string opaque state sent to the provider
 */
if (!hm_exists('nux_oauth2_create_transaction')) {
function nux_oauth2_create_transaction($details, $session, $now = null) {
    if (!is_array($details) || ($details['auth'] ?? false) !== 'oauth2' ||
        empty($details['id']) || empty($details['email'])) {
        throw new InvalidArgumentException('OAuth transaction requires a provider and requested email');
    }
    $now = $now ?? time();
    $transactions = nux_oauth2_prune_transactions(
        $session->get('nux_oauth_transactions', array()),
        $now
    );
    uasort($transactions, function($left, $right) {
        return $left['created_at'] <=> $right['created_at'];
    });
    while (count($transactions) >= NUX_OAUTH2_MAX_TRANSACTIONS) {
        array_shift($transactions);
    }

    do {
        $id = nux_oauth2_base64url(random_bytes(16));
    } while (array_key_exists($id, $transactions));
    $state = 'nux.'.$id.'.'.nux_oauth2_base64url(random_bytes(32));
    $transactions[$id] = array(
        'state_hash' => hash('sha256', $state),
        'provider' => (string) $details['id'],
        'email' => (string) $details['email'],
        'created_at' => $now,
        'details' => $details,
    );
    $session->set('nux_oauth_transactions', $transactions);
    return $state;
}}

/**
 * Consume and validate one OAuth transaction before token exchange.
 *
 * An identifiable transaction is removed before any validation result is
 * returned, including mismatch and expiry outcomes.
 *
 * @subpackage nux/functions
 * @param mixed $state callback state
 * @param object $session session interface
 * @param int|null $now current Unix timestamp, injectable for tests
 * @return array validation status and, on success, bound account details
 */
if (!hm_exists('nux_oauth2_consume_transaction')) {
function nux_oauth2_consume_transaction($state, $session, $now = null) {
    if (!nux_oauth2_is_state($state)) {
        return array('status' => 'unrecognized');
    }
    $now = $now ?? time();
    $transactions = $session->get('nux_oauth_transactions', array());
    if (!is_array($transactions)) {
        $transactions = array();
    }
    if (!preg_match('/^nux\.([A-Za-z0-9_-]{22})\.([A-Za-z0-9_-]{43})$/D', $state, $matches)) {
        $session->set('nux_oauth_transactions', nux_oauth2_prune_transactions($transactions, $now));
        return array('status' => 'invalid');
    }
    $id = $matches[1];
    if (!array_key_exists($id, $transactions) || !is_array($transactions[$id])) {
        $session->set('nux_oauth_transactions', nux_oauth2_prune_transactions($transactions, $now));
        return array('status' => 'missing');
    }

    $transaction = $transactions[$id];
    unset($transactions[$id]);
    $session->set('nux_oauth_transactions', nux_oauth2_prune_transactions($transactions, $now));

    if (!isset($transaction['created_at']) || !is_int($transaction['created_at']) ||
        $transaction['created_at'] + NUX_OAUTH2_TRANSACTION_TTL < $now) {
        return array('status' => 'expired');
    }
    if (!isset($transaction['state_hash']) ||
        !hash_equals((string) $transaction['state_hash'], hash('sha256', $state))) {
        return array('status' => 'mismatch');
    }
    $details = $transaction['details'] ?? array();
    if (!is_array($details) ||
        !isset($transaction['provider'], $transaction['email'], $details['id'], $details['email']) ||
        !hash_equals((string) $transaction['provider'], (string) $details['id']) ||
        !hash_equals((string) $transaction['email'], (string) $details['email'])) {
        return array('status' => 'mismatch');
    }
    return array('status' => 'valid', 'details' => $details);
}}

/**
 * Build a source list for sent folders
 * @subpackage nux/functions
 * @param string $file_path file path
 * @param string $delimiter csv delimiter with default ;
 * @return array
 */
if (!hm_exists('parse_csv_with_headers')) {
function parse_csv_with_headers($file_path, $delimiter = ';') {
    // Open the file
    $file = new SplFileObject($file_path);
    // Set the file to read as CSV
    $file->setFlags(SplFileObject::DROP_NEW_LINE);

    // Initialize an array to hold the rows
    $rows = [];
    $is_first_line = true;
    $header = [];
    // Loop through each line in the CSV file
    while (!$file->eof()) {
        // Get the line as a string
        $line = $file->fgets();

        // Skip empty lines (e.g., due to trailing newlines)
        if ($line === [null] || $line === false) {
            continue;
        }

        // Split the line into an array using the specified delimiter
        $fields = explode($delimiter, $line);
        // Process the header line
        if ($is_first_line) {
            $header = $fields;
            $is_first_line = false;
        } else {
            // Ensure that the number of fields matches the header count
            if (count($fields) === count($header)) {
                // Combine the header and fields into an associative array
                $line_data = array_combine($header, $fields);
                foreach ($line_data as $key => $value) {
                    $line_data[$key] = convert_to_boolean($value);
                }
                $rows[] = $line_data;
            }
        }
    }
    return $rows;
}}

if (!hm_exists('convert_to_boolean')) {
function convert_to_boolean($value) {
    if (!is_string($value)) {
        return $value;
    }
    $normalized = mb_strtolower(trim($value));
    if (in_array($normalized, ['true', '1', 'yes'], true)) {
        return true;
    } elseif (in_array($normalized, ['false', '0', 'no'], true)) {
        return false;
    }
    return $value;
}}

/**
 * @subpackage nux/functions
 */
if (!hm_exists('oauth2_form')) {
    function oauth2_form($details, $mod)
    {
        if (empty($details['oauth2_state']) || !nux_oauth2_is_state($details['oauth2_state'])) {
            return '';
        }
        $oauth2 = new Hm_Oauth2($details['client_id'], $details['client_secret'], $details['redirect_uri']);
        $url = $oauth2->request_authorization_url($details['auth_uri'], $details['scope'], $details['oauth2_state'], $details['email']);
        $res = '<input type="hidden" name="nux_service" value="' . $mod->html_safe($details['id']) . '" />';
        $res .= '<div class="nux_step_two_title fw-bold">' . $mod->html_safe($details['name']) . '</div><div class="mb-3">';
        $res .= $mod->trans('This provider supports Oauth2 access to your account.');
        $res .= $mod->trans(' This is the most secure way to access your E-mail. Click "Enable" to be redirected to the provider site to allow access.');
        $res .= '</div><div class="mb-3"><a class="enable_auth2 btn btn-sm btn-success me-2" data-external="true" href="' . $url . '">' . $mod->trans('Enable') . '</a>';
        $res .= '<a href="" class="reset_nux_form btn btn-sm btn-secondary">Reset</a></div>';
        return $res;
    }
}

/**
 * @subpackage nux/functions
 */
if (!hm_exists('credentials_form')) {
    function credentials_form($details, $mod)
    {
        $res = '<input type="hidden" id="nux_service" name="nux_service" value="' . $mod->html_safe($details['id']) . '" />';
        $res .= '<input type="hidden" name="nux_name" class="nux_name" value="' . $mod->html_safe($details['name']) . '" />';
        $res .= '<div class="nux_step_two_title"><b>' . $mod->html_safe($details['name']) . '</b></div>';
        $res .= $mod->trans('Enter your password for this E-mail provider to complete the connection process');

        $res .= '<div class="row"><div class="col col-lg-4">';
        // E-mail Address Field
        $res .= '<div class="form-floating mb-3 mt-3">';
        $res .= '<input type="text" class="form-control" id="nux_email" name="nux_email" placeholder="' . $mod->trans('E-mail Address') . '" value="' . $mod->html_safe($details['email']) . '">';
        $res .= '<label for="nux_email">' . $mod->trans('E-mail Address') . '</label></div>';

        // E-mail Password Field
        $res .= '<div class="form-floating mb-3">';
        $res .= '<input type="password" class="form-control nux_password" id="nux_password" name="nux_password" placeholder="' . $mod->trans('E-Mail Password') . '">';
        $res .= '<label for="nux_password">' . $mod->trans('E-mail Password') . '</label></div>';
        $res .= '<div class="d-flex flex-md-row gap-3 mt-3">';
        // Connect Button
        $res .= '<input type="button" class="nux_submit px-5 btn btn-primary w-100 w-md-auto" value="' . $mod->trans('Connect') . '">';

        // Reset Link
        $res .= '<a href="" class="reset_nux_form px-5 btn btn-secondary w-100 w-md-auto">Reset</a>';

        $res .= '</div></div></div>';

        return $res;
    }
}

/**
 * @subpackage nux/functions
 */
if (!hm_exists('data_source_available')) {
    function data_source_available($mods, $types)
    {
        if (!is_array($types)) {
            $types = array($types);
        }
        return count(array_intersect($types, $mods)) == count($types);
    }
}
