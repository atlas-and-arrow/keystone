<?php
/**
 * Keystone License Engine
 *
 * AES-256-CBC license validation with local and remote checks.
 *
 * @package Keystone
 * @version 1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Keystone_License Class
 */
class Keystone_License {

    /**
     * Product slug
     *
     * @var string
     */
    private $product;

    /**
     * License key (encrypted base64 string)
     *
     * @var string
     */
    private $key;

    /**
     * License server URL
     *
     * @var string
     */
    private $server;

    /**
     * Encryption secret
     *
     * @var string
     */
    private $secret;

    /**
     * Cached decoded license data
     *
     * @var object|null
     */
    private $data = null;

    /**
     * Cached validation result
     *
     * @var bool|null
     */
    private $valid = null;

    /**
     * Reason for validation result
     *
     * @var string
     */
    private $reason = '';

    /**
     * Constructor
     *
     * @param string $product Product slug
     * @param array  $options Options (key, server, secret)
     */
    public function __construct( $product, $options = array() ) {
        $this->product = $product;

        $defaults = array(
            'key'    => get_option( "keystone_{$product}_license_key", '' ),
            'server' => get_option( "keystone_{$product}_license_server", '' ),
            'secret' => get_option( "keystone_{$product}_license_secret", '' ),
        );

        $options = wp_parse_args( $options, $defaults );

        $this->key    = $options['key'];
        $this->server = rtrim( $options['server'], '/' );
        $this->secret = $options['secret'];
    }

    /* =========================================================================
       Public API
       ========================================================================= */

    /**
     * Check if the product is licensed
     *
     * @return bool
     */
    public function is_licensed() {
        if ( $this->valid !== null ) {
            return $this->valid;
        }

        $result = $this->validate();
        return $result === true;
    }

    /**
     * Check if a specific feature is enabled
     *
     * @param string $feature Feature name
     * @return bool
     */
    public function is_enabled( $feature ) {
        if ( ! $this->is_licensed() ) {
            return false;
        }

        $features = $this->features();
        return in_array( $feature, $features, true );
    }

    /**
     * Get list of enabled features
     *
     * @return array
     */
    public function features() {
        $data = $this->get_data();
        if ( $data && isset( $data->features ) && is_array( $data->features ) ) {
            return $data->features;
        }
        return array();
    }

    /**
     * Get license expiry date
     *
     * @return string|null Date string (Y-m-d) or null
     */
    public function expires() {
        $data = $this->get_data();
        if ( $data && isset( $data->expires ) ) {
            return $data->expires;
        }
        return null;
    }

    /**
     * Get days remaining until expiry
     *
     * @return int|null Days remaining or null if no expiry
     */
    public function days_remaining() {
        $expires = $this->expires();
        if ( ! $expires ) {
            return null;
        }

        $now    = new DateTime( 'now', new DateTimeZone( 'UTC' ) );
        $expiry = new DateTime( $expires, new DateTimeZone( 'UTC' ) );
        $diff   = $now->diff( $expiry );

        return $diff->invert ? -$diff->days : $diff->days;
    }

    /**
     * Get licensed domains
     *
     * @return array
     */
    public function domains() {
        $data = $this->get_data();
        if ( $data && isset( $data->domains ) && is_array( $data->domains ) ) {
            return $data->domains;
        }
        return array();
    }

    /**
     * Get license ID
     *
     * @return string|null
     */
    public function id() {
        $data = $this->get_data();
        if ( $data && isset( $data->id ) ) {
            return $data->id;
        }
        return null;
    }

    /**
     * Get the reason for the last validation result
     *
     * @return string
     */
    public function validation_reason() {
        if ( $this->valid === null ) {
            $this->validate();
        }
        return $this->reason;
    }

    /**
     * Clear cached validation data
     */
    public function clear_cache() {
        $this->data   = null;
        $this->valid  = null;
        $this->reason = '';
        delete_transient( "keystone_lic_{$this->product}" );
    }

    /**
     * Register admin notice for license warnings
     *
     * Hooks into admin_notices to show license status messages.
     */
    public function register_admin_notice() {
        add_action( 'admin_notices', array( $this, 'render_admin_notice' ) );
    }

    /**
     * Render license admin notice if needed
     */
    public function render_admin_notice() {
        $dismissed = get_option( 'keystone_dismissed_notices', array() );

        if ( empty( $this->key ) ) {
            $notice_id = "keystone_license_{$this->product}_missing";
            if ( in_array( $notice_id, $dismissed, true ) ) {
                return;
            }
            $this->output_notice(
                sprintf( 'No license key found for <strong>%s</strong>. Please enter your license key in the settings.', esc_html( ucfirst( $this->product ) ) ),
                'warning',
                $notice_id
            );
            return;
        }

        if ( ! $this->is_licensed() ) {
            $notice_id = "keystone_license_{$this->product}_invalid";
            if ( in_array( $notice_id, $dismissed, true ) ) {
                return;
            }
            $this->output_notice(
                sprintf( 'Your <strong>%s</strong> license is invalid: %s', esc_html( ucfirst( $this->product ) ), esc_html( $this->reason ) ),
                'error',
                $notice_id
            );
            return;
        }

        $days = $this->days_remaining();
        if ( $days !== null && $days <= 30 && $days > 0 ) {
            $notice_id = "keystone_license_{$this->product}_expiring";
            if ( in_array( $notice_id, $dismissed, true ) ) {
                return;
            }
            $this->output_notice(
                sprintf( 'Your <strong>%s</strong> license expires in %d day%s.', esc_html( ucfirst( $this->product ) ), $days, $days === 1 ? '' : 's' ),
                'warning',
                $notice_id
            );
        }
    }

    /* =========================================================================
       Validation
       ========================================================================= */

    /**
     * Validate the license
     *
     * @return bool|null True if valid, false if invalid, null if indeterminate
     */
    public function validate() {
        // Check transient cache first
        $cached = get_transient( "keystone_lic_{$this->product}" );
        if ( $cached !== false ) {
            $this->valid  = $cached['valid'];
            $this->reason = $cached['reason'];
            $this->data   = isset( $cached['data'] ) ? $cached['data'] : null;
            return $this->valid;
        }

        // No key = not licensed
        if ( empty( $this->key ) ) {
            $this->valid  = false;
            $this->reason = 'No license key provided.';
            $this->cache_result( 3600 );
            return false;
        }

        // Local validation
        $local_result = $this->validate_local();
        if ( $local_result === false ) {
            $this->cache_result( 3600 );
            return false;
        }

        // Remote validation (if server configured)
        if ( ! empty( $this->server ) ) {
            $remote_result = $this->validate_remote();

            if ( $remote_result === true ) {
                $this->valid  = true;
                $this->reason = 'License validated successfully.';
                $this->cache_result( 86400 ); // 24 hours
                return true;
            } elseif ( $remote_result === false ) {
                $this->cache_result( 3600 );
                return false;
            }

            // Remote unreachable — trust local validation
            $this->valid  = true;
            $this->reason = 'License validated locally (server unreachable).';
            $this->cache_result( 3600 );
            return true;
        }

        // No server configured — local validation is sufficient
        $this->valid  = true;
        $this->reason = 'License validated locally.';
        $this->cache_result( 86400 );
        return true;
    }

    /**
     * Validate the license locally
     *
     * @return bool
     */
    private function validate_local() {
        // Decrypt the license key
        $data = $this->decrypt( $this->key );
        if ( ! $data ) {
            $this->valid  = false;
            $this->reason = 'License key is invalid or corrupted.';
            return false;
        }

        $this->data = $data;

        // Check product matches
        if ( ! isset( $data->product ) || $data->product !== $this->product ) {
            $this->valid  = false;
            $this->reason = 'License is for a different product.';
            return false;
        }

        // Check expiry (with 3-day grace period)
        if ( isset( $data->expires ) ) {
            $expiry = new DateTime( $data->expires, new DateTimeZone( 'UTC' ) );
            $grace  = clone $expiry;
            $grace->modify( '+3 days' );
            $now = new DateTime( 'now', new DateTimeZone( 'UTC' ) );

            if ( $now > $grace ) {
                $this->valid  = false;
                $this->reason = 'License has expired.';
                return false;
            }
        }

        // Check domain
        if ( isset( $data->domains ) && is_array( $data->domains ) && ! empty( $data->domains ) ) {
            $current_domain = $this->get_site_domain();
            if ( ! $this->domain_matches( $current_domain, $data->domains ) ) {
                $this->valid  = false;
                $this->reason = 'License is not valid for this domain.';
                return false;
            }
        }

        return true;
    }

    /**
     * Validate the license remotely
     *
     * @return bool|null True if valid, false if invalid, null if unreachable
     */
    private function validate_remote() {
        $response = wp_remote_post( $this->server . '/validate', array(
            'timeout' => 15,
            'body'    => array(
                'license_id' => $this->id(),
                'product'    => $this->product,
                'domain'     => $this->get_site_domain(),
                'site_url'   => get_site_url(),
            ),
        ) );

        if ( is_wp_error( $response ) ) {
            return null; // Server unreachable
        }

        $code = wp_remote_retrieve_response_code( $response );
        if ( $code < 200 || $code >= 300 ) {
            return null; // Server error
        }

        $body = json_decode( wp_remote_retrieve_body( $response ) );
        if ( ! $body ) {
            return null;
        }

        if ( isset( $body->valid ) && $body->valid === true ) {
            return true;
        }

        $this->valid  = false;
        $this->reason = isset( $body->reason ) ? $body->reason : 'License rejected by server.';
        return false;
    }

    /* =========================================================================
       Encryption
       ========================================================================= */

    /**
     * Decrypt a license key
     *
     * @param string $encrypted_key Base64-encoded encrypted license key
     * @return object|false Decoded license data or false
     */
    private function decrypt( $encrypted_key ) {
        if ( empty( $this->secret ) ) {
            return false;
        }

        $raw = base64_decode( $encrypted_key, true );
        if ( $raw === false || strlen( $raw ) < 17 ) {
            return false;
        }

        $iv         = substr( $raw, 0, 16 );
        $ciphertext = substr( $raw, 16 );
        $key        = hash( 'sha256', $this->secret, true );

        $decrypted = openssl_decrypt( $ciphertext, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv );
        if ( $decrypted === false ) {
            return false;
        }

        $inflated = @gzuncompress( $decrypted );
        if ( $inflated !== false ) {
            $decrypted = $inflated;
        }

        $data = json_decode( $decrypted );
        if ( ! is_object( $data ) ) {
            return false;
        }

        return $data;
    }

    /**
     * Encrypt license data into a license key
     *
     * Static utility for generating license keys (server/admin use).
     *
     * @param array  $data   License data (id, product, domains, instances, expires, issued, features)
     * @param string $secret Encryption secret
     * @return string Base64-encoded encrypted license key
     */
    public static function encrypt_license( $data, $secret ) {
        $json       = json_encode( $data );
        $compressed = gzcompress( $json );
        $key        = hash( 'sha256', $secret, true );
        $iv         = openssl_random_pseudo_bytes( 16 );

        $ciphertext = openssl_encrypt( $compressed, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv );

        return base64_encode( $iv . $ciphertext );
    }

    /* =========================================================================
       Helpers
       ========================================================================= */

    /**
     * Get the decoded license data
     *
     * @return object|null
     */
    private function get_data() {
        if ( $this->data === null && ! empty( $this->key ) ) {
            $this->data = $this->decrypt( $this->key );
        }
        return $this->data;
    }

    /**
     * Get the current site domain
     *
     * @return string
     */
    private function get_site_domain() {
        return wp_parse_url( get_site_url(), PHP_URL_HOST );
    }

    /**
     * Check if a domain matches any of the allowed domains
     *
     * Supports wildcard patterns (e.g. *.example.com)
     *
     * @param string $domain  Domain to check
     * @param array  $allowed List of allowed domains
     * @return bool
     */
    private function domain_matches( $domain, $allowed ) {
        $domain = strtolower( $domain );

        foreach ( $allowed as $pattern ) {
            $pattern = strtolower( $pattern );

            // Universal wildcard
            if ( $pattern === '*' ) {
                return true;
            }

            // Exact match
            if ( $domain === $pattern ) {
                return true;
            }

            // Wildcard match (*.example.com)
            if ( strpos( $pattern, '*.' ) === 0 ) {
                $suffix = substr( $pattern, 1 ); // .example.com
                if ( substr( $domain, -strlen( $suffix ) ) === $suffix ) {
                    return true;
                }
                // Also match the bare domain (example.com matches *.example.com)
                $bare = substr( $pattern, 2 ); // example.com
                if ( $domain === $bare ) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Cache validation result in a transient
     *
     * @param int $ttl Cache duration in seconds
     */
    private function cache_result( $ttl ) {
        set_transient( "keystone_lic_{$this->product}", array(
            'valid'  => $this->valid,
            'reason' => $this->reason,
            'data'   => $this->data,
        ), $ttl );
    }

    /**
     * Output an admin notice
     *
     * Uses Mosaic::alert() if available, falls back to native WP notices.
     *
     * @param string $message   Notice message (HTML)
     * @param string $type      Notice type (info, success, warning, error)
     * @param string $notice_id Notice ID for persistent dismiss
     */
    private function output_notice( $message, $type, $notice_id = '' ) {
        if ( class_exists( 'Mosaic' ) ) {
            $options = array( 'dismissible' => true );
            if ( $notice_id ) {
                $options['dismiss_action'] = 'keystone_dismiss_notice';
                $options['dismiss_nonce']  = wp_create_nonce( 'keystone_dismiss_notice' );
                $options['class']          = 'keystone-notice';
            }
            echo Mosaic::alert( $message, $type, $options ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
            if ( $notice_id ) {
                printf(
                    '<script>jQuery(function($){$(".keystone-notice .mosaic-info-card-close").last().attr("data-notice-id","%s");})</script>',
                    esc_js( $notice_id )
                );
            }
            return;
        }

        $type_map = array(
            'info'    => 'notice-info',
            'success' => 'notice-success',
            'warning' => 'notice-warning',
            'error'   => 'notice-error',
        );

        $wp_type = isset( $type_map[ $type ] ) ? $type_map[ $type ] : 'notice-info';

        printf(
            '<div class="notice %s is-dismissible" data-notice-id="%s"><p>%s</p></div>',
            esc_attr( $wp_type ),
            esc_attr( $notice_id ),
            wp_kses_post( $message )
        );
    }
}
