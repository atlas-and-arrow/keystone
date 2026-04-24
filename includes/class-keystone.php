<?php
/**
 * Keystone Licensing Library
 *
 * Main class for configuration and license management.
 *
 * @package Keystone
 * @version 1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Keystone Class
 */
class Keystone {

    /**
     * Cached config data
     *
     * @var array|null
     */
    private static $config = null;

    /**
     * Keystone directory path
     *
     * @var string
     */
    private static $path = '';

    /**
     * Cached license instances
     *
     * @var array
     */
    private static $licenses = array();

    /**
     * Whether init has been called
     *
     * @var bool
     */
    private static $initialized = false;

    /* =========================================================================
       Configuration Methods
       ========================================================================= */

    /**
     * Load keystone from the given path
     *
     * @param string $keystone_path Path to keystone directory
     */
    public static function load( $keystone_path = '' ) {
        if ( self::$config !== null && ( empty( $keystone_path ) || $keystone_path === self::$path ) ) {
            return self::$config;
        }

        if ( empty( $keystone_path ) ) {
            $keystone_path = dirname( __DIR__ );
        }

        self::$path = rtrim( $keystone_path, '/' );
        self::$config = array(
            'name' => 'Keystone',
        );

        return self::$config;
    }


    /**
     * Get the version
     *
     * @return string
     */
    public static function version() {
        $version_file = self::$path . '/version.properties';
        if ( file_exists( $version_file ) ) {
            $version_config = parse_ini_file( $version_file );
            if ( isset( $version_config['version'] ) ) {
                return $version_config['version'];
            }
        }

        return self::config( 'version', '1.0.0' );
    }

    /**
     * Get the keystone directory path
     *
     * @return string
     */
    public static function path() {
        if ( empty( self::$path ) ) {
            self::load();
        }
        return self::$path;
    }

    /* =========================================================================
       License Factory
       ========================================================================= */

    /**
     * Get or create a license instance for a product
     *
     * @param string $product Product slug (e.g. 'walter')
     * @param array  $options License options (key, server, secret)
     * @return Keystone_License
     */
    public static function license( $product, $options = array() ) {
        if ( ! isset( self::$licenses[ $product ] ) ) {
            self::$licenses[ $product ] = new Keystone_License( $product, $options );
        }
        return self::$licenses[ $product ];
    }

    /* =========================================================================
       Initialization
       ========================================================================= */

    /**
     * Initialize keystone hooks
     */
    public static function init() {
        if ( self::$initialized ) {
            return;
        }

        self::$initialized = true;
        self::load();
    }
}
