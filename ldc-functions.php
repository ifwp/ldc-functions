<?php
/**
 * Author: Luis del Cid
 * Author URI: https://luisdelcid.com
 * Description: A collection of useful functions for your WordPress theme's functions.php.
 * Domain Path:
 * License: GPL2
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Network:
 * Plugin Name: LDC Functions
 * Plugin URI: https://luisdelcid.com
 * Text Domain: ldc-functions
 * Version: 2019.11.12
 *
 */ // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	defined('ABSPATH') or die('No script kiddies please!');

	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    require_once(plugin_dir_path(__FILE__) . 'includes/plugin-update-checker-4.8.1/plugin-update-checker.php');
    Puc_v4_Factory::buildUpdateChecker('https://github.com/luisdelcid/ldc-functions', __FILE__, 'ldc-functions');

	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	add_action('plugins_loaded', function(){
        if(defined('LDC_Functions') or defined('LDC_Functions_Version')){
            add_action('admin_notices', function(){
				printf('<div class="notice notice-error"><p>LDC Functions already exists.</p></div>');
			});
			deactivate_plugins(plugin_basename(__FILE__));
		} else {
            define('LDC_Functions', __FILE__);
			define('LDC_Functions_Version', '2019.11.12');
            require_once(plugin_dir_path(LDC_Functions) . 'functions.php');
        }
	});
