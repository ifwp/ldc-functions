<?php

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    defined('LDC_Functions') or die('No script kiddies please!');

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	if(!function_exists('_ldc_authenticate_filter')){
		function _ldc_authenticate_filter($user, $username){
			if($user instanceof WP_User){
				return $user;
			}
			if(empty($username)){
				if(is_wp_error($user)){
					return $user;
				}
				return new WP_Error('empty_username', __('<strong>ERROR</strong>: The username field is empty.'));
			}
			$user = get_user_by('login', $username);
			if(!$user){
				return new WP_Error('invalid_username', __('Unknown username. Check again or try your email address.'));
			}
			return $user;
		}
	}

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	if(!function_exists('ldc_attachment_guid_to_postid')){
		function ldc_attachment_guid_to_postid($url = ''){
			if($url){
				/** original */
				$post_id = ldc_guid_to_postid($url);
				if($post_id){
					return $post_id;
				}
				/** resized */
				preg_match('/^(.+)(-\d+x\d+)(\.' . substr($url, strrpos($url, '.') + 1) . ')?$/', $url, $matches);
				if($matches){
					$url = $matches[1];
					if(isset($matches[3])){
						$url .= $matches[3];
					}
				}
				$post_id = ldc_guid_to_postid($url);
				if($post_id){
					return $post_id;
				}
				/** edited */
				preg_match('/^(.+)(-e\d+)(\.' . substr($url, strrpos($url, '.') + 1) . ')?$/', $url, $matches);
				if($matches){
					$url = $matches[1];
					if(isset($matches[3])){
						$url .= $matches[3];
					}
				}
				$post_id = ldc_guid_to_postid($url);
				if($post_id){
					return $post_id;
				}
			}
			return 0;
		}
	}

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	if(!function_exists('ldc_base64_urldecode')){
		function ldc_base64_urldecode($data = ''){
			return base64_decode(strtr($data, '-_', '+/'));
		}
	}

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	if(!function_exists('ldc_base64_urlencode')){
		function ldc_base64_urlencode($data = ''){
			return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
		}
	}

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	if(!function_exists('ldc_fix_file_names')){
		function ldc_fix_file_names(){
			add_filter('sanitize_file_name', 'ldc_sanitize_file_name');
		}
	}

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	// inspired by the awesome wp_create_nonce_guest function by @Mte90 https://gist.github.com/Mte90

	if(!function_exists('ldc_create_guest_nonce')){
		function ldc_create_guest_nonce($action = -1){
			$i = wp_nonce_tick();
  			return substr(wp_hash($i . '|' . $action . '|0|', 'nonce'), -12, 10);
		}
	}

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	if(!function_exists('ldc_guest_nonce_url')){
		function ldc_guest_nonce_url($actionurl = '', $action = -1, $name = '_wpnonce'){
			$actionurl = str_replace('&amp;', '&', $actionurl);
			return add_query_arg($name, ldc_create_guest_nonce($action), $actionurl);
		}
	}

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	if(!function_exists('ldc_guid_to_postid')){
		function ldc_guid_to_postid($guid = ''){
			if($guid){
				global $wpdb;
				$str = "SELECT ID FROM $wpdb->posts WHERE guid = %s";
				$sql = $wpdb->prepare($str, $guid);
				$post_id = $wpdb->get_var($sql);
				if($post_id){
				  return (int) $post_id;
				}
			}
			return 0;
		}
	}

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	if(!function_exists('ldc_is_post_revision')){
		function ldc_is_post_revision($post_id = 0){
			if($post_id){
				if(get_post_status($post_id) == 'auto-draft'){
					return (int) $post_id;
				}
				$post_id = wp_is_post_revision($post_id);
				if($post_id){
					return $post_id;
				}
			}
			return 0;
		}
	}

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	if(!function_exists('ldc_json_decode_response_data')){
		function ldc_json_decode_response_data($response = array(), $assoc = false, $depth = 512, $options = 0){
			if(is_array($response) and isset($response['data'], $response['message'], $response['success'])){
				if($response['data']){
					$data = json_decode($response['data'], $assoc, $depth, $options);
					if(json_last_error() == JSON_ERROR_NONE){
						$response['data'] = $data;
					} else {
						$response['message'] = json_last_error_msg();
						$response['success'] = false;
					}
				}
			}
			return $response;
		}
	}

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	if(!function_exists('ldc_new_xlsxwriter')){
		function ldc_new_xlsxwriter(){
	        if(!class_exists('XLSXWriter', false)){
	            require_once(plugin_dir_path(LDC_Functions) . 'includes/php-xlsxwriter-0.37/xlsxwriter.class.php');
	        }
	        return new XLSXWriter;
	    }
	}

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	if(!function_exists('ldc_nonce_url')){
		function ldc_nonce_url($actionurl = '', $action = -1, $name = '_wpnonce'){
			$actionurl = str_replace('&amp;', '&', $actionurl);
			return add_query_arg($name, wp_create_nonce($action), $actionurl);
	    }
	}

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	if(!function_exists('ldc_parse_response')){
		function ldc_parse_response($response = null){
			if(is_a($response, 'Requests_Exception')){
				return ldc_response_error('', $response->getMessage());
			} elseif(is_a($response, 'Requests_Response')){
				$response_body = $response->body;
				$response_code = $response->status_code;
				$response_message = get_status_header_desc($response_code);
				if($response_code == 200){
					return ldc_response_success($response_body, $response_message);
				} else {
					return ldc_response_error($response_body, $response_message);
				}
			} elseif(is_wp_error($response)){
				return ldc_response_error('', $response->get_error_message());
			} else {
				$response_body = wp_remote_retrieve_body($response);
				$response_code = wp_remote_retrieve_response_code($response);
				$response_message = wp_remote_retrieve_response_message($response);
				if(!$response_message){
					$response_message = get_status_header_desc($response_code);
				}
				if($response_code == 200){
					return ldc_response_success($response_body, $response_message);
				} else {
					return ldc_response_error($response_body, $response_message);
				}
			}
		}
	}

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	// inspired by the awesome programmatic_login function by @iandunn https://gist.github.com/iandunn

	if(!function_exists('ldc_programmatic_login')){
		function ldc_programmatic_login($userid = 0){
			if(!$userid){
				return false;
			}
			if(get_current_user_id() == $userid){
				return true;
			}
			$user_info = get_userdata($userid);
			if(!$user_info){
				return false;
			}
			wp_logout();
			add_filter('authenticate', '_ldc_authenticate_filter', 9, 2);
			$user = wp_signon(array(
				'user_login' => $user_info->user_login,
			));
			remove_filter('authenticate', '_ldc_authenticate_filter', 9, 2);
			if(is_wp_error($user)){
				return false;
			}
			wp_set_current_user($user->ID, $user->user_login);
			return is_user_logged_in();
		}
	}

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	if(!function_exists('ldc_referer_to_postid')){
		function ldc_referer_to_postid(){
			$referer = wp_get_referer();
			if($referer){
				return url_to_postid($referer);
			}
			return 0;
		}
	}

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	if(!function_exists('ldc_remove_private_title_format')){
		function ldc_remove_private_title_format(){
			add_filter('private_title_format', function($private_title_format){
				if(!is_admin()){
					return '%s';
				}
  				return $private_title_format;
			});
		}
	}

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	if(!function_exists('ldc_require_media_functions')){
		function ldc_require_media_functions(){
			if(!is_admin()){
				require_once(ABSPATH . 'wp-admin/includes/file.php');
				require_once(ABSPATH . 'wp-admin/includes/image.php');
				require_once(ABSPATH . 'wp-admin/includes/media.php');
			}
		}
	}

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	if(!function_exists('ldc_response')){
		function ldc_response($data = '', $message = '', $success = false){
			if(!$message){
				$message = 'Unknown';
			}
			return array(
				'data' => $data,
				'message' => $message,
				'success' => $success,
			);
		}
	}

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	if(!function_exists('ldc_response_error')){
		function ldc_response_error($data = '', $message = ''){
			return ldc_response($data, $message, false);
		}
	}

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	if(!function_exists('ldc_response_success')){
		function ldc_response_success($data = '', $message = ''){
			return ldc_response($data, $message, true);
		}
	}

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

		if(!function_exists('ldc_sanitize_file_name')){
			function ldc_sanitize_file_name($filename = ''){
				return implode('.', array_map('sanitize_title', explode('.', $filename)));
			}
		}

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	if(!function_exists('ldc_support_full_hd_thumbnails')){
		function ldc_support_full_hd_thumbnails(){
			 add_action('after_setup_theme', function(){
				add_image_size('full-hd', 1920, 1920);
			});
			add_filter('image_size_names_choose', function($sizes){
				if(!isset($sizes['full-hd'])){
					$sizes['full-hd'] = 'Full HD';
				}
				return $sizes;
			});
		}
	}

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	if(!function_exists('ldc_support_hd_thumbnails')){
		function ldc_support_hd_thumbnails(){
			 add_action('after_setup_theme', function(){
				add_image_size('hd', 1280, 1280);
			});
			add_filter('image_size_names_choose', function($sizes){
				if(!isset($sizes['hd'])){
					$sizes['hd'] = 'HD';
				}
				return $sizes;
			});
		}
	}

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	if(!function_exists('ldc_url_to_postid')){
		function ldc_url_to_postid($url = ''){
			if($url){
				$post_id = url_to_postid($url);
				if($post_id){
					return $post_id;
				}
				$post_id = ldc_attachment_guid_to_postid($url);
				if($post_id){
					return $post_id;
				}
			}
			return 0;
		}
	}

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	if(!function_exists('ldc_verify_guest_nonce')){
		function ldc_verify_guest_nonce($nonce = '', $action = -1){
			$nonce = (string) $nonce;
			if(empty($nonce)){
				return false;
			}
			$i = wp_nonce_tick();
			$expected = substr(wp_hash($i . '|' . $action . '|0|', 'nonce'), -12, 10);
			if(hash_equals($expected, $nonce)){
				return 1;
			}
			$expected = substr(wp_hash(($i - 1) . '|' . $action . '|0|', 'nonce'), -12, 10);
			if(hash_equals($expected, $nonce)){
				return 2;
			}
			return false;
		}
	}

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	if(!function_exists('ldc_visitor_country')){
		function ldc_visitor_country($ip = ''){
			if(!$ip){
				if(!empty($_SERVER['HTTP_CF_IPCOUNTRY'])){
					return $_SERVER['HTTP_CF_IPCOUNTRY'];
				}
				$ip = ldc_visitor_ip();
			}
			if(rest_is_ip_address($ip)){
				$response = wp_remote_get('http://ip-api.com/json/' . $ip . '?fields=countryCode');
				$response = ldc_parse_response($response);
				$response = ldc_json_decode_response_data($response, true);
				if($response['success']){
					if(!empty($response['data']['countryCode'])){
						return $response['data']['countryCode'];
					}
				}
			}
			return '';
		}
	}

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	if(!function_exists('ldc_visitor_ip')){
		function ldc_visitor_ip(){
			if(!empty($_SERVER['HTTP_CF_CONNECTING_IP'])){
				return $_SERVER['HTTP_CF_CONNECTING_IP'];
			}
			if(!empty($_SERVER['REMOTE_ADDR'])){
				return $_SERVER['REMOTE_ADDR'];
			}
			return '';
		}
	}

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
