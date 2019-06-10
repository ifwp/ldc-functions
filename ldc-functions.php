<?php
/**
 * Author: Luis del Cid
 * Author URI: http://luisdelcid.com/
 * Description: LDC Functions for WordPress
 * Domain Path:
 * License: GPL2
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Network:
 * Plugin Name: LDC Functions
 * Plugin URI: http://luisdelcid.com/
 * Text Domain: ldc-functions
 * Version: 0.6.10
 */

defined('ABSPATH') or die('No script kiddies please!');

define('LDC_Functions', true);

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

function ldc_attachment_image_url_to_postid($url = ''){
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

function ldc_url_to_postid($url = ''){
  if($url){
    $post_id = url_to_postid($url);
    if($post_id){
      return $post_id;
    }
    $post_id = ldc_attachment_image_url_to_postid($url);
    if($post_id){
      return $post_id;
    }
  }
  return 0;
}

function ldc_http_referer_to_postid(){
  $referer = wp_get_referer();
  return url_to_postid($referer);
}

function ldc_restrict_frontend_to_logged_in_users_func(){
  $restrict = false;
  if(!is_user_logged_in()){
    $restrict = true;
  }
  $restrict = apply_filters('ldc_restrict_frontend_to_logged_in_users', $restrict);
  if($restrict){
    auth_redirect();
  }
}

function ldc_restrict_frontend_to_logged_in_users(){
  add_action('template_redirect', 'ldc_restrict_frontend_to_logged_in_users_func');
}

function ldc_restrict_rest_api_to_logged_in_users_func($result){
  if(!empty($result)){
 	  return $result;
 	}
  $restrict = false;
  if(!is_user_logged_in()){
    $restrict = true;
  }
  $restrict = apply_filters('ldc_restrict_rest_api_to_logged_in_users', $restrict);
  if($restrict){
    return new WP_Error('rest_not_logged_in', 'API Requests are only supported for authenticated requests.', array(
      'status' => 401,
    ));
  }
  return $result;
}

function ldc_restrict_rest_api_to_logged_in_users(){
  add_filter('rest_authentication_errors', 'ldc_restrict_rest_api_to_logged_in_users_func');
}

function ldc_restrict_dashboard_to_admin_users_func(){
  $restrict = false;
  if(!current_user_can('manage_options') and (!wp_doing_ajax())){
    $restrict = true;
  }
  $restrict = apply_filters('ldc_restrict_dashboard_to_admin_users', $restrict);
  if($restrict){
    $location = home_url();
    wp_safe_redirect($location);
    exit;
  }
}

function ldc_restrict_dashboard_to_admin_users(){
  add_action('admin_init', 'ldc_restrict_dashboard_to_admin_users_func');
}

function ldc_restrict_admin_bar_to_admin_users_func($content){
  $restrict = false;
  if(!current_user_can('manage_options')){
    $restrict = true;
  }
  $restrict = apply_filters('ldc_restrict_admin_bar_to_admin_users', $restrict);
  if($restrict){
    return false;
  }
  return $content;
}

function ldc_restrict_admin_bar_to_admin_users(){
  add_filter('show_admin_bar', 'ldc_restrict_admin_bar_to_admin_users_func');
}

function ldc_fix_rwmb_validate_func(RW_Meta_Box $object){
  if(empty($object->meta_box['validation'])){
    return;
  }
  $file = plugin_dir_path(__FILE__) . 'js/rwmb-validate.js';
	$url = plugin_dir_url(__FILE__) . 'js/rwmb-validate.js';
  if(file_exists($file)){
    wp_dequeue_script('rwmb-validate');
		wp_deregister_script('rwmb-validate');
    wp_enqueue_script('rwmb-validate', $url, array('jquery-validation', 'jquery-validation-additional-methods'), '4.18.2', true);
    if(is_callable(array('RWMB_Helpers_Field', 'localize_script_once'))){
      RWMB_Helpers_Field::localize_script_once('rwmb-validate', 'rwmbValidate', array(
        'summaryMessage' => esc_html__('Please correct the errors highlighted below and try again.', 'meta-box'),
      ));
    } elseif(is_callable(array('RWMB_Helpers_Field', 'localize_script_once'))){
      RWMB_Field::localize_script('rwmb-validate', 'rwmbValidate', array(
        'summaryMessage' => esc_html__('Please correct the errors highlighted below and try again.', 'meta-box'),
      ));
    }
  }
}

function ldc_fix_rwmb_validate(){
  add_action('rwmb_enqueue_scripts', 'ldc_fix_rwmb_validate_func');
}

function ldc_base64url_decode($data){
  return base64_decode(strtr($data, '-_', '+/'));
}

function ldc_base64url_encode($data){
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function ldc_wp_create_guest_nonce($action = -1){
  $i = wp_nonce_tick();
  return substr(wp_hash($i . '|' . $action . '|0|', 'nonce'), -12, 10);
}

function ldc_wp_guest_nonce_url($actionurl, $action = -1, $name = '_wpnonce'){
  $actionurl = str_replace('&amp;', '&', $actionurl);
  /** fix */
  return add_query_arg($name, ldc_wp_create_guest_nonce($action), $actionurl);
}

function ldc_wp_verify_guest_nonce($nonce, $action = -1){
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

function ldc_wp_nonce_url($actionurl, $action = -1, $name = '_wpnonce'){
  $actionurl = str_replace('&amp;', '&', $actionurl);
  /** fix */
  return add_query_arg($name, wp_create_nonce($action), $actionurl);
}

function ldc_programmatic_login($userid = 0){
  /** inspired by the awesome programmatic_login function by @iandunn https://gist.github.com/iandunn */
  if(get_current_user_id() != $userid){
    $user_info = get_userdata($userid);
    if($user_info){
      if(is_user_logged_in()){
        wp_logout();
      }
      add_filter('authenticate', 'ldc_allow_programmatic_login', 5, 3);
      $user = wp_signon(array(
	'user_login' => $user_info->user_login,
      ));
      remove_filter('authenticate', 'ldc_allow_programmatic_login', 5, 3);
      if(!is_wp_error($user)){
        wp_set_current_user($user->ID, $user->user_login);
        return is_user_logged_in();
      }
    }
  }
  return false;
}

function ldc_allow_programmatic_login($user, $username, $password){
  return get_user_by('login', $username);
}

function ldc_parse_remote_response($response = null){
  if($response){
    if(is_wp_error($response)){
      return array(
	'success' => false,
	'data' => $response->get_error_message(),
      );
    }
    $response_code = wp_remote_retrieve_response_code($response);
    if($response_code == 200){
      return array(
	'success' => true,
	'data' => wp_remote_retrieve_body($response),
      );
    }
    $response_message = wp_remote_retrieve_response_message($response);
    if(!$response_message){
	$response_message = get_status_header_desc($response_code);
    }
    if($response_message){
      return array(
	'success' => false,
	'data' => $response_message,
      );
    }
  }
  return array(
    'success' => false,
    'data' => 'Unknown error occurred',
  );
}

function ldc_parse_requests_response($response = null){
  if($response){
    if(is_a($response, 'Requests_Exception')){
      return array(
	'success' => false,
	'data' => $response->getMessage(),
      );
    }
    if(is_a($response, 'Requests_Response')){
      try {
	$response->throw_for_status();
      } catch(Exception $exception){
	return array(
          'success' => false,
          'data' => $exception->getMessage(),
	);
      }
      $response_code = $response->status_code;
      if($response_code == 200){
        return array(
	  'success' => true,
	  'data' => $response->body,
        );
      }
      $response_message = get_status_header_desc($response_code);
	if($response_message){
	  return array(
	    'success' => false,
	    'data' => $response_message,
	  );
      }
    }
  }
  return array(
    'success' => false,
    'data' => 'Unknown error occurred',
  );
}

function ldc_json_decode_parsed_response($response = array(), $assoc = false, $depth = 512, $options = 0){
  if(is_array($response) and $response and isset($response['status']) and $response['status'] and isset($response['data']) and $response['data']){
    $data = json_decode($response['data'], $assoc, $depth, $options);
    if($data){
      $response['data'] = $data;
    } else {
      $response['success'] = false;
      $response['data'] = 'JSON cannot be decoded or the encoded data is deeper than the recursion limit';
    }
  }
  return $response;
}
