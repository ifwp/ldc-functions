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

define('LDC_Functions', true);
define('LDC_Functions_Version', '0.6.10');

defined('ABSPATH') or die('No script kiddies please!');

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

function ldc_referer_to_postid(){
  $referer = wp_get_referer();
  if($referer){
    return url_to_postid($referer);
  }
  return 0;
}

function ldc_restrict_frontend_func(){
  $restrict = false;
  if(!is_user_logged_in()){
    $restrict = true;
  }
  $restrict = apply_filters('ldc_restrict_frontend', $restrict);
  if($restrict){
    auth_redirect();
  }
}

function ldc_restrict_frontend(){
  add_action('template_redirect', 'ldc_restrict_frontend_func');
}

function ldc_restrict_rest_api_func($result){
  if(!empty($result)){
   return $result;
  }
  $restrict = false;
  if(!is_user_logged_in()){
    $restrict = true;
  }
  $restrict = apply_filters('ldc_restrict_rest_api', $restrict);
  if($restrict){
    return new WP_Error('rest_not_logged_in', 'API Requests are only supported for authenticated requests.', array(
      'status' => 401,
    ));
  }
  return $result;
}

function ldc_restrict_rest_api(){
  add_filter('rest_authentication_errors', 'ldc_restrict_rest_api_func');
}

function ldc_restrict_dashboard_func(){
  $restrict = false;
  if(!current_user_can('manage_options') and (!wp_doing_ajax())){
    $restrict = true;
  }
  $restrict = apply_filters('ldc_restrict_dashboard', $restrict);
  if($restrict){
    $location = home_url();
    wp_safe_redirect($location);
    exit;
  }
}

function ldc_restrict_dashboard(){
  add_action('admin_init', 'ldc_restrict_dashboard_func');
}

function ldc_restrict_admin_bar_func($content){
  $restrict = false;
  if(!current_user_can('manage_options')){
    $restrict = true;
  }
  $restrict = apply_filters('ldc_restrict_admin_bar', $restrict);
  if($restrict){
    return false;
  }
  return $content;
}

function ldc_restrict_admin_bar(){
  add_filter('show_admin_bar', 'ldc_restrict_admin_bar_func');
}

function ldc_fix_rwmb_validate_func(RW_Meta_Box $object){
  if(empty($object->meta_box['validation'])){
    return;
  }
  $url = plugin_dir_url(__FILE__) . 'js/rwmb-validate.js';
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

function ldc_fix_rwmb_validate(){
  add_action('rwmb_enqueue_scripts', 'ldc_fix_rwmb_validate_func');
}

function ldc_base64url_decode($data){
  return base64_decode(strtr($data, '-_', '+/'));
}

function ldc_base64url_encode($data){
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

/** inspired by the awesome wp_create_nonce_guest function by @Mte90 https://gist.github.com/Mte90 */

function ldc_create_guest_nonce($action = -1){
  $i = wp_nonce_tick();
  return substr(wp_hash($i . '|' . $action . '|0|', 'nonce'), -12, 10);
}

function ldc_guest_nonce_url($actionurl, $action = -1, $name = '_wpnonce'){
  $actionurl = str_replace('&amp;', '&', $actionurl);
  /** fix */
  return add_query_arg($name, ldc_create_guest_nonce($action), $actionurl);
}

function ldc_verify_guest_nonce($nonce, $action = -1){
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

function ldc_nonce_url($actionurl, $action = -1, $name = '_wpnonce'){
  $actionurl = str_replace('&amp;', '&', $actionurl);
  /** fix */
  return add_query_arg($name, wp_create_nonce($action), $actionurl);
}

/** inspired by the awesome programmatic_login function by @iandunn https://gist.github.com/iandunn */

function ldc_programmatic_login($userid = 0){
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

function ldc_is_post_revision($post_id = 0){
  if($post_id){
    $post_revision_id = wp_is_post_revision($post_id);
    if($post_revision_id){
      return $post_revision_id;
    }
    if(get_post_status($post_id) == 'auto-draft'){
      return (int) $post_id;
    }
  }
  return 0;
}

function ldc_sideload_url($url = '', $post_id = null, $filename = ''){
  ldc_require_media_functions();
  $file_array = array(
    'tmp_name' => download_url($url),
  );
  if(!is_wp_error($file_array['tmp_name'])){
    if($filename){
      $file_array['name'] = $filename;
    } else {
      $file_array['name'] = basename(parse_url($url, PHP_URL_PATH));
    }
    $attachment_id = media_handle_sideload($file_array, $post_id);
    if(is_wp_error($attachment_id)){
      @unlink($file_array['tmp_name']);
    } else {
      return $attachment_id;
    }
  }
  return 0;
}

function ldc_require_media_functions(){
  if(!is_admin()){
    require_once(ABSPATH . 'wp-admin/includes/file.php');
    require_once(ABSPATH . 'wp-admin/includes/image.php');
    require_once(ABSPATH . 'wp-admin/includes/media.php');
  }
}

function ldc_dropdowns_toggled_by_hovering_func(){
  $url = plugin_dir_url(__FILE__) . 'js/jquery.hoverIntent.min.js';
  wp_enqueue_script('jquery-hoverIntent', $url, array('jquery'), '1.10.0', true);
  $url = plugin_dir_url(__FILE__) . 'js/ldc-dropdowns-toggled-by-hovering.js';
  wp_enqueue_script('ldc-dropdowns-toggled-by-hovering', $url, array('jquery-hoverIntent'), LDC_Functions_Version, true);
  $url = plugin_dir_url(__FILE__) . 'css/ldc-dropdowns-toggled-by-hovering.css';
  wp_enqueue_style('ldc-dropdowns-toggled-by-hovering', $url, array(), LDC_Functions_Version);
}

function ldc_dropdowns_toggled_by_hovering(){
  add_action('wp_enqueue_scripts', 'ldc_dropdowns_toggled_by_hovering_func');
}

function ldc_enqueue_popper_func(){
  $url = 'https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.7/umd/popper.min.js';
  wp_enqueue_script('popper', $url, array('jquery'), '1.14.7', true);
}

function ldc_enqueue_popper(){
  add_action('wp_enqueue_scripts', 'ldc_enqueue_popper_func');
}

function ldc_disable_beaver_builder_inline_editing(){
  add_filter('fl_inline_editing_enabled', '__return_false');
}

function ldc_enqueue_bootstrap_4_bundle_func(){
  $url = 'https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.bundle.min.js';
  wp_enqueue_script('bootstrap-4', $url, array('jquery'), '4.3.1', true);
  $url = 'https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css'
  wp_enqueue_style('bootstrap-4', $url, array(), '4.3.1');
}

function ldc_enqueue_bootstrap_4_func(){
  $url = 'https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js';
  wp_enqueue_script('bootstrap-4', $url, array('jquery'), '4.3.1', true);
  $url = 'https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css'
  wp_enqueue_style('bootstrap-4', $url, array(), '4.3.1');
}

function ldc_enqueue_bootstrap_3_func(){
  $url = 'https://stackpath.bootstrapcdn.com/bootstrap/3.4.1/js/bootstrap.min.js';
  wp_enqueue_script('bootstrap-3', $url, array('jquery'), '3.4.1', true);
  $url = 'https://stackpath.bootstrapcdn.com/bootstrap/3.4.1/css/bootstrap.min.css'
  wp_enqueue_style('bootstrap-3', $url, array(), '3.4.1');
}

function ldc_enqueue_bootstrap($version = 4, $bundle = true){
  if($version == 4){
    if($bundle){
      add_action('wp_enqueue_scripts', 'ldc_enqueue_bootstrap_4_bundle_func');
    } else {
      add_action('wp_enqueue_scripts', 'ldc_enqueue_bootstrap_4_func');
    }
  } elseif($version == 3){
    add_action('wp_enqueue_scripts', 'ldc_enqueue_bootstrap_3_func');
  }
}

function ldc_enqueue_fontawesome_5_func(){
  $url = 'https://use.fontawesome.com/releases/v5.8.2/css/all.css'
  wp_enqueue_style('fontawesome-5', $url, array(), '5.8.2');
}

function ldc_enqueue_fontawesome_5_pro_func(){
  $url = 'https://pro.fontawesome.com/releases/v5.8.2/css/all.css'
  wp_enqueue_style('fontawesome-5', $url, array(), '5.8.2');
}

function ldc_enqueue_fontawesome_4_func(){
  $url = 'https://maxcdn.bootstrapcdn.com/font-awesome/4.7.0/css/font-awesome.min.css'
  wp_enqueue_style('fontawesome-4', $url, array(), '4.7.0');
}

function ldc_enqueue_fontawesome($version = 5, $pro = false){
  if($version == 5){
    if($pro){
      add_action('wp_enqueue_scripts', 'ldc_enqueue_fontawesome_5_pro_func');
    } else {
      add_action('wp_enqueue_scripts', 'ldc_enqueue_fontawesome_5_func');
    }
  } elseif($version == 4){
    add_action('wp_enqueue_scripts', 'ldc_enqueue_fontawesome_4_func');
  }
}

function ldc_remove_private_title_format_func($private_title_format){
  if(!is_admin()){
    return '%s';
  }
  return $private_title_format;
}

function ldc_remove_private_title_format(){
  add_filter('private_title_format', 'ldc_remove_private_title_format_func');
}

function ldc_only_show_current_user_attachments_func($query = array()){
  $user_id = get_current_user_id();
  if($user_id){
    $query['author'] = $user_id;
  }
  return $query;
}

function ldc_only_show_current_user_attachments(){
  add_filter('ajax_query_attachments_args', 'ldc_only_show_current_user_attachments_func');
}

/** not needed since 4.5.0 */
/*function ldc_get_the_excerpt($post = null, $length = 55){
  $post = get_post($post);
  if(empty($post)){
    return '';
  }
  if(post_password_required($post)){
    return __('There is no excerpt because this is a protected post.');
  }
  $text = $post->post_excerpt;
  if('' == $text){
    $text = $post->post_content;
    $text = strip_shortcodes($text);
    $text = apply_filters('the_content', $text);
    $text = str_replace(']]>', ']]&gt;', $text);
    $excerpt_length = apply_filters('excerpt_length', $length);
    $excerpt_more = apply_filters('excerpt_more', ' ' . '[&hellip;]');
    $text = wp_trim_words($text, $excerpt_length, $excerpt_more);
  }
  return $text;
}*/

/** back-compat */
function ldc_get_the_excerpt($post = null, $length = 55){
  $text = get_the_excerpt($post);
  $excerpt_length = apply_filters('excerpt_length', 55);
  if($length < $excerpt_length){
    $excerpt_more = apply_filters('excerpt_more', ' ' . '[&hellip;]');
    $text = wp_trim_words($text, $length, $excerpt_more);
  }
  return $text;
}
