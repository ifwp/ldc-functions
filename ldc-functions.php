<?php

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
  if(wp_parse_url($_SERVER['HTTP_REFERER'], PHP_URL_HOST) === wp_parse_url(site_url(), PHP_URL_HOST)){
    return ldc_url_to_postid($_SERVER['HTTP_REFERER']);
  }
  return 0;
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
