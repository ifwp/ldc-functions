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
  $r = false;
  if(!is_user_logged_in()){
    $r = true;
  }
  $r = apply_filters('ldc_restrict_frontend_to_logged_in_users', $r);
  if($r){
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
  $r = false;
  if(!is_user_logged_in()){
    $r = true;
  }
  $r = apply_filters('ldc_restrict_rest_api', $r);
  if($r){
    return new WP_Error('rest_not_logged_in', 'API Requests are only supported for authenticated requests.', array(
      'status' => 401,
    ));
  }
  return $result;
}

function ldc_restrict_rest_api_to_logged_in_users(){
  add_filter('rest_authentication_errors', 'ldc_restrict_rest_api_to_logged_in_users_func');
}
