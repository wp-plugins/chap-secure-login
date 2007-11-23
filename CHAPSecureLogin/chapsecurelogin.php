<?php
/*
Plugin Name: Chap Secure Login
Plugin URI: http://www.redsend.org/chapsecurelogin/
Description: Do not show password, during login, on an insecure channel (without SSL).
Version: 1.2
Author: Enrico Rossomando (redsend)
Author URI: http://www.redsend.org
*/

/*  Copyright 2007  Enrico Rossomando (email : redsend@gmail.com)

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

function generate_challenge(){

	session_start();

	if(!isset($_SESSION['challenge']))
		$_SESSION['challenge']=md5(rand(1,100000));
}

add_action('wp_authenticate', 'generate_challenge');


function generate_javascript(){
		
	?>
	
	<script language="javascript" type="text/javascript" src="<?php echo get_option('siteurl');?>/wp-content/plugins/CHAPSecureLogin/md5.js" ></script>
	<script language="javascript" type="text/javascript">
		function doCHAP (){
		
			var userid = document.getElementById('user_login');
			var psw = document.getElementById('user_pass');
			
			if (!userid.value || !psw.value)
				return false;
			
			var password = psw.value;
			
			psw.value=hex_md5(hex_md5(password)+'<?php echo $_SESSION['challenge']?>');
			return true;
		
		}
	</script>
	
	<?php
}

add_action('login_head', 'generate_javascript');



function integrate_CHAP_login_form(){

	?>
	
	<script language="javascript" type="text/javascript">
		var form_login = document.getElementById('loginform');
		form_login.onsubmit = function (){ return doCHAP();};
	</script>
	
	<?php

}

add_action('login_form', 'integrate_CHAP_login_form');



if( !function_exists('wp_login') ) :
function wp_login($username, $password, $already_md5 = false){
	global $wpdb, $error;

	if ( '' == $username )
		return false;

	if ( '' == $password ) {
		$error = __('<strong>ERROR</strong>: The password field is empty.');
		return false;
	}

	$login = get_userdatabylogin($username);
	//$login = $wpdb->get_row("SELECT ID, user_login, user_pass FROM $wpdb->users WHERE user_login = '$username'");

	if (!$login) {
		$error = __('<strong>ERROR</strong>: Invalid username.');
		return false;
	} else {
	
		session_start();
		
		if ( 	($already_md5 && md5(md5(md5($login->user_pass.$_SESSION['challenge']))) == $password) || 
			($login->user_login == $username && md5($login->user_pass.$_SESSION['challenge']) == $password) ) {
			return true;
		} else {
			$error = __('<strong>ERROR</strong>: Incorrect password.');
			$pwd = '';
			return false;
		}
	}
}
endif;



function destroy_CHAP_challenge(){
	session_start();
	unset($_SESSION['challenge']);
}

add_action('wp_logout', 'destroy_CHAP_challenge');

?>