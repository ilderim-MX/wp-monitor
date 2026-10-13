<?php
// Se ejecuta solo al BORRAR el plugin desde WordPress: limpia todo lo que guardó.
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}
foreach ( array( 'wpm_server', 'wpm_code', 'wpm_last', 'monitor_status_token', 'monitor_status_sitename' ) as $opt ) {
	delete_option( $opt );
}
delete_transient( 'wpm_quota' );
delete_transient( 'wpm_ssl' );
wp_clear_scheduled_hook( 'wpm_send_report' );
