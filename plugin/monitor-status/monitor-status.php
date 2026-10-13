<?php
/**
 * Plugin Name: WP Monitor
 * Plugin URI:  https://github.com/ilderim-mx/wp-monitor
 * Description: Envía el estado del sitio (actualizaciones, respaldos, disco, SSL y seguridad) a un panel de monitoreo central. Solo necesita el servidor y un código.
 * Version:     1.1.0
 * Requires PHP: 7.4
 * Author:      Ilderim Digital Solutions
 * Author URI:  https://ilderim.mx
 * License:     GPL-2.0-or-later
 * Text Domain: wp-monitor
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'WPM_VERSION', '1.1.0' );
define( 'WPM_DEFAULT_SERVER', 'panel.ilderim.mx' );
define( 'WPM_INTERVAL', 6 * HOUR_IN_SECONDS );
define( 'WPM_HOOK', 'wpm_send_report' );

/* ------------------------------------------------------------------
 * Programación del envío automático
 * ---------------------------------------------------------------- */
add_filter( 'cron_schedules', function ( $schedules ) {
	$schedules['wpm_six_hours'] = array(
		'interval' => WPM_INTERVAL,
		'display'  => 'Cada 6 horas (WP Monitor)',
	);
	return $schedules;
} );

// Se asegura en cada carga de que el envío esté programado (cubre actualizaciones sin reactivar).
add_action( 'init', function () {
	if ( wpm_is_configured() && ! wp_next_scheduled( WPM_HOOK ) ) {
		wp_schedule_event( time() + 300, 'wpm_six_hours', WPM_HOOK );
	}
} );

add_action( WPM_HOOK, 'wpm_send_report' );

register_deactivation_hook( __FILE__, function () {
	wp_clear_scheduled_hook( WPM_HOOK );
} );

// Limpieza de la versión anterior (1.0.x usaba un token y un endpoint REST que ya no existen).
add_action( 'admin_init', function () {
	if ( get_option( 'monitor_status_token' ) !== false ) {
		delete_option( 'monitor_status_token' );
		delete_option( 'monitor_status_sitename' );
	}
} );

/* ------------------------------------------------------------------
 * Configuración
 * ---------------------------------------------------------------- */
function wpm_server() {
	return get_option( 'wpm_server', WPM_DEFAULT_SERVER );
}

function wpm_code() {
	return (string) get_option( 'wpm_code', '' );
}

function wpm_is_configured() {
	return wpm_server() !== '' && strpos( wpm_code(), 'ilm_' ) === 0;
}

function wpm_clean_server( $raw ) {
	$s = strtolower( trim( (string) $raw ) );
	$s = preg_replace( '#^https?://#', '', $s );
	$s = rtrim( $s, '/' );
	return preg_match( '/^[a-z0-9.-]+(:\d{2,5})?$/', $s ) ? $s : '';
}

/* ------------------------------------------------------------------
 * Envío del reporte
 * ---------------------------------------------------------------- */
function wpm_send_report() {
	if ( ! wpm_is_configured() ) {
		return wpm_save_result( 0, 'Falta configurar el servidor o el código.' );
	}
	$response = wp_remote_post( 'https://' . wpm_server() . '/api/v1/report', array(
		'timeout'    => 25,
		'headers'    => array(
			'Authorization' => 'Bearer ' . wpm_code(),
			'Content-Type'  => 'application/json',
		),
		'user-agent' => 'WP-Monitor/' . WPM_VERSION . '; ' . home_url(),
		'body'       => wp_json_encode( wpm_collect() ),
	) );

	if ( is_wp_error( $response ) ) {
		return wpm_save_result( 0, 'No se pudo conectar con el servidor: ' . $response->get_error_message() );
	}
	$code = (int) wp_remote_retrieve_response_code( $response );
	$body = json_decode( wp_remote_retrieve_body( $response ), true );
	$err  = is_array( $body ) && isset( $body['error'] ) ? $body['error'] : '';

	$messages = array(
		'invalid_code' => 'El código no es válido. Revisa que lo hayas copiado completo.',
		'no_code'      => 'El código no es válido.',
		'revoked'      => 'Este código fue revocado en el panel.',
		'url_mismatch' => 'Este código ya está ligado a otro sitio. Pide uno nuevo.',
		'too_soon'     => 'Se envió un reporte hace menos de un minuto. Intenta de nuevo en un momento.',
		'no_site_url'  => 'El sitio no reportó su URL.',
		'bad_json'     => 'El servidor no entendió el reporte.',
	);

	if ( 200 === $code && ! empty( $body['ok'] ) ) {
		$name = isset( $body['name'] ) ? sanitize_text_field( $body['name'] ) : '';
		return wpm_save_result( 200, 'Conectado' . ( $name ? ' como «' . $name . '»' : '' ) . '.' );
	}
	if ( isset( $messages[ $err ] ) ) {
		return wpm_save_result( $code, $messages[ $err ] );
	}
	if ( 403 === $code ) {
		return wpm_save_result( $code, 'El servidor rechazó la conexión (403). Puede ser un firewall o la protección del panel.' );
	}
	return wpm_save_result( $code, 'Respuesta inesperada del servidor (HTTP ' . $code . ').' );
}

function wpm_save_result( $http, $message ) {
	$result = array(
		'time'    => time(),
		'http'    => (int) $http,
		'ok'      => 200 === (int) $http,
		'message' => $message,
	);
	update_option( 'wpm_last', $result, false );
	return $result;
}

/* ------------------------------------------------------------------
 * Recolección de datos
 * ---------------------------------------------------------------- */
function wpm_collect() {
	require_once ABSPATH . 'wp-admin/includes/update.php';
	require_once ABSPATH . 'wp-admin/includes/plugin.php';
	require_once ABSPATH . 'wp-admin/includes/file.php';
	require_once ABSPATH . 'wp-admin/includes/misc.php';

	return array(
		'plugin_version' => WPM_VERSION,
		'sitio'          => wp_parse_url( home_url(), PHP_URL_HOST ),
		'timestamp'      => current_time( 'c' ),
		'wordpress'      => wpm_wp_info(),
		'plugins'        => wpm_plugins_info(),
		'backuply'       => wpm_backup_info(),
		'disk'           => wpm_disk_info(),
		'ssl'            => wpm_ssl_info(),
		'uptime'         => array( 'last_check' => current_time( 'c' ), 'status' => 'online' ),
		'security'       => wpm_security_info(),
		'php_version'    => PHP_VERSION,
	);
}

function wpm_wp_info() {
	global $wp_version;
	$updates      = get_core_updates();
	$needs_update = false;
	if ( is_array( $updates ) ) {
		foreach ( $updates as $u ) {
			if ( isset( $u->response, $u->current ) && 'upgrade' === $u->response
				&& version_compare( $wp_version, $u->current, '<' ) ) {
				$needs_update = true;
				break;
			}
		}
	}
	return array(
		'version'      => $wp_version,
		'needs_update' => $needs_update,
		'site_url'     => home_url(),
		'admin_email'  => get_option( 'admin_email' ),
	);
}

function wpm_plugins_info() {
	$all     = get_plugins();
	$updates = get_plugin_updates();
	$list    = array();
	$active  = 0;
	foreach ( $all as $file => $p ) {
		$is_active = is_plugin_active( $file );
		$active   += $is_active ? 1 : 0;
		$list[]    = array(
			'name'         => $p['Name'],
			'version'      => $p['Version'],
			'needs_update' => isset( $updates[ $file ] ),
			'active'       => $is_active,
			'author'       => wp_strip_all_tags( $p['Author'] ),
		);
	}
	return array(
		'total'        => count( $all ),
		'active'       => $active,
		'needs_update' => count( $updates ),
		'lista'        => $list,
	);
}

function wpm_backup_info() {
	$info = array(
		'installed'     => false,
		'status'        => 'not_installed',
		'scheduled'     => false,
		'next_run'      => null,
		'last_backup'   => null,
		'last_auto'     => null,
		'last_size_mb'  => null,
		'last_location' => null,
		'local_count'   => 0,
		'local_mb'      => 0,
		'backups'       => array(),
	);
	if ( ! defined( 'BACKUPLY_VERSION' ) && ! get_option( 'backuply_version' ) ) {
		return $info;
	}
	$info['installed'] = true;
	$info['status']    = 'no_backups';
	$base              = WP_CONTENT_DIR . '/backuply';

	// Registro de cada respaldo (Backuply lo conserva aunque el archivo se vaya a la nube).
	$records = array();
	foreach ( ( glob( $base . '/backups_info-*/*.php' ) ?: array() ) as $file ) {
		if ( 'index.php' === basename( $file ) ) {
			continue;
		}
		$raw = @file_get_contents( $file );
		if ( false === $raw ) {
			continue;
		}
		$json = json_decode( trim( preg_replace( '/^<\?php.*?\?>/s', '', $raw ) ), true );
		if ( is_array( $json ) && ! empty( $json['btime'] ) ) {
			$records[] = $json;
		}
	}
	usort( $records, function ( $a, $b ) {
		return (int) $b['btime'] - (int) $a['btime'];
	} );
	foreach ( array_slice( $records, 0, 5 ) as $r ) {
		$info['backups'][] = array(
			'date'     => gmdate( 'c', (int) $r['btime'] ),
			'size_mb'  => isset( $r['size'] ) ? round( $r['size'] / 1048576, 1 ) : null,
			'auto'     => ! empty( $r['auto_backup'] ),
			'location' => ! empty( $r['backup_location'] ) ? (string) $r['backup_location'] : 'local',
		);
	}
	$last_ts = $records ? (int) $records[0]['btime'] : (int) get_option( 'backuply_last_backup' );
	if ( $last_ts > 0 ) {
		$info['last_backup'] = gmdate( 'c', $last_ts );
		$info['status']      = 'ok';
	}
	if ( $info['backups'] ) {
		$info['last_auto']     = $info['backups'][0]['auto'];
		$info['last_size_mb']  = $info['backups'][0]['size_mb'];
		$info['last_location'] = $info['backups'][0]['location'];
	}

	// ¿Hay respaldos automáticos programados? (eventos de Backuply que no son mantenimiento)
	$crons = _get_cron_array();
	if ( is_array( $crons ) ) {
		foreach ( $crons as $ts => $hooks ) {
			foreach ( array_keys( (array) $hooks ) as $hook ) {
				if ( false !== stripos( $hook, 'backuply' ) && false === stripos( $hook, 'clean' )
					&& false === stripos( $hook, 'update' ) ) {
					$info['scheduled'] = true;
					if ( null === $info['next_run'] || $ts < strtotime( $info['next_run'] ) ) {
						$info['next_run'] = gmdate( 'c', (int) $ts );
					}
				}
			}
		}
	}

	// ¿Respaldo en curso o atorado?
	if ( get_option( 'backuply_status' ) ) {
		$log            = $base . '/backuply_log.php';
		$age            = file_exists( $log ) ? time() - filemtime( $log ) : PHP_INT_MAX;
		$info['status'] = ( $age > 3 * HOUR_IN_SECONDS ) ? 'hung' : 'running';
	}

	// Copias locales que siguen ocupando espacio.
	$bytes = 0;
	foreach ( ( glob( $base . '/backups-*/*.tar.gz' ) ?: array() ) as $f ) {
		$info['local_count']++;
		$bytes += (int) @filesize( $f );
	}
	$info['local_mb'] = round( $bytes / 1048576, 1 );
	return $info;
}

function wpm_dir_size( $path ) {
	if ( ! is_dir( $path ) ) {
		return 0;
	}
	$size = 0;
	try {
		$it = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $path, FilesystemIterator::SKIP_DOTS ),
			RecursiveIteratorIterator::LEAVES_ONLY,
			RecursiveIteratorIterator::CATCH_GET_CHILD
		);
		foreach ( $it as $file ) {
			if ( $file->isFile() ) {
				$size += $file->getSize();
			}
		}
	} catch ( Exception $e ) {
		// Carpeta ilegible: devolvemos lo que se alcanzó a contar.
	}
	return $size;
}

function wpm_disk_info() {
	$uploads = wp_upload_dir();
	$info    = array(
		'backups_folder_mb' => round( wpm_dir_size( WP_CONTENT_DIR . '/backuply' ) / 1048576, 1 ),
		'uploads_folder_mb' => round( wpm_dir_size( $uploads['basedir'] ) / 1048576, 1 ),
		'quota_used_mb'     => null,
		'quota_limit_mb'    => null,
		'total_space_gb'    => null,
		'used_percent'      => null,
		'source'            => 'unavailable',
	);

	// Cuota real de la cuenta cPanel (si el hosting lo permite).
	$quota = get_transient( 'wpm_quota' );
	if ( false === $quota ) {
		$quota    = array();
		$disabled = array_map( 'trim', explode( ',', (string) ini_get( 'disable_functions' ) ) );
		if ( function_exists( 'shell_exec' ) && ! in_array( 'shell_exec', $disabled, true ) ) {
			$bin  = is_executable( '/usr/bin/uapi' ) ? '/usr/bin/uapi' : '/usr/local/cpanel/bin/uapi';
			$out  = is_executable( $bin ) ? @shell_exec( escapeshellcmd( $bin ) . ' --output=json Quota get_quota_info 2>/dev/null' ) : null;
			$json = $out ? json_decode( $out, true ) : null;
			$d    = ( is_array( $json ) && isset( $json['result']['data'] ) ) ? $json['result']['data'] : null;
			if ( is_array( $d ) && isset( $d['megabytes_used'] ) ) {
				$quota = array(
					'used'  => (float) $d['megabytes_used'],
					'limit' => isset( $d['megabyte_limit'] ) ? (float) $d['megabyte_limit'] : 0,
				);
			}
		}
		set_transient( 'wpm_quota', $quota, 30 * MINUTE_IN_SECONDS );
	}
	if ( ! empty( $quota['used'] ) ) {
		$info['quota_used_mb'] = round( $quota['used'], 1 );
		$info['source']        = 'cpanel';
		if ( ! empty( $quota['limit'] ) ) {
			$info['quota_limit_mb'] = round( $quota['limit'], 1 );
			$info['total_space_gb'] = round( $quota['limit'] / 1024, 2 );
			$info['used_percent']   = round( $quota['used'] / $quota['limit'] * 100, 1 );
		}
	}
	return $info;
}

function wpm_ssl_info() {
	$host = wp_parse_url( home_url(), PHP_URL_HOST );
	$info = array( 'enabled' => 0 === strpos( home_url(), 'https://' ), 'expires' => null, 'days_left' => null );
	if ( ! $info['enabled'] || ! $host ) {
		return $info;
	}
	$cached = get_transient( 'wpm_ssl' );
	if ( is_array( $cached ) ) {
		return array_merge( $info, $cached );
	}
	$ctx    = stream_context_create( array( 'ssl' => array(
		'capture_peer_cert' => true,
		'verify_peer'       => false,
		'verify_peer_name'  => false,
		'SNI_enabled'       => true,
		'peer_name'         => $host,
	) ) );
	$client = @stream_socket_client( 'ssl://' . $host . ':443', $errno, $errstr, 10, STREAM_CLIENT_CONNECT, $ctx );
	$data   = array();
	if ( $client ) {
		$params = stream_context_get_params( $client );
		$cert   = isset( $params['options']['ssl']['peer_certificate'] ) ? openssl_x509_parse( $params['options']['ssl']['peer_certificate'] ) : null;
		if ( $cert && ! empty( $cert['validTo_time_t'] ) ) {
			$data = array(
				'expires'   => gmdate( 'Y-m-d', $cert['validTo_time_t'] ),
				'days_left' => (int) floor( ( $cert['validTo_time_t'] - time() ) / DAY_IN_SECONDS ),
			);
		}
		fclose( $client );
	}
	set_transient( 'wpm_ssl', $data, 12 * HOUR_IN_SECONDS );
	return array_merge( $info, $data );
}

function wpm_security_info() {
	$counts   = count_users();
	$admins   = isset( $counts['avail_roles']['administrator'] ) ? (int) $counts['avail_roles']['administrator'] : 0;
	$new_24h  = get_users( array(
		'fields'     => 'ID',
		'date_query' => array( array( 'after' => '24 hours ago', 'inclusive' => true ) ),
	) );
	$new_adm  = get_users( array(
		'fields'     => 'ID',
		'role'       => 'administrator',
		'date_query' => array( array( 'after' => '24 hours ago', 'inclusive' => true ) ),
	) );
	$comments = wp_count_comments();
	return array(
		'users_total'         => (int) $counts['total_users'],
		'users_change_24h'    => '+' . count( $new_24h ),
		'admin_users'         => $admins,
		'comments_pending'    => (int) $comments->moderated,
		'comments_spam'       => (int) $comments->spam,
		'suspicious_activity' => count( $new_adm ) > 0 || count( $new_24h ) > 10,
	);
}

/* ------------------------------------------------------------------
 * Pantalla de ajustes: Ajustes → WP Monitor
 * ---------------------------------------------------------------- */
add_action( 'admin_menu', function () {
	add_options_page( 'WP Monitor', 'WP Monitor', 'manage_options', 'wp-monitor', 'wpm_settings_page' );
} );

add_filter( 'plugin_action_links_' . plugin_basename( __FILE__ ), function ( $links ) {
	array_unshift( $links, '<a href="' . esc_url( admin_url( 'options-general.php?page=wp-monitor' ) ) . '">Ajustes</a>' );
	return $links;
} );

add_action( 'admin_post_wpm_save', function () {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( 'Sin permisos.' );
	}
	check_admin_referer( 'wpm_save' );

	$server = wpm_clean_server( wp_unslash( $_POST['wpm_server'] ?? '' ) );
	update_option( 'wpm_server', $server ? $server : WPM_DEFAULT_SERVER, false );

	$code = trim( sanitize_text_field( wp_unslash( $_POST['wpm_code'] ?? '' ) ) );
	if ( '' !== $code ) { // vacío = conservar el código actual
		update_option( 'wpm_code', $code, false );
	}

	if ( isset( $_POST['wpm_disconnect'] ) ) {
		delete_option( 'wpm_code' );
		wp_clear_scheduled_hook( WPM_HOOK );
		wpm_save_result( 0, 'Desconectado.' );
	} else {
		wp_clear_scheduled_hook( WPM_HOOK );
		wpm_send_report();
		if ( wpm_is_configured() ) {
			wp_schedule_event( time() + WPM_INTERVAL, 'wpm_six_hours', WPM_HOOK );
		}
	}
	wp_safe_redirect( admin_url( 'options-general.php?page=wp-monitor' ) );
	exit;
} );

function wpm_settings_page() {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}
	$code = wpm_code();
	$last = get_option( 'wpm_last' );
	$next = wp_next_scheduled( WPM_HOOK );
	?>
	<div class="wrap">
		<h1>WP Monitor</h1>
		<p>Conecta este sitio al panel de monitoreo. Solo necesitas el <strong>servidor</strong> y el <strong>código</strong> que te dio tu proveedor.</p>

		<?php if ( is_array( $last ) ) : ?>
			<div class="notice notice-<?php echo $last['ok'] ? 'success' : 'error'; ?> inline">
				<p><strong><?php echo esc_html( $last['message'] ); ?></strong>
				<br><span class="description">Último intento: <?php echo esc_html( wp_date( 'd/m/Y H:i', $last['time'] ) ); ?>
				<?php if ( $last['http'] ) : ?> · HTTP <?php echo (int) $last['http']; ?><?php endif; ?></span></p>
			</div>
		<?php endif; ?>

		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<input type="hidden" name="action" value="wpm_save">
			<?php wp_nonce_field( 'wpm_save' ); ?>
			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><label for="wpm_server">Servidor</label></th>
					<td><input name="wpm_server" id="wpm_server" type="text" class="regular-text"
						value="<?php echo esc_attr( wpm_server() ); ?>" placeholder="<?php echo esc_attr( WPM_DEFAULT_SERVER ); ?>">
						<p class="description">Sin <code>https://</code>. Ejemplo: <code><?php echo esc_html( WPM_DEFAULT_SERVER ); ?></code></p></td>
				</tr>
				<tr>
					<th scope="row"><label for="wpm_code">Código</label></th>
					<td><input name="wpm_code" id="wpm_code" type="password" class="regular-text" autocomplete="off"
						placeholder="<?php echo $code ? esc_attr( 'Guardado (termina en …' . substr( $code, -4 ) . ')' ) : 'ilm_…'; ?>">
						<p class="description">Déjalo vacío para conservar el código guardado.</p></td>
				</tr>
			</table>
			<p>
				<?php submit_button( 'Guardar y conectar', 'primary', 'submit', false ); ?>
				<?php if ( $code ) : ?>
					<?php submit_button( 'Desconectar', 'secondary', 'wpm_disconnect', false, array( 'onclick' => "return confirm('¿Desconectar este sitio del panel?');" ) ); ?>
				<?php endif; ?>
			</p>
		</form>

		<?php if ( $next ) : ?>
			<p class="description">Próximo envío automático: <?php echo esc_html( wp_date( 'd/m/Y H:i', $next ) ); ?> (cada 6 horas).</p>
		<?php endif; ?>
	</div>
	<?php
}
