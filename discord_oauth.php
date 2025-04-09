<?php
session_start();
require_once 'env.php';

$code = $_GET['code'];
$state = $_GET['state'];
$expectedState = $_SESSION['discord_nonce'];

function showUserDetails($token) {
	$ch = curl_init('https://discord.com/api/users/@me');
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
	curl_setopt($ch, CURLOPT_HTTPHEADER, [
	    "Authorization: Bearer $token"
	]);
	$user_info = json_decode(curl_exec($ch), true);
	curl_close($ch);

	foreach ($user_info as $key => $value) {
	    echo "$key: $value<br>";
	}
	echo '<img src="https://cdn.discordapp.com/avatars/'.$user_info['id'].'/'.$user_info['avatar'].'.png" />';
}

$tokenExpirationTime = (int)$_SESSION['discord_accessTokenExpiration'];

if (isset($_SESSION['discord_accessToken']) && $tokenExpirationTime > time()) {
	error_log("Reuse token");
	$token = $_SESSION['discord_accessToken'];
	showUserDetails($token);
} else if (!isset($_SESSION['discord_nonce']) || !isset($_GET['state'])) {
	$nonce = bin2hex(random_bytes(8));
	$_SESSION['discord_nonce'] = $nonce;

	$url = "https://discord.com/oauth2/authorize?response_type=code&client_id=".$discord_clientId."&scope=identify%20email&state=".$nonce."&redirect_uri=".urlencode($discord_redirectUrl);
	header("Location: ".$url);
	
	echo '<a href="'.$url.'">Click if you&apos;re not redirected automatically</a>';
} else if($_SESSION['discord_nonce'] !== $_GET['state']) {
    http_response_code(403);
    exit('Error: state parameter mismatch - access denied.');
} else {
	$data = [
	    'client_id' => $discord_clientId,
	    'client_secret' => $discord_clientSecret,
	    'grant_type' => 'authorization_code',
	    'code' => $code,
	    'redirect_uri' => $discord_redirectUrl,
	    'scope' => 'identify email'
	];

	$ch = curl_init('https://discord.com/api/oauth2/token');
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
	curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
	curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/x-www-form-urlencoded']);
	
	$response = curl_exec($ch);
	$httpStatus = curl_getinfo($ch, CURLINFO_HTTP_CODE);
	curl_close($ch);
	
	if ($httpStatus != 200) {
		echo 'Error '.$httpStatus;
		exit('Discord auth fail');
	}

	$authResponse = json_decode($response, true);

	/*
	token_type: Bearer
	access_token: token here
	expires_in: 604800
	refresh_token: token here
	scope: identify email
	*/
	
	$token = $authResponse['access_token'];
	$_SESSION['discord_accessToken'] = $token;
	$_SESSION['discord_accessTokenExpiration'] = time() + $authResponse['expires_in'] - 10;
	$_SESSION['discord_refreshToken'] = $authResponse['refresh_token'];
	showUserDetails($token);
}
?>

