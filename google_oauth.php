<?php
session_start();
require_once 'env.php'; // Define $google_clientId, $google_clientSecret, $google_redirectUrl

$code = $_GET['code'] ?? null;
$state = $_GET['state'] ?? null;
$expectedState = $_SESSION['google_nonce'] ?? null;

function showUserDetails($token) {
    $ch = curl_init('https://www.googleapis.com/oauth2/v1/userinfo?alt=json');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        "Authorization: Bearer $token"
    ]);
    $user_info = json_decode(curl_exec($ch), true);
    curl_close($ch);

    foreach ($user_info as $key => $value) {
        echo "$key: $value<br>";
    }

    echo '<img src="' . $user_info['picture'] . '" />';
}

$tokenExpirationTime = (int)($_SESSION['google_accessTokenExpiration'] ?? 0);

if (isset($_SESSION['google_accessToken']) && $tokenExpirationTime > time()) {
    error_log("Reuse token");
    $token = $_SESSION['google_accessToken'];
    showUserDetails($token);

} else if (!$expectedState || !$state) {
    // Initial redirect to Google
    $nonce = bin2hex(random_bytes(8));
    $_SESSION['google_nonce'] = $nonce;

    $params = [
        'client_id' => $google_clientId,
        'response_type' => 'code',
        'scope' => 'openid email profile',
        'redirect_uri' => $google_redirectUrl,
        'state' => $nonce,
        'access_type' => 'offline',
        'prompt' => 'consent'
    ];

    $authUrl = 'https://accounts.google.com/o/oauth2/v2/auth?' . http_build_query($params);
    header("Location: $authUrl");
    echo '<a href="' . $authUrl . '">Click if you&apos;re not redirected automatically</a>';

} else if ($expectedState !== $state) {
    http_response_code(403);
    exit('Error: state parameter mismatch - access denied.');

} else {
    // Exchange code for token
    $tokenRequestData = [
        'code' => $code,
        'client_id' => $google_clientId,
        'client_secret' => $google_clientSecret,
        'redirect_uri' => $google_redirectUrl,
        'grant_type' => 'authorization_code'
    ];

    $ch = curl_init('https://oauth2.googleapis.com/token');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($tokenRequestData));
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/x-www-form-urlencoded']);

    $response = curl_exec($ch);
    $httpStatus = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($httpStatus != 200) {
        echo 'Error ' . $httpStatus;
        exit('Google auth failed');
    }

    $authResponse = json_decode($response, true);
    $token = $authResponse['access_token'];

    $_SESSION['google_accessToken'] = $token;
    $_SESSION['google_accessTokenExpiration'] = time() + $authResponse['expires_in'] - 10;
    $_SESSION['google_refreshToken'] = $authResponse['refresh_token'] ?? null;

    showUserDetails($token);
}
?>
