<?php
// auth.php
/*/ IMPORTANT:
- change username and password
- if you like, you can change session timeout (currently it is 10 minutes)
*/

// --- Security headers ---
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");

// Start session
ini_set('session.cookie_httponly', 1);   // JS cannot read session cookie
// ini_set('session.cookie_secure', 1);  // cookie sent only over HTTPS - use only if you are using HTTPS!
ini_set('session.use_strict_mode', 1);   // prevents session fixation
session_start();

// Include CSRF helper
require_once __DIR__ . "/csrf.php";

// Generate a random nonce for inline scripts
$nonce = base64_encode(random_bytes(16));

// Send CSP header with the nonce included
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-$nonce'; img-src 'self' data:; style-src 'self' 'unsafe-inline'");

// --- CONFIG ---
// Define valid users here (username => bcrypt hash)
$USERS = [
    "admin" => '$2y$10$8RVq260n.fnSKtNUPplDouMHC7aHLZevPP7igQVfswB/hBcUjQa0u',
];
// --------------

// Helper: check login state
function check_login() {
    $inactiveLimit = 10 * 60; // 10 minutes

    // Only apply timeout for logged-in users
    if (!empty($_SESSION['loggedin']) && $_SESSION['loggedin'] === true) {
        if (isset($_SESSION['LAST_ACTIVITY']) && (time() - $_SESSION['LAST_ACTIVITY'] > $inactiveLimit)) {
            // Session expired: destroy and redirect
            session_unset();
            session_destroy();
            header("Location: " . $_SERVER['PHP_SELF']); // redirect to login page
            exit;
        }
        $_SESSION['LAST_ACTIVITY'] = time();
    }

    // If not logged in, show login form
    if (empty($_SESSION['loggedin']) || $_SESSION['loggedin'] !== true) {
        // Preserve ?number=... if present
        if (isset($_GET['number'])) {
            $_SESSION['prefill_number'] = $_GET['number'];
        }
        show_login_form();
        exit;
    }
}

// Show login modal if not logged in (no changes)
function show_login_form($error = "") {
    ?>
    <!DOCTYPE html>
    <html lang="sl">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>RasPBX SMS system</title>
        <style>
        body { margin:0; font-family:sans-serif; background:#f0d5b8; }
        .container { max-width:400px; width:90%; margin:60px auto; border-radius:8px; overflow:hidden; box-shadow:0 2px 6px rgba(0,0,0,0.15); background:#fff; }
        .header { display:flex; align-items:center; justify-content:space-between; background-color:#000; color:#fff; padding:12px 16px; }
        .header h2 { margin:0; font-size:20px; }
        .content { background:#fff; padding:20px; }
        .content label { display:block; margin-bottom:6px; font-weight:bold; }
        .content input[type="text"], .content input[type="password"] { width:100%; padding:10px; margin-bottom:14px; border:1px solid #ccc; border-radius:5px; box-sizing:border-box; font-size:16px; }
        .content button { width:100%; padding:12px; background:#000; color:#fff; border:none; border-radius:5px; cursor:pointer; font-size:16px; transition: opacity 0.2s ease; }
        .content button:hover { opacity:0.85; }
        .error { color:#c00; margin-bottom:12px; }
        @media (max-width:480px){ .container{ margin:20px auto; } .header h2{ font-size:18px; } .content{ padding:16px; } }
        .header img.login-icon{ width:32px; height:32px; object-fit:contain; margin-right:12px; }
        </style>
    </head>
    <body>
    <div class="container">
        <div class="header">
            <h2>RasPBX SMS login</h2>
            <img src="icons/logo.png" alt="Login icon" class="login-icon">
        </div>
        <div class="content">
            <?php if($error){ echo "<div class='error'>".htmlspecialchars($error)."</div>"; } ?>
            <form method="post">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required autocomplete="username">

                <label for="password">Password</label>
                <input type="password" id="password" name="password" required autocomplete="current-password">

                <!-- CSRF token -->
                <?php echo getCsrfInput(); ?>

                <button type="submit">Login</button>
            </form>
        </div>
    </div>
    </body>
    </html>
    <?php
}

// Handle logout
if (isset($_GET['logout'])) {
    $_SESSION = [];
    session_destroy();
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// Process login request
if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST['username'], $_POST['password'])) {
    if (!validateCsrfToken($_POST['csrf_token'] ?? null)) {
        show_login_form("Security check failed. Please try again.");
        exit;
    }

    global $USERS;
    $user = $_POST['username'];
    $pass = $_POST['password'];

    if (isset($USERS[$user]) && password_verify($pass, $USERS[$user])) {
        session_regenerate_id(true);
        $_SESSION['loggedin'] = true;
        $_SESSION['username'] = $user;

        $redirectUrl = $_SERVER['PHP_SELF'];
        if (isset($_SESSION['prefill_number'])) {
            $redirectUrl .= "?number=" . urlencode($_SESSION['prefill_number']);
            unset($_SESSION['prefill_number']);
        }

        header("Location: " . $redirectUrl);
        exit;
    } else {
        show_login_form("Wrong username or password.");
        exit;
    }
}
