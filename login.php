<?php
namespace App;

use Symfony\Component\Security\Csrf\CsrfTokenManager;
use Symfony\Component\Security\Csrf\TokenGenerator\UriSafeTokenGenerator;

include 'vendor/autoload.php';

$tokenGenerator = new UriSafeTokenGenerator();
$CsrfTokenManager = new CsrfTokenManager($tokenGenerator);
$token = $CsrfTokenManager->getToken('authenticate');
?>


<form action="/" method="post">
    <div class="container">
        <label for="uname"><b>Username</b></label>
        <input type="text" placeholder="Enter Username" value="wouter" name="_username" required>

        <label for="psw"><b>Password</b></label>
        <input type="text" placeholder="Enter Password" value="pa$$word" name="_password" required>

        <label for="psw"><b>Token</b></label>
        <input type="hidden" name="_csrf_token" value="<?php echo $token ?>" required>

        <button type="submit">Login</button>
        <label>
            <input type="checkbox" checked="checked" name="remember"> Remember me
        </label>
    </div>

    <div class="container" style="background-color:#f1f1f1">
        <button type="button" class="cancelbtn">Cancel</button>
        <span class="psw">Forgot <a href="#">password?</a></span>
    </div>
</form>
