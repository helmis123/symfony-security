<?php

namespace App;

include 'vendor/autoload.php';


use Symfony\Component\ErrorHandler\Debug;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;


Debug::enable();

$kernel = new Kernel();
$request = Request::createFromGlobals();
$request->setSession(new Session());

try {
    $response = $kernel->handle($request);
} catch (\Exception $e) {
    dd($e);
}
$response->send();

