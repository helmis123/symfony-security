<?php

namespace App;


use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\HttpKernelInterface;


class Kernel implements HttpKernelInterface
{

    public function handle(Request $request, $type = self::MAIN_REQUEST, $catch = true): Response
    {
        return new Response();
    }


}