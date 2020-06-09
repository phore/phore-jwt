<?php
/**
 * Created by PhpStorm.
 * User: matthias
 * Date: 09.06.20
 * Time: 16:45
 */



$facade = new OAuthVerifyFacade("clientid", "clietsecret", "authHostOpenId");

$facade->addRequiredScopes([

]);


$token = $facade->decode("data");
