<?php 
header("X-Before: foobar");
$r = apache_lookup_uri("target.php");
header("X-After: foobar");

printf("status=%d:method=%s:uri=%s",
       $r->status, $r->method, $r->uri);
?>
