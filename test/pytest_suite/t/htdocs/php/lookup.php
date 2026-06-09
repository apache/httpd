<?php 
$r = apache_lookup_uri("target.php");
printf("status=%d:method=%s:uri=%s",
       $r->status, $r->method, $r->uri);
?>
