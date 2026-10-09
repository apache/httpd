<?php
$rc = $_GET['code'];
header("HTTP/1.1 $rc Custom Status");
flush();
?>