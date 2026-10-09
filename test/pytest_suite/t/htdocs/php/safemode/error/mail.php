<?php
// fix for CAN-2002-0985: mail() must reject 5th argument in safe mode
if (mail("root@localhost", "httpd-test PHP mail", 
	 "test mail from httpd-test", "", "-C/etc/passwd")) {
	print("FAIL");
} else {
	print("OK");
}
?>
