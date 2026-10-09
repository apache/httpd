<?php
	switch ($_SERVER["REQUEST_METHOD"]) {
	case "GET":
		echo $_GET["variable"];
		break;
	case "POST":
		echo $_POST["variable"];
		break;
	default:
		echo "ERROR!";
	}
?>
