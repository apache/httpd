<?php
	switch ($_SERVER["REQUEST_METHOD"]) {
	case "GET":
		echo join(" ", array($_GET["v1"],
				     $_GET["v2"],
				     $_GET["v3"]));
		break;
	case "POST":
		echo join(" ", array($_POST["v1"],
				     $_POST["v2"],
				     $_POST["v3"]));
		break;
	default:
		echo "ERROR!";
	}
?>
