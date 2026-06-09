<?php 
setlocale (LC_CTYPE, "C");
echo htmlspecialchars ("<>\"&åÄ\n", ENT_COMPAT, "ISO-8859-1");
echo htmlentities ("<>\"&åÄ\n", ENT_COMPAT, "ISO-8859-1");
?>
