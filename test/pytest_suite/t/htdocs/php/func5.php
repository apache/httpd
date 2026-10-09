<?php

$file = $_SERVER["argv"][0];

function foo()
{
        global $file;

        $fp = fopen($file, "w");
        if( $fp )
        {
                fclose($fp);
        }
        else
        {
                // Attempt to alert the user
                error_log("can't write $file.", 0);
        }
}

register_shutdown_function("foo");

print "foo() will be called on shutdown...\n";

?>
