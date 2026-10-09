<?php

function print_stuff($stuff)
{
	print $stuff;
}


function still_working()
{
	return "I'm still alive";
}

function dafna()
{
	static $foo = 0;
	
	print "Dafna!\n";
	print call_user_func("still_working")."\n";
	$foo++;
	return (string) $foo;
}


class dafna_class {
	var $myname;
	function __construct() {
		$this->myname = "Dafna";
	}
	# PHP4 compatibility
	function dafna_class() {
		self::__construct();
	}
	function GetMyName() {
		return $this->myname;
	}
	function SetMyName($name) {
		$this->myname = $name;
	}
};

for ($i=0; $i<200; $i++):
	print "$i\n";
	call_user_func("dafna");
	call_user_func("print_stuff","Hey there!!\n");
	print "$i\n";
endfor;


$dafna = new dafna_class();

print $name=call_user_func(array($dafna, "GetMyName"));
print "\n";

?>
