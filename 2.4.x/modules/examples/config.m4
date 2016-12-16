
APACHE_MODPATH_INIT(examples)

APACHE_MODULE(example_hooks, Example hook callback handler module, , , no)
APACHE_MODULE(case_filter, Example uppercase conversion filter, , , no)
APACHE_MODULE(case_filter_in, Example uppercase conversion input filter, , , no)
APACHE_MODULE(example_ipc, Example of shared memory and mutex usage, , , no)

APACHE_MODPATH_FINISH
