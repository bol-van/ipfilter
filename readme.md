This tool allows to filter incoming IP list stream using another IP/subnet/range list. Available modes are `exclude` and `intersect`.

Command line parameters :

     -4                             ; ipv4 list (default)
     -6                             ; ipv6 list
     --mode                         ; intersect or exclude
     --filter                       ; filter subnet list file

Input must be ip address list read from stdin. May not include subnets and ranges but allows /32 or /128.
Filter may contain ip addresses, ranges `ip1-ip2` and `ip/prefixlen`
Output goes to stdout.
