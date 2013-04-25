mod_kapow
=========

Anti-ddos apache module

This is the GPLed source code written by Ed Kaiser Wu-chang Feng

corresponding to the paper also authored by them, titled 

"mod kaPoW: Protecting the Web with TransparentProof-of-Work"

published in Global Internet 08.

http://www.thefengs.com/wuchang/work/puzzles/globalinternet08_kapow.pdf


They gave me permission to release the source code under the GNU GPL (see the accompanying pdf email)



INSTALLATION NOTES:

1) Move kaPoW.js and invalid_pow.php to the root HTTP directory [/var/www/html].

2) Run [apache/bin/] apxs -i -a -c mod_kaPoW.c

3) Modify [apache/conf/] httpd.conf to include these directives:

      <VirtualHost *:80>
         ServerName "Low "
         ServerAlias kapow.cs.pdx.edu *.cs.pdx.edu
         KeepAlive Off
      </VirtualHost>
      <VirtualHost *:80>
         ServerName "High"
         KeepAlive On
         KeepAliveTimeOut 300
         MaxKeepAliveRequests 0
      </VirtualHost>

4) Restart Apache.