NOTE: AS OF 4/25/2017 DATA IN THIS PLUGIN IS NOT ENCRYPTED AT REST
example: If you input a password for a private key, it is stored in clear text

add this to the lemur.plugins entry_points in /www/lemur/setup.py
        
'linux_destination = lemur.plugins.lemur_linuxdst.plugin:LinuxDstPlugin',

note: DO NOT FORGET TO EXECUTE 'make release' and restart your service after modifying the setup.py
