# Perfect - mod_perfect - Apache 2.4 Connector
Write me!
But here is a sample Apache .conf snippet. This uses mod_rewrite in order to provide extension-less URLs.

```
<IfModule !perfect_module>
	LoadModule perfect_module /path/to/mod_perfect.dylib
</IfModule>

<IfModule !rewrite_module>
	LoadModule rewrite_module libexec/apache2/mod_rewrite.so
</IfModule>

### Sample vhost
<VirtualHost *:80>

	ServerName my-server.local
	DocumentRoot "/path/to/my-server/webroot"
	
	<Directory "/path/to/my-server/webroot">
		Require all granted
		DirectoryIndex index.moustache index.html
	</Directory>
	
	RewriteEngine on
	
	# unless a directory, remove trailing slash
	RewriteCond %{DOCUMENT_ROOT}%{REQUEST_FILENAME} !-d
	RewriteRule ^(.*)/$ $1 [R=301,L]
	
	# resolve .moustache file for extensionless moustache urls
	RewriteCond %{DOCUMENT_ROOT}%{REQUEST_FILENAME} !-d
	RewriteCond %{DOCUMENT_ROOT}%{REQUEST_FILENAME} !-f
	RewriteCond %{DOCUMENT_ROOT}%{REQUEST_FILENAME}\.moustache -f
	RewriteRule ^(.*)$ $1.moustache [NC,PT,L]
	
	# redirect external .moustache requests to extensionless url
	RewriteCond %{THE_REQUEST} ^[A-Z]+\ /([^/]+/)*[^.#?\ ]+\.moustache([#?][^\ ]*)?\ HTTP/
	RewriteRule ^(([^/]+/)*[^.]+)\.moustache $1 [R=301,L]
	
	<Location ~ "^.*\.[Mm][Oo][Uu][Ss][Tt][Aa][Cc][Hh][Ee]$">
		SetHandler perfect-handler
	</Location>

</VirtualHost>
### Sample vhost

```