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
		DirectoryIndex index.mustache index.html
	</Directory>
	
	RewriteEngine on
	
	# unless a directory, remove trailing slash
	RewriteCond %{DOCUMENT_ROOT}%{REQUEST_FILENAME} !-d
	RewriteRule ^(.*)/$ $1 [R=301,L]
	
	# resolve .mustache file for extensionless mustache urls
	RewriteCond %{DOCUMENT_ROOT}%{REQUEST_FILENAME} !-d
	RewriteCond %{DOCUMENT_ROOT}%{REQUEST_FILENAME} !-f
	RewriteCond %{DOCUMENT_ROOT}%{REQUEST_FILENAME}\.mustache -f
	RewriteRule ^(.*)$ $1.mustache [NC,PT,L]
	
	# redirect external .mustache requests to extensionless url
	RewriteCond %{THE_REQUEST} ^[A-Z]+\ /([^/]+/)*[^.#?\ ]+\.mustache([#?][^\ ]*)?\ HTTP/
	RewriteRule ^(([^/]+/)*[^.]+)\.mustache $1 [R=301,L]
	
	<Location ~ "^.*\.[Mm][Uu][Ss][Tt][Aa][Cc][Hh][Ee]$">
		SetHandler perfect-handler
	</Location>

</VirtualHost>
### Sample vhost

```