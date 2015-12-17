# Perfect - mod_perfect - Apache 2.4 Connector
Write me!

## Linux Build Notes
* cd into mod_perfect
* make

This will automatically install the appropriate Apache development resources if required, potentially prompting you for your sudo password. You must then install the produced mod_perfect.so as you would any other Apache module.

## Configuration

Here is an Apache conf snippet which pipes files/directories which do not exist through to Perfect Server. This is handy if you are using Perfect's URL routing system (or your own system).

```
	RewriteEngine on
	RewriteCond %{REQUEST_FILENAME} !-f
	RewriteCond %{REQUEST_FILENAME} !-d
	RewriteRule (.*) - [L,NS,H=perfect-handler]

```

Here is a sample Apache .conf snippet. This uses mod_rewrite in order to provide extension-less URLs for mustache templates.

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