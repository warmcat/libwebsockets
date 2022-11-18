# lws minimal http client auth digest

A minimal example on how to perform digest authentification on a non secure Apache2 server configured with digest auth

Testing configuration for apache2 :

/etc/apache2/conf-enabled

```
....
<Directory /var/www/html/digest >
  AuthType Digest
  AuthName "test"
  AuthDigestProvider file
  AuthUserFile "/etc/apache2/conf-available/.htpasswd"
  AuthDigestDomain /
  Require valid-user
</Directory>
...
```

Generate htdigest file :

```
 $ htdigest -c /etc/apache2/conf-available/.htpasswd REALM USER
 > Password prompt

```

mkdir -p /var/www/html/digest

## build

```
 $ cmake . && make
```

## usage

./lws-minimal-http-client-digest-auth --user=USER --password=PASSWORD --server 127.0.0.1 -p 80 --path "/digest/"



