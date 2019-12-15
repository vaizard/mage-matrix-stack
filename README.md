# mage-matrix-stack

Mage-matrix-stack is an Ansible role providing:

- coturn (turn server listening on ports 3478, 3479)
- matrix-synapse (matrix server listening on ports 8448 and 8008)
- mautrix-whatsapp bridge
- mautrix-facebook bridge
- maubot (https://matrix.example.com:29316/_matrix/maubot)
- nginx (serving riot-web, listening on port 80)
- riot-web (glossy web client / frontend to the matrix-synapse server - static webapp written in js)

This role relies on other roles:

- mage-postgres (provides storage for matrix-synapse)
- mage-haproxy (tls terminating reverse proxy)

Mage-matrix-stack expects a proxy/loadbalancer sitting infront and terminating ssl connections.
Mage-matrix-stack requires at least 2 GB RAM on install time, due to crazy RAM usage of npm.

NOTE: To run matrix-stack in production, you should use two containers (matrix, proxy). Forcing the
matrix-stack onto a single machine / into a single container is possible but not recommended.

## Matrix container

## Proxy container
An nginx proxy/loadbalancer container (sporting mage.nginx-proxy and mage.letsencrypt roles) consisting of

- nginx (running as a proxy/loadbalancer only)
- letsencrypt

## How it fits together

```
ANDROID / DESKTOP / IOS client --> https://matrix-server.example.com      [proxy container, nginx (ssl terminator), port 443] --> [matrix container, matrix-synapse, port 8008]
Browsers                       --> https://matrix.example.com             [proxy container, nginx (ssl terminator), port 443] --> [matrix container, nginx, port 80, serving riot-web]
Federation servers             --> https://matrix-server.example.com:8443 [matrix container, matrix-synapse, port 8448]
Clients                        --> matrix-server.example.com              [matrix container, coturn, ports 3478, 3479 - both UDP and TCP traffic]
```

Letsencrypt certificates are used by the proxy container's nginx.
matrix-server.example.com:8443 listeing on port 8443 to servers in federation uses a selfsigned certificate with a 10 year validity.
See https://github.com/matrix-org/synapse#using-a-reverse-proxy-with-synapse why different certificates are used.

Two distict subdomains are used to run the matrix stack because of security reasons. Riot developers do not recommend running Riot
from the same domain name as your Matrix homeserver. The reason is the risk of XSS (cross-site-scripting) vulnerabilities that could
occur if someone caused Riot to load and render malicious user generated content from a Matrix API which then had trusted access to
Riot (or other apps) due to sharing the same domain. While some coarse mitigations are in place to try to protect against this 
situation, it's still not good practice to do it in the first place. See https://github.com/vector-im/vector-web/issues/1977 for details.


### Federation

By default federation is turned of for security reasons. To turn it on, set `restrict_federation: false`.

```
## Example playbook

###########################################
### Container and VM provisioning #########
###########################################

###
### Virtual host (physical machine)
###

- hosts: localhost
  vars:
      main_wan_ip: "192.168.1.233"
      main_lxd_iface: "lxdbr0"
      lxd_provisioning_inventory:
      - name: "proxy"
        image: "ubuntu/xenial/amd64"
        nat:
        - { wan_port: "443", lxd_port: "443" }
        - { wan_port: "80",  lxd_port: "80" }
      - name: "matrix"
        image: "ubuntu/xenial/amd64"
        nat:
        #- { wan_port: "8080", lxd_port: "8080", protocol: tcp }
        - { wan_port: "8448", lxd_port: "8448", protocol: tcp }
        - { wan_port: "3478", lxd_port: "3478", protocol: tcp }
        - { wan_port: "3478", lxd_port: "3478", protocol: udp }
        - { wan_port: "3479", lxd_port: "3479", protocol: tcp }
        - { wan_port: "3479", lxd_port: "3479", protocol: udp }
  roles:
    - role: "mage-vmhost"
    - role: "mage.lxd-provisioning"

###
### Common roles
###

- hosts: all
  roles:
    - role: "mage-update"
- hosts: lxd
  roles:
    - role: "mage-common"


###
### Proxy container
###

- hosts: proxy
  vars:
      nginx_proxy_default_certificate:         "/etc/letsencrypt/live/example.com/fullchain.pem"
      nginx_proxy_default_certificate_key:     "/etc/letsencrypt/live/example.com/privkey.pem"
      nginx_proxy_default_trusted_certificate: "/etc/letsencrypt/live/example.com/fullchain.pem"
      letsencrypt:
         - { email: "admin@example.com", domains: ["example.com", "matrix.example.com", "matrix-server.example.com" ] }
      nginx_proxy_upstream:
      - name: "matrix"
        servers: [ "matrix:80" ]
      - name: "matrix-server"
        servers: [ "matrix:8008" ]
      nginx_proxy_server:
      - name: "matrix.example.com"
        locations:
          - { name: "/", proxy_pass: "http://matrix/" }
      - name: "matrix-server.example.com"
        locations:
          - { name: "/_matrix", proxy_pass: "http://matrix-server/" }


  roles:
    - role: mage.nginx-proxy
    - role: mage.letsencrypt
    - role: mage.nginx-proxy

##########################################
### Containers and VMs ###################
##########################################

- hosts: matrix
  vars:
   # mage.matrix-stack vars
   recaptcha_private_key: <get me on https://www.google.com/recaptcha/>
   recaptcha_public_key: <get me on https://www.google.com/recaptcha/>
   turn_shared_secret: ReplaceThisWithAPropperSecret
   registration_shared_secret: ReplaceThisTooToMakeThingsCount
   hostname_server: matrix-server.example.com
   hostname_webapp: matrix.example.com
   public_baseurl: https://matrix-server.example.com/
   enable_registration: true
   enable_registration_captcha: true
   email_enable_notifs: true
   email_smtp_host: 'mail.example.com'
   email_smtp_port: 587
   email_notif_from: 'Example %(app)s Chat Server <chat@example.com>'
   email_notif_for_new_users: true
   email_smtp_auth: true
   email_smtp_user: 'chat@example.com'
   email_smtp_pass: 'MYverySECRETpassword'
   email_riot_base_url: 'https://matrix.example.com'
   email_require_transport_security: 'True'
   db_password: ReplaceThisWithThePostgresqlPasswordForSynapseDB
   db_name: synapse
   db_host: 127.0.0.1
   db_cp_min: 5
   db_cp_max: 10
   riot_version: HEAD
   restrict_federation: true
   # mage.postgresql vars
   postgresql_version: 9.5
   postgresql_databases:
     - name: synapse
       owner: synapse
       encoding: 'UTF-8'
       lc_collate: 'C'
       lc_ctype: 'C'
   postgresql_users:
     - name: synapse
       pass: ReplaceThisWithThePostgresqlPasswordForSynapseDB
       encrypted: no
   postgresql_user_privileges:
     - name: synapse
       db: synapse
       priv: "ALL"
  roles:
    - mage.postgresql
    - mage.matrix-stack
```

