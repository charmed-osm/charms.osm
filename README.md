# charms.osm
A Python library to aid the development of charms for Open Source Mano (OSM)

## SSHProxy

Example:

```python
from charms.osm.sshproxy import SSHProxy

# Check if SSH Proxy has key
if not SSHProxy.has_ssh_key():
    # Generate SSH Key
    SSHProxy.generate_ssh_key()

# Get generated public and private keys
SSHProxy.get_ssh_public_key()
SSHProxy.get_ssh_private_key()

# Get Proxy
proxy = SSHProxy(
    hostname=config["ssh-hostname"],
    username=config["ssh-username"],
    password=config["ssh-password"],
)

# Verify credentials
verified = proxy.verify_credentials()

if verified:
    # Run commands in remote machine
    proxy.run("touch /home/ubuntu/touch")
```

## Libansible

```python
from charms.osm import libansible

# Install ansible packages in the charm
libansible.install_ansible_support()

result = libansible.execute_playbook(
    "configure-remote.yaml",  # Name of the playbook <-- Put the playbook in playbooks/ folder
    config["ssh-hostname"],
    config["ssh-username"],
    config["ssh-password"],
    dict_vars,  # Dictionary with variables to populate in the playbook
)
```

## Usage

Import submodules:

```bash
git submodule add https://github.com/charmed-osm/charms.osm mod/charms.osm
git submodule add https://github.com/juju/charm-helpers.git mod/charm-helpers  # Only for libansible
```

Add symlinks:

```bash
mkdir -p lib/charms
ln -s ../mod/charms.osm/charms/osm lib/charms/osm
ln -s ../mod/charm-helpers/charmhelpers lib/charmhelpers  # Only for libansible
```
