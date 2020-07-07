# charms.osm

A Python library to aid the development of charms for Open Source Mano (OSM)

## How to install

```bash
git submodule add https://github.com/canonical/operator mod/operator
git submodule add https://github.com/charmed-osm/charms.osm mod/charms.osm
git submodule add https://github.com/juju/charm-helpers.git mod/charm-helpers  # Only for libansible
```

## SSHProxyCharm

In this section, we show the class you should inherit from in order to develop your SSH Proxy charms.

Example:

```python
from charms.osm.sshproxy import SSHProxyCharm

class MySSHProxyCharm(SSHProxyCharm):

    def __init__(self, framework, key):
        super().__init__(framework, key)

        # Listen to charm events
        self.framework.observe(self.on.config_changed, self.on_config_changed)
        self.framework.observe(self.on.install, self.on_install)
        self.framework.observe(self.on.start, self.on_start)

        # Listen to the touch action event
        self.framework.observe(self.on.touch_action, self.on_touch_action)

    def on_config_changed(self, event):
        """Handle changes in configuration"""
        super().on_config_changed(event)

    def on_install(self, event):
        """Called when the charm is being installed"""
        super().on_install(event)

    def on_start(self, event):
        """Called when the charm is being started"""
        super().on_start(event)

    def on_touch_action(self, event):
        """Touch a file."""

        if self.model.unit.is_leader():
            filename = event.params["filename"]
            proxy = self.get_ssh_proxy()
            stdout, stderr = proxy.run("touch {}".format(filename))
            event.set_results({"output": stdout})
        else:
            event.fail("Unit is not leader")
            return
```

### Attributes and methods available

- Atttributes:
  - state: StoredState object. It can be used to store state data to be shared within a charm across different hooks
- SSH related methods:
  - get_ssh_proxy(): Return an SSHProxy object with which you can then execute scp and ssh commands in the remote machine.
  - verify_credentials(): Return True if it has the right credentials to SSH the remote machine. It also updates the status of the unit.
- Charm related methods: Methods that should be run in specific hooks/events.
  - on_install(): Install dependencies for enabling SSH functionality
  - on_start(): Generate needed SSH keys
  - on_config_changed(): Check if the SSH

### config.yaml

You need to add this in your config.yaml in your charm.

```yaml
options:
  ssh-hostname:
    type: string
    default: ""
    description: "The hostname or IP address of the machine to"
  ssh-username:
    type: string
    default: ""
    description: "The username to login as."
  ssh-password:
    type: string
    default: ""
    description: "The password used to authenticate."
  ssh-public-key:
    type: string
    default: ""
    description: "The public key of this unit."
  ssh-key-type:
    type: string
    default: "rsa"
    description: "The type of encryption to use for the SSH key."
  ssh-key-bits:
    type: int
    default: 4096
    description: "The number of bits to use for the SSH key."

```

### metadata.yaml

You need to add this in your metadata.yaml in your charm.

```yaml
peers:
  proxypeer:
    interface: proxypeer
```

### actions.yaml

You need to add this in your actions.yaml in your charm.

```yaml
# Required by charms.osm.sshproxy
run:
  description: "Run an arbitrary command"
  params:
    command:
      description: "The command to execute."
      type: string
      default: ""
  required:
    - command
generate-ssh-key:
  description: "Generate a new SSH keypair for this unit. This will replace any existing previously generated keypair."
verify-ssh-credentials:
  description: "Verify that this unit can authenticate with server specified by ssh-hostname and ssh-username."
get-ssh-public-key:
  description: "Get the public SSH key for this unit."
```

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
