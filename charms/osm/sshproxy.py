"""Module to help with executing commands over SSH."""
##
# Copyright 2016 Canonical Ltd.
# All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
##

# from charmhelpers.core import unitdata
# from charmhelpers.core.hookenv import log

import io
import ipaddress
from packaging import version
import subprocess
import os
import socket
import shlex
import traceback
import sys
import yaml

from shutil import which
from subprocess import (
    check_call,
    Popen,
    CalledProcessError,
    PIPE,
)

from ops.charm import CharmBase, CharmEvents
from ops.framework import StoredState, EventBase, EventSource
from ops.main import main
from ops.model import (
    ActiveStatus,
    BlockedStatus,
    MaintenanceStatus,
    WaitingStatus,
    ModelError,
)
import os
import subprocess
from .proxy_cluster import ProxyCluster

import logging


logger = logging.getLogger(__name__)


APT_MIRROR_SCRIPT = """
#!/bin/bash
set -e

old_archive_mirror=$(awk "/^deb .* $(awk -F= '/DISTRIB_CODENAME=/ {{gsub(/"/,""); print $2}}' /etc/lsb-release) .*main.*\$/{{print \$2;exit}}" /etc/apt/sources.list)
new_archive_mirror={}
sed -i s,$old_archive_mirror,$new_archive_mirror, /etc/apt/sources.list
old_prefix=/var/lib/apt/lists/$(echo $old_archive_mirror | sed 's,.*://,,' | sed 's,/$,,' | tr / _)
new_prefix=/var/lib/apt/lists/$(echo $new_archive_mirror | sed 's,.*://,,' | sed 's,/$,,' | tr / _)
[ "$old_prefix" != "$new_prefix" ] &&
for old in ${{old_prefix}}_*; do
    new=$(echo $old | sed s,^$old_prefix,$new_prefix,)
    if [ -f $old ]; then
      mv $old $new
    fi
done
"""

SECURITY_APT_MIRROR_SCRIPT = """
old_security_mirror=$(awk "/^deb .* $(awk -F= '/DISTRIB_CODENAME=/ {{gsub(/"/,""); print $2}}' /etc/lsb-release)-security .*main.*\$/{{print \$2;exit}}" /etc/apt/sources.list)
new_security_mirror={}
sed -i s,$old_security_mirror,$new_security_mirror, /etc/apt/sources.list
old_prefix=/var/lib/apt/lists/$(echo $old_security_mirror | sed 's,.*://,,' | sed 's,/$,,' | tr / _)
new_prefix=/var/lib/apt/lists/$(echo $new_security_mirror | sed 's,.*://,,' | sed 's,/$,,' | tr / _)
[ "$old_prefix" != "$new_prefix" ] &&
for old in ${{old_prefix}}_*; do
    new=$(echo $old | sed s,^$old_prefix,$new_prefix,)
    if [ -f $old ]; then
      mv $old $new
    fi
done
"""


class SSHKeysInitialized(EventBase):
    def __init__(self, handle, ssh_public_key, ssh_private_key):
        super().__init__(handle)
        self.ssh_public_key = ssh_public_key
        self.ssh_private_key = ssh_private_key

    def snapshot(self):
        return {
            "ssh_public_key": self.ssh_public_key,
            "ssh_private_key": self.ssh_private_key,
        }

    def restore(self, snapshot):
        self.ssh_public_key = snapshot["ssh_public_key"]
        self.ssh_private_key = snapshot["ssh_private_key"]


class ProxyClusterEvents(CharmEvents):
    ssh_keys_initialized = EventSource(SSHKeysInitialized)


class SSHProxyCharm(CharmBase):

    state = StoredState()
    on = ProxyClusterEvents()

    def __init__(self, *args):
        super().__init__(*args)

        self.peers = ProxyCluster(self, "proxypeer")

        # SSH Proxy actions (primitives)
        self.framework.observe(
            self.on.generate_ssh_key_action, self.on_generate_ssh_key_action
        )
        self.framework.observe(
            self.on.get_ssh_public_key_action, self.on_get_ssh_public_key_action
        )
        self.framework.observe(self.on.run_action, self.on_run_action)
        self.framework.observe(
            self.on.verify_ssh_credentials_action, self.on_verify_ssh_credentials_action
        )

        self.framework.observe(
            self.on.proxypeer_relation_changed, self.on_proxypeer_relation_changed
        )

        self.configure_mirrors()

    def configure_mirrors(self):
        juju_version = os.environ.get("JUJU_VERSION")
        if version.parse(juju_version) < version.parse("2.9.4") and self.is_k8s_proxy_charm():
            try:
                if "apt-mirror" in self.config:
                    subprocess.run(
                        ["sh", "-c", APT_MIRROR_SCRIPT.format(self.config["apt-mirror"])],
                        check=True,
                    )
                if "security-apt-mirror" in self.config:
                    subprocess.run(
                        [
                            "sh",
                            "-c",
                            SECURITY_APT_MIRROR_SCRIPT.format(
                                self.config["security-apt-mirror"]
                            ),
                        ],
                        check=True,
                    )
            except CalledProcessError as e:
                logger.error(f"Failed configuring mirrors. Stdout={e.stdout}, Stderr={e.stderr}")

    def is_k8s_proxy_charm(self) -> bool:
        """Check if charm is running on K8s"""
        metadata_path = f'{os.environ["JUJU_CHARM_DIR"]}/metadata.yaml'
        with open(metadata_path) as metadata_file:
            metadata = yaml.safe_load(metadata_file.read())
            return "containers" in metadata or "kubernetes" in metadata.get(
                "series", []
            )

    def get_ssh_proxy(self):
        """Get the SSHProxy instance"""
        proxy = SSHProxy(
            hostname=self.model.config["ssh-hostname"],
            username=self.model.config["ssh-username"],
            password=self.model.config["ssh-password"],
        )
        return proxy

    def on_proxypeer_relation_changed(self, event):
        if self.peers.is_cluster_initialized and not SSHProxy.has_ssh_key():
            pubkey = self.peers.ssh_public_key
            privkey = self.peers.ssh_private_key
            SSHProxy.write_ssh_keys(public=pubkey, private=privkey)
            self.verify_credentials()
        else:
            event.defer()

    def on_config_changed(self, event):
        """Handle changes in configuration"""
        self.verify_credentials()

    def on_install(self, event):
        SSHProxy.install()

    def on_start(self, event):
        """Called when the charm is being installed"""
        if not self.peers.is_joined:
            event.defer()
            return

        if not SSHProxy.has_ssh_key():
            self.unit.status = MaintenanceStatus("Generating SSH keys...")
            pubkey = None
            privkey = None
            if self.unit.is_leader():
                if self.peers.is_cluster_initialized:
                    SSHProxy.write_ssh_keys(
                        public=self.peers.ssh_public_key,
                        private=self.peers.ssh_private_key,
                    )
                else:
                    SSHProxy.generate_ssh_key()
                    self.on.ssh_keys_initialized.emit(
                        SSHProxy.get_ssh_public_key(), SSHProxy.get_ssh_private_key()
                    )
        self.verify_credentials()

    def verify_credentials(self):
        proxy = self.get_ssh_proxy()
        verified, _ = proxy.verify_credentials()
        if verified:
            self.unit.status = ActiveStatus()
        else:
            self.unit.status = BlockedStatus("Invalid SSH credentials.")
        return verified

    #####################
    # SSH Proxy methods #
    #####################
    def on_generate_ssh_key_action(self, event):
        """Generate a new SSH keypair for this unit."""
        if self.model.unit.is_leader():
            if not SSHProxy.generate_ssh_key():
                event.fail("Unable to generate ssh key")
        else:
            event.fail("Unit is not leader")
            return

    def on_get_ssh_public_key_action(self, event):
        """Get the SSH public key for this unit."""
        if self.model.unit.is_leader():
            pubkey = SSHProxy.get_ssh_public_key()
            event.set_results({"pubkey": SSHProxy.get_ssh_public_key()})
        else:
            event.fail("Unit is not leader")
            return

    def on_run_action(self, event):
        """Run an arbitrary command on the remote host."""
        if self.model.unit.is_leader():
            cmd = event.params["command"]
            proxy = self.get_ssh_proxy()
            stdout, stderr = proxy.run(cmd)
            event.set_results({"output": stdout})
            if len(stderr):
                event.fail(stderr)
        else:
            event.fail("Unit is not leader")
            return

    def on_verify_ssh_credentials_action(self, event):
        """Verify the SSH credentials for this unit."""
        unit = self.model.unit
        if unit.is_leader():
            proxy = self.get_ssh_proxy()
            verified, stderr = proxy.verify_credentials()
            if verified:
                event.set_results({"verified": True})
                unit.status = ActiveStatus()
            else:
                event.set_results({"verified": False, "stderr": stderr})
                event.fail("Not verified")
                unit.status = BlockedStatus("Invalid SSH credentials.")

        else:
            event.fail("Unit is not leader")
            return


class LeadershipError(ModelError):
    def __init__(self):
        super().__init__("not leader")


class SSHProxy:
    # The key will be stored in /var/lib/juju/agents, because for k8s operators that's a
    # persisten volume, which means that the keys will be there after reboot
    keys_base_path = "/var/lib/juju/agents/.ssh"
    private_key_path = "{}/id_sshproxy".format(keys_base_path)
    public_key_path = "{}/id_sshproxy.pub".format(keys_base_path)
    key_type = "rsa"
    key_bits = 4096

    def __init__(self, hostname: str, username: str, password: str = ""):
        self.hostname = hostname
        self.username = username
        self.password = password

    @staticmethod
    def install():
        check_call("apt update && apt install -y openssh-client sshpass", shell=True)

    @staticmethod
    def generate_ssh_key():
        """Generate a 4096-bit rsa keypair."""
        if which("ssh-keygen") is None:
            SSHProxy.install()
        if not os.path.exists(SSHProxy.keys_base_path):
            os.mkdir(SSHProxy.keys_base_path)
        if not os.path.exists(SSHProxy.private_key_path):
            cmd = "ssh-keygen -t {} -b {} -N '' -f {}".format(
                SSHProxy.key_type,
                SSHProxy.key_bits,
                SSHProxy.private_key_path,
            )

            try:
                check_call(cmd, shell=True)
            except CalledProcessError:
                return False

        return True

    @staticmethod
    def write_ssh_keys(public, private):
        """Write a 4096-bit rsa keypair."""
        if not os.path.exists(SSHProxy.keys_base_path):
            os.mkdir(SSHProxy.keys_base_path)
        with open(SSHProxy.public_key_path, "w") as f:
            f.write(public)
            f.close()
        with open(SSHProxy.private_key_path, "w") as f:
            f.write(private)
            f.close()

    @staticmethod
    def get_ssh_public_key():
        publickey = ""
        if os.path.exists(SSHProxy.private_key_path):
            with open(SSHProxy.public_key_path, "r") as f:
                publickey = f.read()
        return publickey

    @staticmethod
    def get_ssh_private_key():
        privatekey = ""
        if os.path.exists(SSHProxy.private_key_path):
            with open(SSHProxy.private_key_path, "r") as f:
                privatekey = f.read()
        return privatekey

    @staticmethod
    def has_ssh_key():
        return True if os.path.exists(SSHProxy.private_key_path) else False

    def run(self, cmd: str) -> (str, str):
        """Run a command remotely via SSH.

        Note: The previous behavior was to run the command locally if SSH wasn't
        configured, but that can lead to cases where execution succeeds when you'd
        expect it not to.
        """
        if isinstance(cmd, str):
            cmd = shlex.split(cmd)

        host = self._get_hostname()
        user = self.username
        passwd = self.password
        key = self.private_key_path

        # Make sure we have everything we need to connect
        if host and user:
            return self.ssh(cmd)

        raise Exception("Invalid SSH credentials.")

    def scp(self, source_file, destination_file):
        """Execute an scp command. Requires a fully qualified source and
        destination.

        :param str source_file: Path to the source file
        :param str destination_file: Path to the destination file
        :raises: :class:`CalledProcessError` if the command fails
        """
        if which("sshpass") is None:
            SSHProxy.install()
        cmd = [
            "sshpass",
            "-p",
            self.password,
            "scp",
            "-i",
            os.path.expanduser(self.private_key_path),
            "-o",
            "StrictHostKeyChecking=no",
            "-q",
        ]
        destination = "{}@{}:{}".format(self.username, self.hostname, destination_file)
        cmd.extend([source_file, destination])
        subprocess.run(cmd, check=True)

    def ssh(self, command):
        """Run a command remotely via SSH.

        :param list(str) command: The command to execute
        :return: tuple: The stdout and stderr of the command execution
        :raises: :class:`CalledProcessError` if the command fails
        """

        if which("sshpass") is None:
            SSHProxy.install()
        destination = "{}@{}".format(self.username, self.hostname)
        cmd = [
            "sshpass",
            "-p",
            self.password,
            "ssh",
            "-i",
            os.path.expanduser(self.private_key_path),
            "-o",
            "StrictHostKeyChecking=no",
            "-q",
            destination,
        ]
        cmd.extend(command)
        output = subprocess.run(
            cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        return (
            output.stdout.decode("utf-8").strip(),
            output.stderr.decode("utf-8").strip(),
        )

    def verify_credentials(self):
        """Verify the SSH credentials.

        :return (bool, str): Verified, Stderr
        """
        verified = False
        try:
            (stdout, stderr) = self.run("hostname")
            verified = True
        except CalledProcessError as e:
            stderr = "Command failed: {} ({})".format(" ".join(e.cmd), str(e.output))
        except (TimeoutError, socket.timeout):
            stderr = "Timeout attempting to reach {}".format(self._get_hostname())
        except Exception as error:
            tb = traceback.format_exc()
            stderr = "Unhandled exception: {}".format(tb)
        return verified, stderr

    ###################
    # Private methods #
    ###################
    def _get_hostname(self):
        """Get the hostname for the ssh target.

        HACK: This function was added to work around an issue where the
        ssh-hostname was passed in the format of a.b.c.d;a.b.c.d, where the first
        is the floating ip, and the second the non-floating ip, for an Openstack
        instance.
        """
        return self.hostname.split(";")[0]
