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
import subprocess
import os
import socket
import shlex
import traceback
import sys

from subprocess import (
    check_call,
    Popen,
    CalledProcessError,
    PIPE,
)


class SSHProxy:
    private_key_path = "/root/.ssh/id_sshproxy"
    public_key_path = "/root/.ssh/id_sshproxy.pub"
    key_type = "rsa"
    key_bits = 4096

    def __init__(self, hostname: str, username: str, password: str = ""):
        self.hostname = hostname
        self.username = username
        self.password = password

    @staticmethod
    def install():
        check_call("apt update && apt install -y openssh-client", shell=True)

    @staticmethod
    def generate_ssh_key():
        """Generate a 4096-bit rsa keypair."""
        if not os.path.exists(SSHProxy.private_key_path):
            cmd = "ssh-keygen -t {} -b {} -N '' -f {}".format(
                SSHProxy.key_type, SSHProxy.key_bits, SSHProxy.private_key_path,
            )

            try:
                check_call(cmd, shell=True)
            except CalledProcessError:
                return False

        return True

    @staticmethod
    def write_ssh_keys(public, private):
        """Write a 4096-bit rsa keypair."""
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
        """
        cmd = [
            "scp",
            "-i",
            os.path.expanduser(self.private_key_path),
            "-o",
            "StrictHostKeyChecking=no",
            "-q",
            "-B",
        ]
        destination = "{}@{}:{}".format(self.user, self.host, destination_file)
        cmd.extend([source_file, destination])
        check_call(cmd)

    def ssh(self, command):
        """Run a command remotely via SSH.

        :param str command: The command to execute
        :return: tuple: The stdout and stderr of the command execution
        :raises: :class:`CalledProcessError` if the command fails
        """

        destination = "{}@{}".format(self.user, self.host)
        cmd = [
            "ssh",
            "-i",
            os.path.expanduser(self.private_key_path),
            "-o",
            "StrictHostKeyChecking=no",
            "-q",
            destination,
        ]
        cmd.extend([command])
        p = Popen(cmd, stdout=PIPE, stderr=PIPE)
        stdout, stderr = p.communicate()
        return (stdout.decode("utf-8").strip(), stderr.decode("utf-8").strip())

    def verify_credentials(self):
        """Verify the SSH credentials.
        
        :return (bool, str): Verified, Stderr
        """
        try:
            (stdout, stderr) = self.run("hostname")
        except CalledProcessError as e:
            stderr = "Command failed: {} ({})".format(" ".join(e.cmd), str(e.output))
        except (TimeoutError, socket.timeout):
            stderr = "Timeout attempting to reach {}".format(self._get_hostname())
        except Exception as error:
            tb = traceback.format_exc()
            stderr = "Unhandled exception: {}".format(tb)

        if len(stderr) == 0:
            return True, stderr
        return False, stderr

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
