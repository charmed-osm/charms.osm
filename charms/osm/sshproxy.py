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

def install_dependencies():
    # Make sure Python3 + PIP are available
    if not os.path.exists("/usr/bin/python3") or not os.path.exists("/usr/bin/pip3"):
        # This is needed when running as a k8s charm, as the ubuntu:latest
        # image doesn't include either package.

        # Update the apt cache
        check_call(["apt-get", "update"])

        # Install the Python3 package
        check_call(["apt-get", "install", "-y", "python3", "python3-pip"],)

    # Install the build dependencies for our requirements (paramiko)
    check_call(["apt-get", "install", "-y", "libffi-dev", "libssl-dev"],)

    check_call(
        [sys.executable, "-m", "pip", "install", "paramiko"],
    )

try:
    import paramiko
except Exception as ex:
    install_dependencies()
    import paramiko

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
            return self._ssh(cmd)

        raise Exception("Invalid SSH credentials.")

    def sftp(self, local, remote):
        client = self._get_ssh_client()

        # Create an sftp connection from the underlying transport
        sftp = paramiko.SFTPClient.from_transport(client.get_transport())
        sftp.put(local, remote)
        client.close()
        pass

    def verify_credentials(self):
        """Verify the SSH credentials.
        
        :return (bool, str): Verified, Stderr
        """
        try:
            (stdout, stderr) = self.run("hostname")
        except CalledProcessError as e:
            stderr = "Command failed: {} ({})".format(" ".join(e.cmd), str(e.output))
        except paramiko.ssh_exception.AuthenticationException as e:
            stderr = "{}.".format(e)
        except paramiko.ssh_exception.BadAuthenticationType as e:
            stderr = "{}".format(e.explanation)
        except paramiko.ssh_exception.BadHostKeyException as e:
            stderr = "Host key mismatch: expected {} but got {}.".format(
                e.expected_key, e.got_key,
            )
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

    def _get_ssh_client(self):
        """Return a connected Paramiko ssh object."""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        pkey = None

        # Otherwise, check for the auto-generated private key
        if os.path.exists(self.private_key_path):
            with open(self.private_key_path) as f:
                pkey = paramiko.RSAKey.from_private_key(f)

        ###########################################################################
        # There is a bug in some versions of OpenSSH 4.3 (CentOS/RHEL 5) where    #
        # the server may not send the SSH_MSG_USERAUTH_BANNER message except when #
        # responding to an auth_none request. For example, paramiko will attempt  #
        # to use password authentication when a password is set, but the server   #
        # could deny that, instead requesting keyboard-interactive. The hack to   #
        # workaround this is to attempt a reconnect, which will receive the right #
        # banner, and authentication can proceed. See the following for more info #
        # https://github.com/paramiko/paramiko/issues/432                         #
        # https://github.com/paramiko/paramiko/pull/438                           #
        ###########################################################################

        try:
            client.connect(
                self.hostname,
                port=22,
                username=self.username,
                password=self.password,
                pkey=pkey,
            )
        except paramiko.ssh_exception.SSHException as e:
            if "Error reading SSH protocol banner" == str(e):
                # Once more, with feeling
                client.connect(
                    host, port=22, username=user, password=password, pkey=pkey
                )
            else:
                # Reraise the original exception
                raise e

        return client

    def _ssh(self, cmd):
        """Run an arbitrary command over SSH.

        Returns a tuple of (stdout, stderr)
        """
        client = self._get_ssh_client()

        cmds = " ".join(cmd)
        stdin, stdout, stderr = client.exec_command(cmds, get_pty=True)
        retcode = stdout.channel.recv_exit_status()
        client.close()  # @TODO re-use connections
        if retcode > 0:
            output = stderr.read().strip()
            raise CalledProcessError(returncode=retcode, cmd=cmd, output=output)
        return (
            stdout.read().decode("utf-8").strip(),
            stderr.read().decode("utf-8").strip(),
        )
