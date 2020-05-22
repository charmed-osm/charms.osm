##
# Copyright 2020 Canonical Ltd.
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

import fnmatch
import os
import yaml
import subprocess
import sys

sys.path.append("lib")
import charmhelpers.fetch


ansible_hosts_path = "/etc/ansible/hosts"


def install_ansible_support(from_ppa=True, ppa_location="ppa:ansible/ansible"):
    """Installs the ansible package.

    By default it is installed from the `PPA`_ linked from
    the ansible `website`_ or from a ppa specified by a charm config..

    .. _PPA: https://launchpad.net/~rquillo/+archive/ansible
    .. _website: http://docs.ansible.com/intro_installation.html#latest-releases-via-apt-ubuntu

    If from_ppa is empty, you must ensure that the package is available
    from a configured repository.
    """
    if from_ppa:
        charmhelpers.fetch.add_source(ppa_location)
        charmhelpers.fetch.apt_update(fatal=True)
    charmhelpers.fetch.apt_install("ansible")
    with open(ansible_hosts_path, "w+") as hosts_file:
        hosts_file.write("localhost ansible_connection=local")


def create_hosts(hostname, username, password, hosts):
    inventory_path = "/etc/ansible/hosts"

    with open(inventory_path, "w") as f:
        f.write("[{}]\n".format(hosts))
        h1 = "host ansible_host={0} ansible_user={1} ansible_password={2}\n".format(
            hostname, username, password
        )
        f.write(h1)


def create_ansible_cfg():
    ansible_config_path = "/etc/ansible/ansible.cfg"

    with open(ansible_config_path, "w") as f:
        f.write("[defaults]\n")
        f.write("host_key_checking = False\n")


# Function to find the playbook path
def find(pattern, path):
    result = ""
    for root, dirs, files in os.walk(path):
        for name in files:
            if fnmatch.fnmatch(name, pattern):
                result = os.path.join(root, name)
    return result


def execute_playbook(playbook_file, hostname, user, password, vars_dict=None):
    playbook_path = find(playbook_file, "/var/lib/juju/agents/")

    with open(playbook_path, "r") as f:
        playbook_data = yaml.load(f)

    hosts = "all"
    if "hosts" in playbook_data[0].keys() and playbook_data[0]["hosts"]:
        hosts = playbook_data[0]["hosts"]

    create_ansible_cfg()
    create_hosts(hostname, user, password, hosts)

    call = "ansible-playbook {} ".format(playbook_path)

    if vars_dict and isinstance(vars_dict, dict) and len(vars_dict) > 0:
        call += "--extra-vars "

        string_var = ""
        for k,v in vars_dict.items():
            string_var += "{}={} ".format(k, v)

        string_var = string_var.strip()
        call += '"{}"'.format(string_var)

    call = call.strip()
    result = subprocess.check_output(call, shell=True)

    return result
