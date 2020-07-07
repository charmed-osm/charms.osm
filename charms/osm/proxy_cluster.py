import socket

from ops.framework import Object, StoredState


class ProxyCluster(Object):

    state = StoredState()

    def __init__(self, charm, relation_name):
        super().__init__(charm, relation_name)
        self._relation_name = relation_name
        self._relation = self.framework.model.get_relation(self._relation_name)

        self.framework.observe(charm.on.ssh_keys_initialized, self.on_ssh_keys_initialized)

        self.state.set_default(ssh_public_key=None)
        self.state.set_default(ssh_private_key=None)

    def on_ssh_keys_initialized(self, event):
        if not self.framework.model.unit.is_leader():
            raise RuntimeError("The initial unit of a cluster must also be a leader.")

        self.state.ssh_public_key = event.ssh_public_key
        self.state.ssh_private_key = event.ssh_private_key
        if not self.is_joined:
            event.defer()
            return

        self._relation.data[self.model.app][
            "ssh_public_key"
        ] = self.state.ssh_public_key
        self._relation.data[self.model.app][
            "ssh_private_key"
        ] = self.state.ssh_private_key

    @property
    def is_joined(self):
        return self._relation is not None

    @property
    def ssh_public_key(self):
        if self.is_joined:
            return self._relation.data[self.model.app].get("ssh_public_key")

    @property
    def ssh_private_key(self):
        if self.is_joined:
            return self._relation.data[self.model.app].get("ssh_private_key")

    @property
    def is_cluster_initialized(self):
        return (
            True
            if self.is_joined
            and self._relation.data[self.model.app].get("ssh_public_key")
            and self._relation.data[self.model.app].get("ssh_private_key")
            else False
        )
