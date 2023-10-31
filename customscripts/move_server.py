import re

from _common import Importer, format_logs, SWITCH_INTERFACES_PREFIX_ALLOWLIST

from dcim.models import Device
from extras.scripts import ChoiceVar, ObjectVar, Script, StringVar


class MoveServer(Script, Importer):
    class Meta:
        name = "Move a server within the same row"
        description = "More exactly: keep the same vlan and IP."
        commit_default = False

    device = ObjectVar(
        required=True,
        description=("Server. (Required)"),
        model=Device,
        query_params={
            'role': 'server',
        }
    )
    z_nbdevice = ObjectVar(
        required=True,
        label="New switch",
        description=("New top of rack switch. (Required)"),
        model=Device,
        query_params={
            'role': ('asw', 'cloudsw'),
            'status': ('active', 'staged'),
        }
    )
    z_iface = StringVar(label="Switch interface", description="Switch interface. (Required)", required=True)

    position = ChoiceVar(
        required=True,
        choices=[(i, i) for i in range(48)],
        label="New rack unit",
        description=("Rack will be the same as the new top of rack switch."),
    )
    cable_id = StringVar(label="Cable ID", required=False)

    def run(self, data, commit):
        """Run the script and return all the log messages."""
        self.log_info(f"Called with parameters: {data}")
        self.move_server(data)
        return format_logs(self.log)

    def move_server(self, data):
        """Process a single device."""
        device = data['device']
        z_nbdevice = data['z_nbdevice']
        z_iface = data['z_iface']
        position = data['position']
        cable_id = data['cable_id']

        if not z_nbdevice or z_iface == '':
            self.log_failure(
                f"{device}: New switch or switch interface missing, skipping."
            )
            return

        if z_nbdevice.status not in ('active', 'staged'):
            self.log_failure(f"{device}: switch {z_nbdevice} with status {z_nbdevice.status}, "
                             "expected Active or Staged, skipping.")
            return

        if int(position) == 0:
            self.log_failure(f"{device}: Rack unit can't be 0, skipping.")
            return

        if device.device_role.slug != "server":
            self.log_failure(
                f"{device.name}: role {device.device_role}, only servers are supported, skipping."
            )
            return

        if z_nbdevice.device_role.slug not in ('asw', 'cloudsw'):
            self.log_failure(f"{device}: switch {z_nbdevice} with role {z_nbdevice.device_role}, "
                             "only switches are supported, skipping.")
            return

        if not re.match(f"^{'|'.join(SWITCH_INTERFACES_PREFIX_ALLOWLIST)}", z_iface):
            self.log_failure(f"{device}: Switch interface {z_iface} invalid, must start with "
                             f"{' or '.join(SWITCH_INTERFACES_PREFIX_ALLOWLIST)}.")
            return

        if z_nbdevice.virtual_chassis:
            zint_vc_id = int(z_iface.split("-")[1].split("/")[0])  # Juniper VC only
            if zint_vc_id != z_nbdevice.vc_position:
                self.log_failure(f"{device}: Interface name {z_iface} invalid, first digit of port "
                                 f"number should be {z_nbdevice.vc_position}, matching {z_nbdevice.name} "
                                 "virtual-chassis postition.")
                return

        nbiface = self.find_main_interface(device)
        if not nbiface:
            return
        z_old_nbiface = self.find_remote_interface(nbiface)

        # Configure the new switch interface
        z_nbiface = self._update_z_nbiface(z_nbdevice, z_iface, z_old_nbiface.untagged_vlan, z_old_nbiface.type,
                                           list(z_old_nbiface.tagged_vlans.all()))
        if z_nbiface.cable:
            # TODO replace with raise AbortScript
            self.log_failure(f"There is already a cable on {z_nbiface.device}:{z_nbiface} (typo?), skipping.")
            return

        # Clean the old one
        self.clean_interface(z_old_nbiface)
        self.log_success(f"{device}: reset old switch interface {z_old_nbiface.device}:{z_old_nbiface}.")

        # Remove the old cable
        nbiface.cable.delete()
        # After deleting the cable refresh the interface, otherwise
        # nbiface.cable still returns the old cable
        nbiface.refresh_from_db()
        self.log_success(f"{device}: deleted old cable.")

        # Create the new one
        self._create_cable(nbiface, z_nbiface, label=cable_id if cable_id else '')

        # Don't forget to update the device rack/U
        device.rack = z_nbdevice.rack
        device.position = int(position)
        device.save()
        self.log_success(f"{device}: moved to rack {device.rack}, U{device.position}.")


class MoveServersUplinks(Script, Importer):
    class Meta:
        name = "Move all the servers' uplinks from old to new ToR."
        description = "Assigns port number based on the rack U number of the server."
        commit_default = False

    new_switch = ObjectVar(
        required=True,
        label="New switch",
        description=("New top of rack switch. (Required)"),
        model=Device,
        query_params={
            'role': ('asw', 'cloudsw'),
            'status': ('active', 'staged', 'planned'),
        }
    )

    def run(self, data, commit):
        """Run the script and return all the log messages."""
        self.log_info(f"Called with parameters: {data}")
        self.move_uplinks(data)
        return format_logs(self.log)

    def move_uplinks(self, data):
        """Process all servers in the rack."""
        new_switch = data['new_switch']

        # Get all servers from the same rack as the new switch
        all_servers = Device.objects.filter(device_role__slug='server',
                                            status='active',
                                            tenant__isnull=True,
                                            rack=new_switch.rack)

        server_count = 0
        for server in all_servers:
            server_count += 1
            interface = self.find_primary_interface(server)
            if not interface:
                continue
            z_old_nbiface = self.find_remote_interface(interface)
            # Only works with Juniper
            z_iface = f"{z_old_nbiface.name.split('-')[0]}-0/0/{str(server.position - 1)}"

            # Configure the new switch interface
            z_nbiface = self._update_z_nbiface(new_switch, z_iface, z_old_nbiface.untagged_vlan, z_old_nbiface.type,
                                               list(z_old_nbiface.tagged_vlans.all()))

            # Clean the old one
            self.clean_interface(z_old_nbiface)
            label = str(interface.cable.label)
            # Remove the old cable
            interface.cable.delete()
            # After deleting the cable refresh the interface, otherwise
            # interface.cable still returns the old cable
            interface.refresh_from_db()
            # Create the new one
            self._create_cable(interface, z_nbiface, label=label)
            self.log_success(f"{server} ({server_count}/{len(all_servers)}): All done.")
