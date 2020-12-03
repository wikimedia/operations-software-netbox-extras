from dcim.models import Device
from extras.constants import LOG_LEVEL_CODES
from extras.scripts import Script, StringVar


class OfflineDevice(Script):

    class Meta:
        name = 'Offline a device with extra actions'
        description = ('Set the device status to Offline (unracked), unset its position and delete all interfaces '
                       'and related IP addresses.')
        commit_default = False

    devices = StringVar(
        label='Device name(s)',
        description='Device to be offlined, space separated if more than one',
    )

    def run(self, data):
        """Offline the device."""
        try:
            self._run(data)
        except Exception as e:
            self.log_failure('Failed to offline device(s) {name}: {e}'.format(name=data['device_name'], e=e))

        return self._format_logs()

    def _run(self, data):
        """Actually run the script."""
        devices = Device.objects.filter(name__in=data['devices'].split())
        self.log_info('Found {n} Netbox devices'.format(n=len(devices)))

        for device in devices:
            self._run_device(device)

    def _run_device(self, device):
        """Run the script for one device."""
        if device.status != 'decommissioning':
            self.log_failure(('Device {name} is in {status} status, only decommissioned devices '
                              'can be offlined. Skipping device.').format(name=device, status=device.status))
            return

        self.log_info('Setting device {device} status to Offline and unset rack/unit position'.format(device=device))
        device.status = 'offline'
        device.rack = None
        device.position = None
        device.face = ''
        device.primary_ip4 = None
        device.primary_ip6 = None
        device.save()  # Avoid any race condition with DNS generations scripts

        for interface in device.interfaces.all():
            for address in interface.ip_addresses.all():
                self.log_info('Deleting address {ip} with DNS {dns} on interface {iface} for device {name}'.format(
                              ip=address, dns=address.dns_name, iface=interface, name=device))
                address.delete()

            self.log_info('Deleting interface {iface} on device {name}'.format(iface=interface, name=device))
            interface.delete()

        device.save()
        self.log_success('Successfully offlined device {name}'.format(name=device))

    def _format_logs(self):
        """Return all log messages properly formatted."""
        return "\n".join(
            "[{level}] {msg}".format(level=LOG_LEVEL_CODES.get(level), msg=message) for level, message in self.log
        )
