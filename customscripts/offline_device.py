from dcim.models import Device
from extras.scripts import Script, StringVar


class OfflineDevice(Script):

    class Meta:
        name = 'Offline a device with extra actions'
        description = 'Set the device status to Offline (unracked) and delete all interfaces and related IP addresses.'

    device_name = StringVar(label='Device name', description='Device to be offlined')

    def run(self, data):
        """Offline the device."""
        try:
            message = self._run(data)
            self.log_success(message)
        except Exception as e:
            message = 'Failed to offline device {name}: {e}'.format(name=data['device_name'], e=e)
            self.log_failure(message)

        return message

    def _run(self, data):
        """Actually run the script."""
        device = Device.objects.get(name=data['device_name'])
        self.log_info('Found Netbox device')
        if device.status != 'decommissioning':
            raise RuntimeError('Device {name} is in {status} status, only already decommissioned devices '
                               'can be offlined.'.format(name=device, status=device.status))

        self.log_info('Setting device %s status to Offline', device)
        device.status = 'offline'
        device.save()  # Avoid any race condition with DNS generations scripts

        for interface in device.interfaces.all():
            for address in interface.ip_addresses.all():
                self.log_info('Deleting address %s with DNS name %s on interface %s',
                              address, address.dns_name, interface)
                address.delete()

            self.log_info('Deleting interface %s', interface)
            interface.delete

        device.save()
        return ('Successfully offlined device {name}, all interfaces and related IPs have been deleted').format(
            name=device)
