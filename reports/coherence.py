"""Several integrity/coherence checks against the data."""

from dcim.models import Device
from extras.reports import Report


class Rack(Report):
    description = "Several integrity/coherence checks against the rack related data."

    def test_connected_unracked(self):
        """Determine if unracked boxes still have console connections marked as conneced."""
        for device in Device.objects.filter(rack=None):
            # TODO all cables, not just console
            consoleports = device.consoleports.all()
            good = True
            msgs = [
                f"connected console ports attached to unracked device {device.name}:"
            ]
            for port in consoleports:
                if port.cable:
                    msgs.append(port.name)
                    good = False
            if not good:
                self.log_failure(device, " ".join(msgs))
