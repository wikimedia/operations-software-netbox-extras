from wmf_scripts_imports.common import format_logs

from dcim.models import Device
from extras.scripts import BooleanVar, Script, ObjectVar


class ReplaceDevice(Script):
    class Meta:
        name = "Move devices attributes"
        description = (
            "Move all attributes (cables, etc) from one device to the other. "
            "To be used for RMAs and other in place replacement. "
            "Note that existing attributes on the new device will be deleted."
        )
        commit_default = False

    source_device = ObjectVar(
        required=True,
        label="Old device name",
        description=("Old device (Required)"),
        model=Device,
    )
    destination_device = ObjectVar(
        required=True,
        label="New device name",
        description=("Replacement device (Required)"),
        model=Device,
    )
    already_racked = BooleanVar(
        label="Already racked",
        description=(
            "The replacement device is already racked at its definitive location. "
            "If checked, the script does NOT touch racking, console and power."
        ),
    )
    move_inventory = BooleanVar(
        label="Move inventory items",
        description=("By default does NOT touch the inventory items."),
    )

    def run(self, data, commit):  # noqa: unused-argument
        """Replace the device."""
        try:
            self._run(data)
        except Exception as e:  # noqa: broad-exception-caught TODO fix after upgrade
            self.log_failure(f"Failed to run script. {e}")

        return format_logs(self.messages)

    def _copy_attributes(self, source_device, destination_device, attributes, remove_old=False):
        for attribute in attributes:
            source_attribute = getattr(source_device, attribute)
            destination_attribute = getattr(destination_device, attribute)
            if source_attribute == destination_attribute:
                # Ignore already set attributes to prevent excessive logging
                continue
            setattr(destination_device, attribute, source_attribute)
            self.log_success(f"[dst] Setting {attribute} to {source_attribute}")
            if remove_old:
                setattr(source_device, attribute, None)
                self.log_info(f"[src] Removing {attribute}")

    def _run(self, data):
        """Actually run the script."""
        source_device = data["source_device"]
        destination_device = data["destination_device"]
        if source_device == destination_device:
            self.log_error("Source and destination devices are the same")
            return

        destination_device.name = source_device.name
        source_device.name = source_device.name + "-old"
        source_device.status = "decommissioning"
        destination_device.status = "active"
        destination_device.comments = destination_device.comments + " - Replaced " + str(source_device.asset_tag)

        # Direct device attributes that are set to None on the source after the swap
        attributes = ["cluster", "virtual_chassis", "vc_position", "vc_priority", "primary_ip4", "primary_ip6"]
        if not data["already_racked"]:
            attributes.extend(["position"])
        self._copy_attributes(source_device, destination_device, attributes, remove_old=True)

        # Direct device attributes that are kept on the source after the swap
        attributes = ["tenant"]
        if not data["already_racked"]:
            attributes.extend(["rack", "face"])
        self._copy_attributes(source_device, destination_device, attributes)

        # Objects attributes with the device as primary key
        attributes = ["interfaces", "consoleserverports", "poweroutlets"]

        if not data["already_racked"]:
            attributes.extend(["powerports", "consoleports"])
        if data["move_inventory"]:
            attributes.extend(["inventoryitems"])

        for attribute in attributes:
            source_objects = getattr(source_device, attribute)
            destination_objects = getattr(destination_device, attribute)
            # Delete all objects on the destination
            for dest_object in destination_objects.all():
                self.log_info(f"[dst] Deleting {attribute} {dest_object.name}.")
                dest_object.delete()
            # Move the objects from the source to the destination
            for src_object in source_objects.all():
                src_object.device = destination_device
                self.log_success(f"Moved {attribute} {src_object.name}")

                src_object.save()

        source_device.save()
        destination_device.save()

        self.log_success(f"All done! {destination_device.asset_tag} replaced {source_device.asset_tag}")
