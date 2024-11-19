from django.contrib.contenttypes.models import ContentType

from dcim.models import Cable, Device, Manufacturer

from extras.models import ObjectChange
from extras.scripts import Script, StringVar

KEY_TO_MODEL = {  # TODO how to automate it for all models?
    'cable': Cable,
    'device': Device,
    'manufacturer': Manufacturer,
}


class Revert(Script):
    class Meta:
        name = "Revert change(s)"
        description = ("(experimental) TRY to revert a single request ID or multiple change IDs. "
                       "Only supports create and delete actions. Make sure to use dry-run first.")
        commit_default = False  # noqa: unused-variable

    request_or_change_id = StringVar(description="Request ID or change IDs (coma separated) from the changelog page.",
                                     label="Request/Change")

    def run(self, data: dict, commit: bool) -> None:  # noqa: unused-argument
        """Execute script as per Script interface."""
        request_or_change_id = data["request_or_change_id"]
        if '-' in request_or_change_id:
            # eg. 8ff8c035-ce55-4048-b098-049c391ee3d7
            query_filter = {'request_id': request_or_change_id}
        else:
            # Also works with a single ID
            query_filter = {'id__in': request_or_change_id.split(',')}

        changes = ObjectChange.objects.filter(**query_filter).order_by('-time')

        if not changes:
            self.log_failure(f"No changes found while filtering with {query_filter}")
            return

        for change in changes:
            self._revert_change(change)
        return

    def _revert_change(self, change: ObjectChange) -> None:
        """Try to revert the given change ID"""
        if change.action == 'update':  # TODO diff postchange_data and prechange_data to see what changed
            self.log_warning("Revert of update actions not supported", obj=change)
            return

        if change.action == 'delete':  # Recreate the object from change.prechange_data
            model_class = change.changed_object_type.model_class()

            # Remove any empty k:v pairs from prechange_data_clean
            # As they're not useful (empty means default) and can even be blocking at create time
            create_data = {k: v for k, v in change.prechange_data_clean.items() if v}

            # Transform some of the exposed fields into their equivalent required to create objects

            # Retreive the assigned ObjectType from its ID if any
            for object_type in ['assigned_object_type', 'termination_type']:
                if (object_type in create_data and isinstance(create_data[object_type], int)):
                    create_data[object_type] = ContentType.objects.get(id=create_data[object_type])
            # Retreive the actual device object from its ID if any
            for key, model in KEY_TO_MODEL.items():
                if (key in create_data and isinstance(create_data[key], int)):
                    create_data[key] = model.objects.get(id=create_data[key])
            # Rename the custom_fields key to what's expected for create action
            if 'custom_fields' in create_data:
                create_data['custom_field_data'] = create_data.pop('custom_fields')

            try:
                created_object = model_class.objects.create(**create_data)
                created_object.save()
                self.log_success(f"Object re-created to revert: {change}", obj=created_object)
            except Exception as e:  # noqa: broad-exception-caught
                self.log_failure(f"Couldn't re-create object to revert change (error: {e})", obj=change)
            return

        if change.action == 'create':  # TODO Delete the object
            change.changed_object.delete()
            self.log_success("Object deleted to revert change", obj=change)
            return
