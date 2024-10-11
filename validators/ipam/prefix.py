from extras.validators import CustomValidator


class Main(CustomValidator):
    """Main class referenced in the Netbox config"""

    def validate(self, instance, request) -> None:  # noqa: unused-argument
        """Mandatory entry point"""
        # Kubernetes prefixes must have the kubernetes role if their parent have it
        parent_prefix = instance.get_parents().last()
        if not parent_prefix or not parent_prefix.role or parent_prefix.role.slug != 'kubernetes':
            return
        # At this point the parent prefix is Kubernetes
        if not instance.role or instance.role.slug != 'kubernetes':
            self.fail(f"Invalid role: must be 'kubernetes' like its parent {parent_prefix}", field="role")
        if not instance.role or instance.site != parent_prefix.site:
            self.fail(f"Invalid site: must be {parent_prefix.site} like its parent {parent_prefix}", field="site")
