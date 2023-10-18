import os

from modules.plugin_base import AbstractPlugin

__all__ = ["AuthCore"]


class CMD:
    ROOT = "auth"
    LIST = "list"
    PERM = "perm"
    USER = "user"
    ROLE = "role"
    SRC = "src"
    GRANT = "grant"
    New = "new"
    Delete = "del"
    INFO = "info"


class Mode:
    Perm2Role = "pr"
    Role2User = "ru"


class AuthCore(AbstractPlugin):
    @classmethod
    def _get_config_dir(cls) -> str:
        return os.path.abspath(os.path.dirname(__file__))

    @classmethod
    def get_plugin_name(cls) -> str:
        return "AuthCore"

    @classmethod
    def get_plugin_description(cls) -> str:
        return "adds up permissions management"

    @classmethod
    def get_plugin_version(cls) -> str:
        return "0.0.2"

    @classmethod
    def get_plugin_author(cls) -> str:
        return "Whth"

    def install(self):
        from modules.cmd import RequiredPermission, NameSpaceNode, ExecutableNode
        from modules.auth.resources import required_perm_generator
        from modules.auth.permissions import Permission, PermissionCode

        def grant_perm_to_role(perm_label: str, role_label: str) -> str:
            """
            Grant permission to a role.

            Args:
                perm_label (str): The label of the permission to grant.
                role_label (str): The label of the role to grant the permission to.

            Returns:
                str: A string indicating the success of the permission grant operation.
            """
            stdout = (
                f"Grant {perm_label} to {role_label}\n"
                f"Success = {self._auth_manager.grant_perm_to_role(perm_label, role_label,)}"
            )
            return stdout

        def grant_role_to_user(role_label: str, user_label: str) -> str:
            """
            Grant a role to a user.

            Args:
                role_label (str): The label of the role to grant.
                user_label (str): The label of the user to grant the role to.

            Returns:
                str: A string indicating the success of the operation.

            """
            # TODO: use id as the unique identifier for user, since that
            stdout = (
                f"Grant {role_label} to {user_label}\n"
                f"Success = {self._auth_manager.grant_role_to_user(role_label, user_label)}"
            )
            return stdout

        def new_permission(perm_id: int, perm_name: str) -> str:
            """
            Creates a new permission with the given permission ID and permission name.

            Parameters:
            - perm_id (int): The ID of the new permission.
            - perm_name (str): The name of the new permission.

            Returns: - str: A string indicating the success of creating the new permission.
            It includes the permission ID and name,
            as well as the result of adding the permission to the authentication manager.
            """
            stdout = (
                f"New permission {perm_id} {perm_name}\n"
                f"Success = {self._auth_manager.add_perm_from_info(perm_id, perm_name)}"
            )
            return stdout

        def delete_permission(perm_id: int, perm_name: str) -> str:
            """
            Delete a permission with the given ID and name.

            :param perm_id: The ID of the permission to delete.
            :param perm_name: The name of the permission to delete.
            :return: A string indicating the success or failure of the deletion.
            """
            stdout = f"Delete permission {perm_id}\nSuccess = {self._auth_manager.remove_perm(perm_id, perm_name)}"
            return stdout

        def new_role(role_id: int, role_name: str) -> str:
            """
            Creates a new role with the given role ID and role name.

            Parameters:
                role_id (int): The ID of the new role.
                role_name (str): The name of the new role.

            Returns:
                str: A string indicating the success of the operation.
                It includes the new role ID and role name, as well as whether the role was successfully added.
            """
            stdout = f"New role {role_id} {role_name}\nSuccess = {self._auth_manager.add_role(role_id, role_name)}"
            return stdout

        def delete_role(role_id: int, role_name: str) -> str:
            """
            Delete a role.

            Args:
                role_id (int): The ID of the role to delete.
                role_name (str): The name of the role to delete.

            Returns:
                str: A string indicating the result of the deletion.
            """
            stdout = f"Delete role {role_id}\nSuccess = {self._auth_manager.remove_role(role_id, role_name)}"
            return stdout

        def new_user(user_id: int, user_name: str) -> str:
            """
            Adds a new user to the system.

            Args:
                user_id (int): The unique identifier for the user.
                user_name (str): The name of the user.

            Returns:
                str: A string indicating the success of adding the user.
            """
            stdout = f"New user {user_id} {user_name}\nSuccess = {self._auth_manager.add_user(user_id, user_name)}"
            return stdout

        def delete_user(user_id: int, user_name: str) -> str:
            """
            Deletes a user with the given user ID and user name.

            Args:
                user_id (int): The ID of the user to be deleted.
                user_name (str): The name of the user to be deleted.

            Returns:
                str: A string indicating the success of the deletion operation.
            """
            stdout = f"Delete user {user_id}\nSuccess = {self._auth_manager.remove_user(user_id, user_name)}"
            return stdout

        def role_info(role_id: int, role_name: str) -> str:
            """
            Get information about a role based on its ID and name.

            Parameters:
                role_id (int): The ID of the role.
                role_name (str): The name of the role.

            Returns:
                str: A string containing information about the role.
                If the role is not found, "Not found" is returned.
                If the role is found, the string contains the role's ID, name, and permissions.
            """
            stdout = f"Query Role {role_id} {role_name}\n---------------\n"
            matched_role = list(
                filter(lambda role: role.id == role_id and role.name == role_name, self._auth_manager.roles)
            )
            if len(matched_role) == 0:
                stdout += "Not found"
            elif len(matched_role) == 1:
                stdout += f"ID: {matched_role[0].id}\n"
                stdout += f"Name: {matched_role[0].name}\n"
                permission_string = "\n".join(
                    [f"[{i}]: {perm.unique_label}" for i, perm in enumerate(matched_role[0].permissions)]
                )
                stdout += f"Permissions: \n{permission_string}\n"
            else:
                return "Query failed due to Illegal Data"
            return stdout

        def user_info(user_id: int, user_name: str) -> str:
            """
            Retrieves information about a user based on their ID and name.

            Args:
                user_id (int): The ID of the user.
                user_name (str): The name of the user.

            Returns:
                str: A string containing the user information.
                If the user is not found, "Not found" is appended to the string.
                If the user is found, their ID, name, and roles are included in the string.
                    - If the user is found, the roles are listed on separate lines.
                    - If the query fails due to illegal data,
                    "Query failed due to Illegal Data" is returned.
            """
            stdout = f"Query User {user_id} {user_name}\n---------------\n"
            matched_user = list(
                filter(lambda user: user.id == user_id and user.name == user_name, self._auth_manager.users)
            )
            if len(matched_user) == 0:
                stdout += "Not found"
            elif len(matched_user) == 1:
                stdout += f"ID: {matched_user[0].id}\n"
                stdout += f"Name: {matched_user[0].name}\n"
                roles_string = "\n".join(
                    [f"[{i}]: {role.unique_label}" for i, role in enumerate(matched_user[0].roles)]
                )
                stdout += f"Role: \n{roles_string}\n"
            else:
                return "Query failed due to Illegal Data"
            return stdout

        su_perm = Permission(id=PermissionCode.SuperPermission.value, name=self.get_plugin_name())
        req_perm: RequiredPermission = required_perm_generator(
            target_resource_name=self.get_plugin_name(), super_permissions=[su_perm]
        )
        tree = NameSpaceNode(
            name=CMD.ROOT,
            required_permissions=req_perm,
            help_message=self.get_plugin_description(),
            children_node=[
                NameSpaceNode(
                    name=CMD.LIST,
                    required_permissions=req_perm,
                    help_message="allow view of authorization elements",
                    children_node=[
                        ExecutableNode(
                            name=CMD.PERM,
                            source=lambda: "\n".join([perm.unique_label for perm in self._auth_manager.permissions]),
                        ),
                        ExecutableNode(
                            name=CMD.USER,
                            source=lambda: "\n".join([user.unique_label for user in self._auth_manager.users]),
                        ),
                        ExecutableNode(
                            name=CMD.ROLE,
                            source=lambda: "\n".join([role.unique_label for role in self._auth_manager.roles]),
                        ),
                        ExecutableNode(
                            name=CMD.SRC,
                            source=lambda: "\n".join([src.unique_label for src in self._auth_manager.resources]),
                        ),
                    ],
                ),
                NameSpaceNode(
                    name=CMD.GRANT,
                    required_permissions=req_perm,
                    help_message="allow to grant permissions\nAdd Perm to Role\nAdd Role to User",
                    children_node=[
                        ExecutableNode(
                            name=Mode.Perm2Role,
                            source=grant_perm_to_role,
                            help_message=grant_perm_to_role.__doc__,
                        ),
                        ExecutableNode(
                            name=Mode.Role2User,
                            source=grant_role_to_user,
                            help_message=grant_role_to_user.__doc__,
                        ),
                    ],
                ),
                NameSpaceNode(
                    name=CMD.New,
                    required_permissions=req_perm,
                    help_message="allow to create new perm,role,user",
                    children_node=[
                        ExecutableNode(
                            name=CMD.PERM,
                            source=new_permission,
                            help_message=new_permission.__doc__,
                        ),
                        ExecutableNode(
                            name=CMD.ROLE,
                            source=new_role,
                            help_message=new_role.__doc__,
                        ),
                        ExecutableNode(
                            name=CMD.USER,
                            source=new_user,
                            help_message=new_user.__doc__,
                        ),
                    ],
                ),
                NameSpaceNode(
                    name=CMD.Delete,
                    required_permissions=req_perm,
                    help_message="allow to delete perm,role,user",
                    children_node=[
                        ExecutableNode(
                            name=CMD.PERM,
                            source=delete_permission,
                            help_message=delete_permission.__doc__,
                        ),
                        ExecutableNode(
                            name=CMD.ROLE,
                            source=delete_role,
                            help_message=delete_role.__doc__,
                        ),
                        ExecutableNode(
                            name=CMD.USER,
                            source=delete_user,
                            help_message=delete_user.__doc__,
                        ),
                    ],
                ),
                NameSpaceNode(
                    name=CMD.INFO,
                    required_permissions=req_perm,
                    help_message="allow to get info of role,user",
                    children_node=[
                        ExecutableNode(
                            name=CMD.ROLE,
                            source=role_info,
                            help_message=role_info.__doc__,
                        ),
                        ExecutableNode(
                            name=CMD.USER,
                            source=user_info,
                            help_message=user_info.__doc__,
                        ),
                    ],
                ),
            ],
        )

        self._auth_manager.add_perm_from_req(req_perm)
        self._root_namespace_node.add_node(tree)
