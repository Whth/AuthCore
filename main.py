import os

from modules.plugin_base import AbstractPlugin

__all__ = ["AuthCore"]


class AuthCore(AbstractPlugin):
    CONFIG_DETECTED_KEYWORD = "detected_keyword"

    def _get_config_parent_dir(self) -> str:
        return os.path.abspath(os.path.dirname(__file__))

    @classmethod
    def get_plugin_name(cls) -> str:
        return "AuthCore"

    @classmethod
    def get_plugin_description(cls) -> str:
        return "adds up permissions management"

    @classmethod
    def get_plugin_version(cls) -> str:
        return "0.0.1"

    @classmethod
    def get_plugin_author(cls) -> str:
        return "Whth"

    def __register_all_config(self):
        self._config_registry.register_config(self.CONFIG_DETECTED_KEYWORD, "auth")

    def install(self):
        from graia.ariadne.message.parser.base import ContainKeyword
        from graia.ariadne.model import Group
        from graia.ariadne.event.message import GroupMessage

        self.__register_all_config()
        self._config_registry.load_config()

        from graia.ariadne import Ariadne

        @self.receiver(
            GroupMessage,
            decorators=[ContainKeyword(keyword=self._config_registry.get_config(self.CONFIG_DETECTED_KEYWORD))],
        )
        async def hello(app: Ariadne, group: Group):
            await app.send_message(group, "hello")
