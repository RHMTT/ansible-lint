from __future__ import annotations
import os

from ansiblelint.rules import AnsibleLintRule
from ansiblelint.utils import convert_to_boolean, get_first_cmd_arg

class BecomeOverCommandRule(AnsibleLintRule):
    """Using escalatin sudo on Command of Shell module."""

    id = "become-over-command"
    description = (
        "Executing Sudo on a command instead of using become = True "
    )
    severity = "VERY_HIGH”"
    tags = ["command-shell", "security"]
    version_added = "historic"

    _commands = ["command", "shell", "raw"]

    _modules = {
        "sudo": "become_method = sudo",
        "su": "become_method = su",
        "pbrun": "become_method = pbrun",
    }

    def matchtask(
        self, task: dict[str, Any], file: Lintable | None = None
    ) -> bool | str:

        if task["action"]["__ansible_module__"] not in self._commands:
            return False

        first_cmd_arg = get_first_cmd_arg(task)

        if not first_cmd_arg:
            return False

        executable = os.path.basename(first_cmd_arg)

        if executable in self._modules and convert_to_boolean(
            task["action"].get("warn", True)
        ):
            message = "{0} used in place of become = True in module"
            return message.format(executable, self._modules[executable])
        return False
