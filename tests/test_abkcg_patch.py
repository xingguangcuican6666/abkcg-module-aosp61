import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "abkcg_patch.py"
SPEC = importlib.util.spec_from_file_location("abkcg_patch", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
abkcg_patch = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(abkcg_patch)


class KernelMakefilePatchTest(unittest.TestCase):
    def test_adds_selinux_generated_header_paths_and_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            makefile = Path(directory) / "Makefile"
            makefile.write_text("obj-$(CONFIG_CGROUPS) += cgroup/\nobj-y += fork.o\n")

            abkcg_patch.patch_kernel_makefile(makefile)
            first_patch = makefile.read_text()
            abkcg_patch.patch_kernel_makefile(makefile)

            self.assertIn(
                "CFLAGS_abkcg_core.o += -I$(srctree)/security/selinux "
                "-I$(srctree)/security/selinux/include "
                "-I$(objtree)/security/selinux "
                "-I$(objtree)/security/selinux/include\n",
                first_patch,
            )
            self.assertIn(
                "$(obj)/abkcg_core.o: $(objtree)/security/selinux/flask.h "
                "$(objtree)/security/selinux/av_permissions.h\n",
                first_patch,
            )
            self.assertEqual(first_patch, makefile.read_text())

    def test_upgrades_existing_object_rule_without_duplication(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            makefile = Path(directory) / "Makefile"
            makefile.write_text(
                "obj-$(CONFIG_CGROUPS) += cgroup/\n"
                "obj-$(CONFIG_ABK_CGROUP) += abkcg_core.o\n"
            )

            abkcg_patch.patch_kernel_makefile(makefile)
            patched = makefile.read_text()

            self.assertEqual(patched.count("obj-$(CONFIG_ABK_CGROUP) += abkcg_core.o\n"), 1)
            self.assertIn("CFLAGS_abkcg_core.o +=", patched)
            self.assertIn("$(obj)/abkcg_core.o: $(objtree)/security/selinux/flask.h", patched)


if __name__ == "__main__":
    unittest.main()
