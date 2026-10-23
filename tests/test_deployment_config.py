import importlib
import json
import pathlib
import tomllib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class DeploymentConfigurationTests(unittest.TestCase):
    def test_vercel_uses_the_flask_app_not_cli_main(self):
        metadata = tomllib.loads((ROOT / 'pyproject.toml').read_text(encoding='utf-8'))
        module, name = metadata['tool']['vercel']['entrypoint'].split(':')
        application = getattr(importlib.import_module(module), name)
        self.assertTrue(callable(application))
        deployment = json.loads((ROOT / 'vercel.json').read_text(encoding='utf-8'))
        self.assertEqual(deployment['framework'], 'flask')
        self.assertEqual(deployment['functions'][module.replace('.', '/') + '.py']['maxDuration'], 60)
        self.assertNotIn('rewrites', deployment)
        self.assertNotIn('outputDirectory', deployment)

    def test_dependencies_match_existing_requirements(self):
        metadata = tomllib.loads((ROOT / 'pyproject.toml').read_text(encoding='utf-8'))
        requirements = {line.strip() for line in (ROOT / 'requirements.txt').read_text().splitlines()
                        if line.strip() and not line.startswith('#')}
        self.assertEqual(set(metadata['project']['dependencies']), requirements)


if __name__ == '__main__':
    unittest.main()
