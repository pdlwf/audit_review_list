from __future__ import annotations

from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from cim.cli import main


def create_sample_repo(root: Path) -> Path:
    src_dir = root / "src"
    services_dir = src_dir / "services"
    web_dir = root / "web"
    pages_dir = web_dir / "pages"
    config_dir = root / "cim"

    services_dir.mkdir(parents=True)
    pages_dir.mkdir(parents=True)
    config_dir.mkdir()
    (config_dir / "rules").mkdir()

    (src_dir / "app.py").write_text(
        "from src.services.user import get_user\n\ndef controller():\n    return get_user()\n",
        encoding="utf-8",
    )
    (services_dir / "user.py").write_text(
        "def get_user():\n    return {'name': 'demo'}\n",
        encoding="utf-8",
    )
    (web_dir / "routes.ts").write_text(
        "import { HomePage } from './pages/home'\nexport const routes = [HomePage]\n",
        encoding="utf-8",
    )
    (pages_dir / "home.tsx").write_text(
        "export const HomePage = () => <div>{process.env.APP_NAME}</div>\n",
        encoding="utf-8",
    )

    config_path = config_dir / "cim.config.yaml"
    config_path.write_text(
        """
version: 1
include:
  - "src/**/*.py"
  - "web/**/*.ts"
  - "web/**/*.tsx"
exclude: []
features:
  parsePython: true
  parseJSTS: true
  parseConfig: false
  gitHotspot: false
rules:
  load: []
impact:
  defaultDepth: 2
""",
        encoding="utf-8",
    )
    return config_path


def test_cli_build_and_impact(tmp_path: Path) -> None:
    config_path = create_sample_repo(tmp_path)
    buffer = StringIO()
    with redirect_stdout(buffer):
        exit_code = main(["build", "--config", str(config_path)])
    assert exit_code == 0, buffer.getvalue()

    out_dir = config_path.parent / "out"
    assert (out_dir / "impact_map.json").exists()
    assert (out_dir / "impact_map.md").exists()
    assert (out_dir / "impact_graph.html").exists()

    impact_buffer = StringIO()
    with redirect_stdout(impact_buffer):
        exit_code = main([
            "impact",
            "--config",
            str(config_path),
            "--target",
            "src/app.py",
            "--depth",
            "1",
        ])
    assert exit_code == 0
    assert "src/services/user.py" in impact_buffer.getvalue()
