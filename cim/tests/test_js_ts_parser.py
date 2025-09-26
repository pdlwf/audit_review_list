from __future__ import annotations

from pathlib import Path

from cim.parsers.js_ts_parser import parse_js


def test_parse_js_imports_and_components(tmp_path: Path) -> None:
    source = """
import React from 'react'
import { Link } from './router'
const config = require('../config.json')

export function UserCard() {
  return <div>{process.env.APP_NAME}</div>
}

export const Button = () => <button>{i18n.t('save')}</button>
"""
    path = tmp_path / "component.tsx"
    path.write_text(source, encoding="utf-8")

    result = parse_js(path)

    imports = {item.source for item in result.imports}
    assert "react" in imports
    assert "./router" in imports
    assert any(comp == "UserCard" for comp in result.components)
    assert any(res.kind == "env" and res.value == "APP_NAME" for res in result.resources)
    assert any(res.kind == "i18n" and res.value == "save" for res in result.resources)
