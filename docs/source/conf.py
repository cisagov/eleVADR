import os
import sys
from datetime import datetime
from typing import Any, cast

import subprocess

# https://github.com/pyodide/sphinx-js/issues/304
# The sphinx-js (as of 5.0.3) package hardcodes the use of "npx".
_original_run = subprocess.run


def _pnpm_patched_run(
    args: str | list[str], *pargs: Any, **kwargs: Any
) -> subprocess.CompletedProcess[str]:
    if isinstance(args, list) and args and args[0] == "npx":
        # Translate ['npx', 'tsx@4.15.8', ...] to ['pnpm', 'dlx', 'tsx@4.15.8', ...]
        new_args = ["pnpm", "dlx"] + args[1:]
        return _original_run(new_args, *pargs, **kwargs)
    return _original_run(args, *pargs, **kwargs)


subprocess.run = cast(Any, _pnpm_patched_run)

# Point Sphinx to the backend code to enable autodoc functionality
sys.path.insert(0, os.path.abspath("../../backend"))
sys.path.insert(0, os.path.abspath("../../frontend"))
sys.path.insert(0, os.path.abspath("../../frontend/node_modules/.bin"))

os.environ["SPHINX_JS_NODE_MODULES"] = os.path.abspath("../../frontend/node_modules")

project = "eleVADR"
copyright = f"{datetime.now().year}, CISA"
author = "CISA"
release = "0.1.0"

extensions = [
    "sphinx.ext.autodoc",  # Auto-generated source code API docs (built-in)
    "sphinx.ext.napoleon",  # Google-style docstrings (built-in)
    "sphinx.ext.viewcode",  # Links to source code (built-in)
    "sphinx.ext.intersphinx",  # Allow referencing other projects' docs
    "sphinx_copybutton",  # Adds a copy to clipboard button to code blocks
    "sphinx_autodoc_typehints",  # Use Python type annotations for types in docs
    "myst_parser",  # Use Markdown files
    "sphinx_js",  # Handle javascript/typescript (the frontend)
    "sphinx_design",  # response UI components
]

exclude_patterns = [
    "_build",
    "_built_docs",
    ".doctrees",
    "Thumbs.db",
    ".DS_Store",
    ".vscode",
    ".idea",
    ".vagrant",
]

# Code styles: https://pygments.org/docs/styles/
pygments_style = "tango"
pygments_dark_style = "monokai"

# Napoleon settings (lets us use Google-style docstrings)
# https://www.sphinx-doc.org/en/master/usage/extensions/napoleon.html
napoleon_google_docstring = True
napoleon_numpy_docstring = False
napoleon_attr_annotations = True

# sphinx-js settings
js_language = "typescript"
js_source_path = "../../frontend/src/"
jsdoc_tsconfig_path = "../../frontend/tsconfig.json"

# autodoc
# https://www.sphinx-doc.org/en/master/usage/extensions/autodoc.html
autodoc_default_options = {
    "member-order": "bysource",
    "undoc-members": True,
    # Include docs from members even if they're not included in '__all__'
    "ignore-module-all": True,
}
add_module_names = False

# autodoc-typehints
typehints_document_rtype_none = True
always_use_bars_union = True

templates_path = ["_templates"]
exclude_patterns = []

html_theme = "furo"
html_static_path = ["_static"]
html_title = "eleVADR Documentation"
html_short_title = "eleVADR"
html_theme_options = {
    "top_of_page_buttons": ["view", "edit"],
    "source_repository": "https://github.com/cisagov/eleVADR/",
    "source_branch": "develop",
    "source_directory": "docs/",
}

myst_enable_extensions = [
    "colon_fence",
    "deflist",
    "fieldlist",
    "html_admonition",
    "html_image",
]
