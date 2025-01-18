# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = 'pufferblow'
copyright = '2025, ramsy0dev'
author = 'ramsy0dev'
release = '0.0.1-beta'

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    "sphinx_favicon"
]

templates_path = ['_templates']
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = 'sphinx_book_theme'
html_css_files = [
    "css/styles.css"
]
html_static_path = ['_static']

html_title = "pufferblow"
html_favicon = "_static/favicon.ico"
html_theme_options = {
    "use_download_button": True, # Allow users to download the current page in different formats
    "icon_links": [
        {
            "name": "GitHub",
            "url": "https://github.com/PufferBlow/pufferblow",
            "icon": "fa-brands fa-square-github",
            "type": "fontawesome",
        }
    ],
    "icon_links_label": "Quick Links",
    "repository_url": "https://github.com/PufferBlow/pufferblow",
    "repository_branch": "docs",
    "path_to_docs": "./docs",
    "use_repository_button": True,
    "use_issues_button": True,
    "use_edit_page_button": True,
    "use_sidenotes": True,
    # Sidebar
    "toc_title": "Table of content",
}
