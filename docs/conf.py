# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = 'pufferblow-api'
copyright = '2023, ramsy0dev'
author = 'ramsy0dev'
release = '0.0.1-beta'

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    "sphinx_favicon",
    "myst_parser" # Support for Markdown
]
source_suffix = [
    ".md"
]

templates_path = ['_templates']
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']


# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = "sphinx_book_theme"
html_favicon = "_static/favicon.ico"
# html_logo = "_static/favicon.ico" NOTE: the logo needs to be redone to make it high quality, and can be exported in different sizes.
html_title = "pufferblow-api docs"
html_theme_options = {
    "repository_url": "https://github.com/PufferBlow/pufferblow-api",
    "use_repository_button": True,
}
# html_static_path = ['_static']
