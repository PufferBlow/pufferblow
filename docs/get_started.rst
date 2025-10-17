
===============
Get started
===============

To get started on hosting your own `pufferblow <https://github.com/PufferBlow/pufferblow>`__ server, you will need the following:

* Linux VPS
* PostgreSQL

Setup a Linux VPS
=================

Numerous affordable VPS services are available, offering reliable Linux VPS solutions. Among the options that we recommend are:

* `Oracle's Free tier <https://www.oracle.com/cloud/free>`_
* `Contabo <https://contabo.com/en/>`_

Setup PostgreSQL
================

Head over `PostgreSQL's download page <https://www.postgresql.org/download/>`_ and follow the instructions based on your distro.

Install pufferblow
=====================

Installing **pufferblow** is very straight forward all you need to do is:

* Install via Git:

.. code-block:: bash

    pip install git+https://github.com/pufferblow/pufferblow.git

* Build from source:

.. code-block:: bash

    git clone https://github.com/pufferblow/pufferblow.git --depth=1
    cd pufferblow
    pip install -e .


pufferblow has a modern, interactive setup wizard that guides you through the installation process. Simply run:

.. code-block:: bash

    pufferblow setup

The setup wizard will present you with a clean, modern interface featuring:

- **Interactive mode selection**: Choose from full setup, server configuration only, or updates
- **Visual progress indicators**: Real-time progress bars with spinners and percentage completion
- **Color-coded feedback**: Clear visual cues for success, warnings, and errors
- **Guided credential input**: Secure password entry and detailed configuration prompts
- **Post-setup guidance**: Step-by-step instructions for getting started after setup

The wizard supports three main modes:

**🆕 Full Server Setup**
   Complete installation including database configuration, server settings, and admin account creation.

**🔧 Server Configuration Only**
   Configure server information when you already have a config file and want to set up server details.

**🔄 Update Existing Server**
   Modify server information like name, description, and welcome messages.

If a config file already exists, the wizard will provide appropriate options based on the current system state.
Setup pufferblow

pufferblow has a modern, interactive setup wizard that guides you through the installation process. Simply run:

.. code-block:: bash

    pufferblow setup

The setup wizard will present you with a clean, modern interface featuring:

- **Interactive mode selection**: Choose from full setup, server configuration only, or updates
- **Visual progress indicators**: Real-time progress bars with spinners and percentage completion
- **Color-coded feedback**: Clear visual cues for success, warnings, and errors
- **Guided credential input**: Secure password entry and detailed configuration prompts
- **Post-setup guidance**: Step-by-step instructions for getting started after setup

The wizard supports three main modes:

**🆕 Full Server Setup (Recommended)**
   Complete installation including database configuration, server settings, and admin account creation.

**🔧 Server Configuration Only**
   Configure server information when you already have a config file and want to set up server details.

**🔄 Update Existing Server**
   Modify server information like name, description, and welcome messages.

If you're using the flags directly, you can run:

.. code-block:: bash

    pufferblow setup --setup-server   # Configure server info only
    pufferblow setup --update-server  # Update existing server configuration

The setup process includes comprehensive error handling and will guide you through fixing any database connection issues or configuration problems.

**What you'll see during setup:**

.. code-block::

    🚀 Welcome to PufferBlow Setup Wizard
    ====================================

    Choose your setup workflow:

      [1] 🆕 Full Server Setup (Recommended)
          Complete installation - database, server config & admin account
          ⏱️  Estimated time: ~5-10 mins

      [2] 🔧 Server Configuration Only
          Configure server info when you already have a config file
          ⏱️  Estimated time: ~2 mins

      [3] 🔄 Update Existing Server
          Modify server information without database changes
          ⏱️  Estimated time: ~1 min

      [4] ❌ Cancel Setup
          Exit the setup wizard
          ⏱️  Estimated time: Immediate

    Select an option [1-4] (1):

At the end of a successful setup, you'll receive your server authentication token and next-steps guidance.
================

pufferblow has a command called setup that enables you to set it up, all you need to do is run the following:

.. code-block:: bash

    pufferblow setup

if it detects that a config file is already present, the following will be outputed:

.. code-block::

    A config file already exists. Do you want to continue? [y/n]:

but normaly it will ask you for your postgreSQL database name, the default is postgres:

.. code-block::

    PostgreSQL database name (postgres):

then it will ask you about the database's username, password, host and port:

.. code-block::

    PostgreSQL database username:
    PostgreSQL database password:
    PostgreSQL database host:
    PostgreSQL database name port:

after that it will ask you about some light info on your server, like the server name, description, welcome message:

.. code-block::

    Enter your server's name:
    Enter your server's description:
    Enter your server's welcome message for new members:

and lastly the username, password for the admin user:

.. code-block::

    Enter your owner account username:
    Enter your owner account password:

.. note::

    Don't panic when typing in a password; it will not be shown by design.

Start your pufferblow server
============================

Now you can start your pufferblow server with the following command:

.. code-block:: bash

    pufferblow serve
