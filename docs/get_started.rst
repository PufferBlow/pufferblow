===============
Get started
===============

Welcome! This guide will walk you through setting up your own PufferBlow chat server step by step. PufferBlow is a decentralized platform, meaning you get to host your own server and have complete control over your data and community - no relying on big companies like Discord or Slack.

By the end of this guide, you'll have your own independent chat server running that your friends, family, or community can use to communicate.

What You Need Before Starting
===============================

**Hardware Requirements**
    * A computer or VPS running Linux (Ubuntu, Debian, CentOS, etc. work great)
    * At least 2GB RAM (4GB recommended for better performance)
    * 10GB free disk space (for messages, files, and system data)
    * Stable internet connection

**Software Skills**
    * Basic command line knowledge (don't worry, we'll guide you through every command)
    * Ability to install software and follow step-by-step instructions

**Time Required**
    * First time setup: 30-60 minutes
    * Daily operation: 5 minutes to start/stop the server

Step 1: Choose Where to Host Your Server
==========================================

You have several options for where to run your PufferBlow server:

**Option A: Your Own Computer (For Testing)**
    * Pros: Free, full control, private
    * Cons: Server only runs when your computer is on, may be slow for many users

**Option B: Rent a VPS (Virtual Private Server) - Recommended**
    * Pros: Always online, good performance, professional setup
    * Cons: Monthly cost (typically $5-20/month)

.. note::
    For your first server, we recommend renting a VPS. It's inexpensive and reliable.

**Recommended VPS Providers**
    * `Oracle Cloud Free Tier <https://www.oracle.com/cloud/free>`_ - Free forever (with usage limits)
    * `Contabo <https://contabo.com/en/>`_ - Very affordable, starts at $4.99/month
    * `Hetzner <https://www.hetzner.com/>`_ - Reliable, good performance
    * `DigitalOcean <https://www.digitalocean.com/>`_ - Easy to use, good documentation

**Once you have your server**, connect to it using SSH:

.. code-block:: bash

    ssh username@your-server-ip

Step 2: Install Python and System Dependencies
===============================================

PufferBlow runs on Python, so we need to install it along with some basic tools.

**Update your system (run these commands one by one):**

.. code-block:: bash

    sudo apt update
    sudo apt upgrade -y

**Install Python and pip (the package manager):**

.. code-block:: bash

    sudo apt install -y python3 python3-pip python3-dev

**Verify Python is installed:**

.. code-block:: bash

    python3 --version

You should see something like "Python 3.10.0" or higher. If you get an error, ask in our community for help.

**Install PostgreSQL (the database):**

PostgreSQL is like a smart filing cabinet that stores all your chat messages, user accounts, and settings.

.. code-block:: bash

    sudo apt install postgresql postgresql-contrib

**Start the PostgreSQL service:**

.. code-block:: bash

    sudo systemctl start postgresql
    sudo systemctl enable postgresql

**Verify PostgreSQL is running:**

.. code-block:: bash

    sudo systemctl status postgresql

You should see "active (running)" in green. If not, run:

.. code-block:: bash

    sudo systemctl start postgresql

Step 3: Set Up the Database
============================

Now we need to create a database for PufferBlow to use.

**Switch to the PostgreSQL user:**

.. code-block:: bash

    sudo -u postgres psql

**Create a database named 'pufferblow' (you can choose any name you like):**

.. code-block:: sql

    CREATE DATABASE pufferblow;

**Create a database user (replace 'mypassword' with a secure password):**

.. code-block:: sql

    CREATE USER pufferblow WITH PASSWORD 'mypassword';

**Give the user permission to use the database:**

.. code-block:: sql

    GRANT ALL PRIVILEGES ON DATABASE pufferblow TO pufferblow;

**Exit the PostgreSQL prompt:**

.. code-block:: sql

    \q

**Optional: Secure your PostgreSQL installation**

For a production server, you should run:

.. code-block:: bash

    sudo -u postgres psql
    ALTER USER pufferblow CREATEDB;
    \q

And configure PostgreSQL to listen on the right interfaces if needed.

Step 4: Install PufferBlow
===========================

Now we'll install the PufferBlow server software.

**Option A: Install from the official repository (recommended):**

.. code-block:: bash

    pip3 install git+https://github.com/pufferblow/pufferblow.git

**Option B: Download and install from source (for developers):**

.. code-block:: bash

    git clone https://github.com/pufferblow/pufferblow.git --depth=1
    cd pufferblow
    pip3 install -e .

**Verify installation:**

.. code-block:: bash

    pufferblow --version

You should see the version number. If you get "command not found", you may need to add Python's local bin directory to your PATH:

.. code-block:: bash

    export PATH="$HOME/.local/bin:$PATH"

Then try the version command again.

Step 5: Configure Your Server
===============================

PufferBlow has an interactive setup wizard that makes configuration easy.

**Run the setup wizard:**

.. code-block:: bash

    pufferblow setup

**Select Option 1 (Full Server Setup)** when prompted.

**Enter your database information:**
    * Database name: pufferblow (or whatever you named it)
    * Username: pufferblow
    * Password: mypassword (use the password you set earlier)
    * Host: localhost (or 127.0.0.1)
    * Port: 5432 (default PostgreSQL port)

The wizard will test the database connection. If it fails:
    * Double-check your database name, username, and password
    * Make sure PostgreSQL is running: ``sudo systemctl status postgresql``

**Configure your server details:**
    * **Server name**: Give your server a friendly name (e.g., "My Gaming Community" or "Family Chat")
    * **Server description**: A short description of what your server is about
    * **Welcome message**: What new users see when they join

**Create your admin account:**
    * **Username**: Your admin username (this will be your login)
    * **Password**: Choose a strong password (it will be hidden while typing)

The setup will complete and show you an **authentication token**. **SAVE THIS TOKEN** - you'll need it to log into your server as the admin.

Step 6: Start Your Server
==========================

Now for the exciting part - starting your chat server!

**Start the server:**

.. code-block:: bash

    pufferblow serve

You should see startup messages. The server runs on port 7575 by default.

**Verify it's running:**

Open a web browser and go to: ``http://your-server-ip:7575``

You should see a basic API info page that says the server is running.

**To run in the background (recommended for production):**

Stop the server with Ctrl+C, then run:

.. code-block:: bash

    nohup pufferblow serve > server.log 2>&1 &

**Check if it's still running:**

.. code-block:: bash

    ps aux | grep pufferblow

You should see the server process running.

Step 7: Connect to Your Server
===============================

Now you can connect chat clients to your server.

**Web Client:**
    Visit: http://your-server-ip:7575 (note: the PufferBlow client might be on a different URL)

**Desktop/Mobile Clients:**
    Point clients to your server URL: ``http://your-server-ip:7575``

**Login with your admin account:**
    Use the username and password you created during setup.

Step 8: Next Steps and Management
===================================

**Congratulations!** Your server is now running. Here are some next steps:

**Create your first channel:**
    As admin, create channels for different topics (e.g., #general, #gaming, #random)

**Invite users:**
    Share your server address with friends/family

**Customize settings:**
    Use the admin dashboard to configure moderation, file limits, etc.

**Daily operations:**
    - Start server: ``pufferblow serve``
    - Stop server: Find the process with ``ps aux | grep pufferblow`` and ``kill <PID>``
    - Update: ``pip install --upgrade git+https://github.com/pufferblow/pufferblow.git``

**Backup your data:**
    Regularly backup your PostgreSQL database:

    .. code-block:: bash

        pg_dump pufferblow > pufferblow_backup.sql

Troubleshooting Common Issues
===============================

**Server won't start:**

.. code-block:: text

    Check: Are you running as the same user who installed PufferBlow?
    Check: Is port 7575 available? Run: netstat -tlnp | grep 7575
    Check: Are all dependencies installed? Try reinstalling: pip3 install --upgrade --force-reinstall git+https://github.com/pufferblow/pufferblow.git

**Database connection fails:**

.. code-block:: text

    Check: Is PostgreSQL running? sudo systemctl status postgresql
    Check: Can you connect manually? psql -h localhost -U pufferblow -d pufferblow
    Check: Are the database credentials correct? Rerun setup: pufferblow setup --update-server

**Can't access from other computers:**

.. code-block:: text

    Check: Is your firewall blocking port 7575? Ubuntu: sudo ufw allow 7575
    Check: Is your VPS network configuration correct?

**Performance issues:**

.. code-block:: text

    Check: System resources with: htop or top
    Check: Database connections with: ps aux | grep postgres

Need Help?
===========

If you run into problems:

1. Check the server logs in the current directory (``server.log``)
2. Re-run setup: ``pufferblow setup``
3. Ask the community at our GitHub issues page
4. Join our official server for support

What's Next?
=============

Now that you have your own server running, you can:

- **Invite friends and family** to join your private community
- **Customize the experience** with channels, roles, and settings
- **Add more features** as the PufferBlow platform grows
- **Learn about decentralized tech** and why self-hosting matters

Welcome to the decentralized future of communication! 🎉
