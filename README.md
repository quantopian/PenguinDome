qlmdm -- Quantopian Linux Mobile Device Management
==================================================

There aren't that many Mobile Device Management (MDM) offerings for Linux laptops and desktops, and most of the ones that are available don't seem to be very good.

At Quantopian, we have a few Linux laptops and desktops that we need to do MDM for. We've invested a lot of effort into deploying a complex MDM product for Macs and Windows PCs, but that product doesn't support Linux. We don't want to switch to a different MDM product that supports Mac, Windows, and Linux, because then we'll have to redo all the work that went into deploying the product that we're doing now. And we don't want to deploy a second, complex MDM product just for a few Linux boxes

Just to make things more complicated, some of our people who use Linux have somewhat "esoteric" tastes in Linux distributions. We want to allow people to choose their Linux distributions if at all possible, and some of the distributions are engineers are using aren't supported by any of the MDM products that claim to support Linux.

Finally, Linux's openness makes it relatively easier to build MDM functionality from scratch than it is on other platforms.

Putting all this together, we decided it made more sense for us to write our own, minimal Linux MDM solution that is tailored to and satisfies our specific MDM requirements. This project is the result.

This isn't a big, fancy MDM solution. There's no fancy Web UI, no system tray apps, etc. It doesn't have fancy policy enforcement. It just collects data about your Linux boxes and uploads it periodically to a central server, and the central server periodically checks for things you probably want to fix and send you terse emails about them.

Requirements
------------

Currently this works on recent Ubuntu versions. It needs some pretty standard Linux utilities, most notably GnuPG. If you're missing something it needs, it'll let you know, by failing catastrophically. It's written in Python, so it obviously needs that as well. It installs itself in its own virtualenv and installs the Python packages it needs in the virtualenv, so you don't need to worry about that (though you do need to have virtualenv installed!). You need Cron on the clients, as well as on the server if you want to run the audit script periodically.

I'm also planning on adding support for Arch Linux, though I haven't gotten there yet.

You need a MongoDB database server -- running on the same machine as the qlmdm server or elsewhere -- to store the data.

Deployment
----------

### Server

Copy the whole source tree onto the machine you're going to use as the web server. Run `server/server-setup.sh` as root. It'll configure the server virtualenv, install the necessary Python packages, ask you a bunch of configuration questions, and set up the necessary configuration files for the server and the clients.

Once that's done, run `bin/client_release` as root. This will generate a numbered tar file in `var/client_releases` which you can then download and install on your client Linux boxes as described below.

Whenever any of the files that are used on the clients are changed, you run `bin/client_release` again, and a new release is generated *and downloaded and installed automatically by the clients.* Neat, huh?

The `server-setup.sh` script will create `server/settings.yml` and `client/settings.yml`. The former is used on the server, the latter is deployed to clients in the release tar files described below. You can also edit these files directory in addition to or instead of using the setup script (but note that you do need to run the setup script at least once, because it does other necessary things besides creating the settings files). See `server/settings.yml.template` and `client/settings.yml.template` for documentation of the former of these files.

Changing the client settings after the initial deployment, especially the server URL if you need to move the server to a new host, is tricky. Once you change the file and create a new release, clients will download and install the new release, after which they'll start trying to use the new URL. If the new URL isn't working yet, they'll be incommunicado until the server transitions to the new URL. If you can get all the clients updated quickly enough, that may be fine. Otherwise, you might be able to have an overlap time during which you're running a server on both the old a new URLs so that clients can transition gradually.

### Client

Take the aforementioned tar file, copy it to a client, untar it anywhere you want (`/opt/qlmdm`, `/usr/local/qlmdm`, whatever you want), and run `client/client-setup.sh` as root. It'll prompt you for what it needs to know. When it's done, the client should immediately start reporting to the server, assuming that you configured and started the server successfully before.

Architecture
------------

### Plugins

Scripts in `client/plugins` collect data about the computer and output it as JSON. The `bin/collect` script, which is called periodically by `bin/client-cron` out of a crontab, rolls up all these data and squeezes them into a big blog which is then sent to the server by `bin/submit`, which is also called by `bin/client-cron`.

### One-time commands

For general-purpose, one-time data collection, scripts in `client/commands` are invoked by `bin/collect` and their output is collected as text and then transmitted by `bin/submit` as well. These scripts are deleted after they are executed successfully.

One-time commands make their way onto the clients in one of two ways:

* They can be included in a release by saving them into the `client/commands` directory on the server and then running `bin/client_release`.

* They can be shipped as a patch to one or more clients using `bin/client_command` on the server, which accepts either a shell command or a script file and queues it for execution on one or more clients.

Remote wipe
-----------

Wiping a client is a special case of the one-off commands described above. When you run <tt>bin/client_wipe *hostname*</tt> on the server, it queues `server/files/wipe.sh` on the specified host for execution the next time the host checks in. This script wipes all non-system-user home directories, kills all of their processes, and then deletes their accounts.

Auditing
--------

The `bin/audit` command on the server checks for a bunch of problems (you can read the big list of them at the top of `server/audit.py`) and prints plain-text messages to stdout about them. Once it prints a message about a problem it doesn't warn about it again for another hour. It's intended to be run out of a crontab once per minute.

Client-server API
-----------------

The server supports the following queries from clients:

* `/qlmdm/v1/submit` for submitting plugin or command results (called by `bin/submit` on the client)

* `/qlmdm/v1/update` for downloading a new release and/or patches as needed (called by `bin/update` on the client)

* `/qlmdm/v1/acknowledge_patch` for acknowledging that a particular patch has been applied successfully on the client so it can be unqueued on the server (also called by `bin/update` on the client)

That's it. It's a very simple API.

All of the API endpoints accept two form fields:

* `data` contains the JSON-encoded query data.

* `signature` contains a detached GnuGPG signature for the data. More on this below.

Security
--------

When the server is configured with `server/server-setup.sh`, two SSH keypairs are generated, one for the server and one for the clients. All of the files in releases that go down to the clients are signed with the server's private key, and clients verify that the files are intact (i.e., the signatures are valid) before using them. Plugins, command scripts, etc., that aren't signed by the server's private key won't be run on the clients.

The client key is used to sign all API requests sent by the clients to the server. The server won't process any request that doesn't have a valid signature.

All the clients use the same private key. We felt this was sufficient, at least for the time being, for what we're trying to accomplish here.

There's room in the architecture for rotating either the server or the client key, though that's not yet fully supported in the code. We'll cross that bridge when we come to it.

Database
--------

There are no indexes on the database yet. At some point we'll need to add some, when performance becomes an issue. It will probably be a very long time before that happens.

The database contains the following collections:

* `submissions` contains all the data sent in by clients. Client hostnames are assumed to be unique, so if two computers with the same hostname are reporting to the server at the same time, bad things will happen.

* `patches` contains patches that have been deployed to clients in the past and/or are still pending deployment.

* `issues` is used to keep track of current and previous issues with clients, including the bookkeeping information necessary to determine when to alert about them.

Geolocation
-----------

If you want to use the geolocation plugin, you'll need an API key from Google. See https://developers.google.com/maps/documentation/geolocation/intro.

Portability concerns
--------------------

The guts of the logic for collecting information about clients is in the plugin scripts. you can run them standalone for debugging by first doing `. var/client-venv/bin/activate` to activate the virtual environment so you have access to all the necessary Python modules. Some of them are more likely than others to require modification for different environments. In particular:

* `os_updates` -- Right now the logic here is Ubuntu-specific. It might work in part or in full in other Debian-based systems, but probably not. Certainly for non-Debian systems, more work is going to need to be done.

* `guest_session` -- Right now it only knows about lightdm, and it may not even be compatible with all lightdm versions. Some work will need to be done to make it smarter about identifying the active display manager and determining whether it support a guest session and has it enabled.

* `screenlock` -- This is specific right now to GNOME screensaver. Work will need to be done to generalize it.

* `hd_encryption` -- Checks for LUKS encryption, either directly on a raw disk device or through LVM. I've only tested this with one configuration so I imagine it's going to have to be made smarter to support others.

* `eraagent` -- If you're not using the ESET ERA Agent, you can delete this. If you delete it on the server before building the release you deploy to clients, it won't be active on the clients. If you delete it after deploying to clients and then build a new release with `bin/client_release`, then the clients will delete it when they download and update to the new release.

* `eset` -- If you're not using ESET antivirus, you can delete this.

* `prey` -- If you're not using Prey, you can delete it.

The other plugin scripts not listed here are more generic, and will probably work on a wide variety of Linux distributions with little or know modification.
