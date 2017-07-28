PenguinDome -- Simple Linux Mobile Device Management
====================================================

PenguinDome is a minimalist MDM solution for Linux laptop and desktop
computers. It strives to be simple, secure, and easily extendable.
Unlike other MDM solutions which invest a lot of effort in policy
enforcement, PenguinDome is focused on monitoring and reporting.

We wrote PenguinDome at Quantopian to help keep our Linux devices
compliant with our IT and cybersecurity policies without investing a
lot of effort in deploying yet another big, complicated enterprise
security application. Most of the MDM solutions on the market don't
support Linux at all, and we were reluctant to invest a lot of time
and money into deploying one of the few that does.

We like to give our engineers as much leeway as possible in their
technology choices, so we don't require a specific Linux distribution
or "build." After discovering how challenging it was to roll out MDM
to our devices running Windows and Mac OS -- which are much more
heterogeneous, closed systems -- we knew that we would run into even
more complications rolling out a commercial MDM solution for Linux.

We think others might benefit from our approach, so we are releasing
PenguinDome as an open-source project for others to use and contribute
to.

Although we are using PenguinDome in production at Quantopian to
manage our Linux devices, it's still very early-stage software. For
example:

* There's no web app, no fancy user interface, no system-tray icons
  for clients, no integrations with third-party services. At this
  point it's pretty much all command-line-based. We're not against
  adding bells and whistles; we just haven't felt the need for them
  yet ourselves.

* Deployment requires quite a bit of manual effort.

* Although much of the code is generic and should work on most Linux
  distributions, the distro-specific code is heavily weighted toward
  Ubuntu and Arch Linux, the two distros our engineers use.

* Several of the data-collection plugins which are enabled by default
  are particular to our environment rather than generally applicable.

We hope that if others decide to take up the baton and deploy
PenguinDome in other environments, they will submit pull requests
which make the more configurable and deployable for varied
environments, as well as expanding support for additional Linux
distributions.

The PenguinDome approach
------------------------

In a nutshell:

* scripts run on client devices to collect data and submit them to a
  central server;

* the server sticks the data into a MongoDB database; and

* a script periodically looks for client problems in the data and
  warns about them so that they can be addressed.

There are some additional wrinkles related to logging, automatic
client updates, and secure communication between the clients and
server, but the three bullet points capture PenguinDome's essential
functionality.

Requirements
------------

The two strictest requirements for PenguinDome are Python 3.5.x on
both the clients and server, and GnuPG 2.1.11+ on the clients
and 2.1.15+ on the server.

Aside from that, there are of course various OS package dependencies
for the clients and server. These are defined in the
`ubuntu-packages.txt` and `arch-packages.txt` files in the `client`
and `server` subdirectories of the code base. These packages are
installed on the client by `client/client-setup.sh` and on the server
by `server/server-setup.sh`; it should be relatively easy to teach
these scripts to know about additional OS distributions and create
package lists for these distributions using the existing package lists
as a guide.

PenguinDome also uses a bunch of Python packages, all of which are
deployed into a private virtualenv on the clients and server using
`pip` at install time.

There's a nascent attempt in the `arch` subdirectory to build Pacman
client packages for Arch Linux, but these don't entirely work right
now, so for the time being, Arch clients use the same deployment
scripts as other distributions.

Both the server and client use `cron`, though the aforementioned Arch
package attempts to use `systemd` on the client instead. The server
process is managed as a `systemd` service, though it should be easy
enough to manage it differently on distributions that don't have
`systemd`.

Finally, you need a MongoDB server to hold PenguinDome's data.

Deployment
----------

### Server

Copy the whole source tree onto the machine you're going to use as the
server. Run `server/server-setup.sh` as root (obviously, it would be
ideal if the server didn't need to run as root after installation, but
we haven't implemented this yet; we'll gladly accept patches!). The
setup script installs the necessary OS patches, configures the server
virtualenv, installs the necessary Python packages, asks you a bunch
of configuration questions (discussed below), and sets up the
necessary configuration files for the server and the clients.

Once that's done, run `bin/client_release` as root. This generates a
numbered tar file in `var/client_releases` which is then download and
install on clients as described below.

Whenever any of the files used on the clients is changed, you run
`bin/client_release` again, and a new release is generated and
downloaded and installed automatically by existing clients.

The server setup script creates `server/settings.yml` and
`client/settings.yml`. The former is used on the server, and the
latter is deployed to clients in the release tar files described
below. You can also edit these files directly, instead of or in
addition to using the setup script, but note that you do need to run
the setup script at least once, because it does other necessary things
besides creating the settings files. See
`server/settings.yml.template` and `client/settings.yml.template` for
documentation of what goes in these files.

The server uses `cron` to periodically run an audit script which
reports on outstanding issues, as well as a helper script necessary
for tracking Arch Linux security updates.

### Client

To install the client, you take the most recent release tar file in
`var/client_releases`, copy it to the client, unpack it in a directory
somewhere (anywhere will work, but `/opt/penguindome` is relatively
standard), and run `client/client-setup.sh -y` as root.

There are two ways to get the tar file onto the client. First, you can
copy it out-of-band and distribute it however you see fit. Second, you
can use the `/PenguinDome/v1/download_release` server endpoint. For
example:

    sudo mkdir /opt/penguindome
    curl -s http://server-host:port/penguindome/v1/download_release > \
      penguindome.tar
    sudo tar -C /opt/penguindome -x -f penguindome.tar
    sudo /opt/penguindome/client/client-setup.sh -y

Note that the release tar files contain sensitive information, such as
SSL certificates and GnuPG keypairs use to secure communication
between the client and server, so access to them should be restricted
to the people in your organization who need them. The
`download_release` endpoint can be restricted using IP ranges or
password authentication, as explained in
`server/settings.yml.template`, or of course you can use a firewall on
the server itself to restrict access to your internal IPs.

Configuration
-------------

The server setup script asks the questions necessary to set up basic,
initial server and client configurations. In addition, there are
advanced configuration options that are not handled by the setup
script.

### Server setup script

* **Do you want to support Arch Linux clients?** If you say yes, then
  cron jobs will be configured on the server to periodically poll the
  mailing list archives for the Arch Security mailing list and ingest
  new security announcements, to enable the server to determine when
  Arch clients need to install security patches.

* **What port should the server listen on?** The port number of the
  PenguinDome web service. If you decide to run the web service behind
  nginx or a proxy or something, the port number that the server
  listens on may be different from the port number clients use to
  connect. Here, you're being asked what port the server, not the
  clients, should bind to.

* **Do you want the server to use SSL?** If you say yes, then you'll
  be offered a choice between specifying your own certificate and key
  files, or having the setup script generate a self-signed certificate
  instead. If you choose the latter, then the self-signed certificate
  is included in client releases and used by the clients to verify the
  server certificate, so it is secure.

* **Should the server be multithreaded?** There's no reason for it not
  to be unless you're actively developing or debugging it.

* **Database host:port** specifies the MongoDB host name and port
  number the server should connect to. If it's a replicaset, you can
  specify more than one (you'll keep being prompted until you hit
  Enter to indicate you're done specifying hosts). If you leave off
  the port, the default port number 27017 is used.

* **Replicaset name** and **Database name** should be obvious.

* **Database username** and **Database password** can be blank if the
  database doesn't require authentication, obviously a very bad idea
  unless you're running it on the same host as the server and it's
  heavily protected!

* **Server logbook handler**, **Server logging level**, and possibly
  also **Server syslog facility**, **Server syslog host**, and
  **Server syslog port** control how log messages are handled on the
  server, via [Logbook](https://logbook.readthedocs.io/en/stable/).
  Later in the script, you'll be asked the same questions for the
  client. Note that in addition to the logging configured here, the
  server and client both do full debug logging locally in
  `var/log/penguindome.log` (which is rotated automatically) within
  their installation directory.

* **Do you want to enable the audit cron job?** If you say no, then
  both the periodic audit _and_ the Arch Security information
  collector cron jobs won't be installed. If you want the Arch
  Security jobs but you don't want the audit job, then install the
  crontab and then edit it by hand to comment out the audit job.

* **What email address should get the audit output?** This is just the
  `MAILTO` setting in the crontab.

* **URL base for clients to reach server** is the first part of the
  URL the client should use to connect to the server. As noted above,
  the port number could be different if you're putting the server
  behind some sort of proxy.

* **Google geolocation API key, if any** is necessary if you want to
  use the PenguinDome's geolocation functionality. See
  [this page](https://developers.google.com/maps/documentation/geolocation/intro)
  for additional information.

* **How often (minutes) do you want to collect data?** controls how
  often each client should run its plugin scripts. The scripts are not
  invasive or burdensome, though some of them (most notably the
  geolocation script) take the better part of a minute to run, so it's
  probably not a useful to set this to less than 2.

* **How often (minutes) do you want re-try submits?** You might as
  well leave this set to every minute unless you've got a really good
  reason not to (if you've managing so many clients that that's too
  much for the server to handle, we'd love to hear about it!).

That's the end of the configuration settings that the setup script
asks about. It then asks some additional questions about whether to
add the server to systemd, enable and/or start the systemd service,
install or replace the crontab, and build a client release with the
new client settings.

### Server ports

The setup script can only configure a single port for the server to
listen on, but the server can actually be configured to listen on any
number of ports, and SSL can be configured separately on every port.

The easiest way to do advanced port configuration is with the
`bin/configure_ports` script which is installed by the server setup
script. Run `bin/configure_ports --help` as root for additional
information.

There are a number of reasons why you might want the server to listen
on multiple ports. For example:

* You want to use a self-signed SSL certificate for clients to
  communicate with the server, but you want a non-SSL port for the
  `download_release` endpoint so that users can download the client
  without getting a self-signed certificate error.

* You need to renew your self-signed SSL certificate, and you want the
  old and new certificates active at the same time on different ports
  for a seamless transition.

* Similarly if you want to switch clients from SSL to non-SSL or _vice
  versa_.

* Similarly if for whatever reason you need to change the port that
  clients are connecting to.

One of the things `bin/configure_ports` allows you to do is mark a
port "deprecated," which will cause the server to track clients that
are still using it as open issues. This way, you can easily determine
when it is safe to remove a deprecated port.

### Authentication information for `download_release`

As noted above, you don't want your client release files to be
accessible to the public, because they contain security-sensitive
information which should not be distributed outside your organization.
Therefore, the server allows the `download_release` endpoint to be
authenticated by IP addresses and ranges (IPv4 and IPv6) and/or
username / password pairs. Any combination of these can be used, and
only one match is required (i.e., either a valid client IP address or
a valid username and password) for the request to the endpoint to
succeed.

To add permitted IP ranges, edit `server/settings.xml` directly (see
`server/settings.xml.template` for the format). To add a username and
password, use `bin/save_password` (run it with `--help` for more
information) so that the password is hashed properly in the settings
file.

Note that at this time the `download_release` endpoint is the only one
that supports authentication, though the other endpoints are
authenticated using GnuPG.

Secret-keeping
--------------

One of the concerns with any MDM platform is _Quis custodiet ipsos
custodes?_ or, "Who watches the watchmen?" When private information
such as a device's current location is accessible to administrators,
then how does one prevent a malicious administrator -- who by
necessity needs to have access to the MDM data to do their job -- from
accessing private information without a legitimate business need?

PenguinDome solves this problem as follows:

* MongoDB field selectors are used to designate certain data submitted
  by clients as private. For example, to keep geolocation data, which
  is stored in the database under `{plugins: {geolocation: location:
  {...}}}`, you would configure secret-keeping on the selector
  `plugins.geolocation.location`.

* A special, separate secret-keeping GnuPG keypair is generated, to be
  used for the server to encrypt private data.

* The private key of that keypair is split into several shares, and
  the original private key can only be reconstructed when several of
  those shares are provided. The total number of shares and the number
  required to reconstruct the original key (called the "combine
  threshold") are configurable.

* The private key shares are distributed to different administrators,
  who store them separately and securely, and then _the original
  private key is removed from the server._

* Clients encrypt private data using the secret-keeping public key
  before submitting it to the server. (As a backup, the server checks
  if the private data weren't encrypted on the client, and if so,
  encrypts them.)

* If there is ever a need to decrypt and view private data, at least
  {combine threshold} administrators must provide their shares to
  reconstruct the private key, at which point the data can be
  decrypted and viewed.

Secret-keeping is managed by the server-side script
`bin/secret_keeping`. This script allows you to show the current
configuration; add or remove secret-data selectors; enable or disable
secret-keeping, including generating the necessary keypair and
splitting up the private key into shares for distribution to
secret-keepers; encrypt and decrypt secret data persistently into the
database; or view secret data without decrypting it persistently. Run
`bin/secret_keeping --help` for additional information.

Everyday operation
------------------

### Issues audit

The issues audit that is run out of cron on the server basically just
invokes the script `bin/issues audit`, displays the results to stdout,
and logs them as well.

The issues that it generates output about fall into three categories:

* clients matching MongoDB query specs hard-coded in the `issues`
  script;

* issues flagged by code built into the `issues` script (i.e., SSL
  certificates nearing expiration, clients that have had pending
  patches for a long time); and

* issues flagged by the server during normal operation (i.e., clients
  connecting on deprecated ports).

If you decide not to use any of the plugins that ship by default with
PenguinDome, you may need to remove the corresponding MongoDB query
specs from `server/issues.py`. You may also want to tweak the issues
list at the top of the script to add other queries and/or change the
configurations, e.g., the grace periods before alerts are generated,
of the issues enumerated there.

Clearly, this could be easier to configure than MongoDB query specs
hard-coded in a script. Patches are welcome. ;-)

### Patching clients

If you need to patch PenguinDome files on individual clients, as
opposed to creating a new release with changes that go to all clients,
you can do so using the server-side `bin/patch_hosts` utility. Run
`bin/patch_hosts --help` for additional information.

### Executing one-time commands on clients

For general-purpose, one-time data collection, any scripts found in
the `client/commands` directory on clients are executed, their output
is collected and submitted to the server, and they are deleted after
successful execution (i.e., after they exit with a status of 0).

You can get a one-time command onto clients in one of two ways:

* You can save a script into `client/commands` on the server and then
  run `bin/client_release`.

* You can use the `bin/client_command` script to add a script file or
  shell command to one or more clients as a patch. Run
  `bin/client_command --help` for more information.

### Wiping a client

Wiping a client is a special case of the one-time commands
functionality described above. When you run <code>bin/client_wipe
*hostname*</code> on the server, it queues `server/files/wipe.sh` on
the specified host for execution the next time the host checks in.
This script wipes all non-system-user home directories, kills all of
their processes, and then deletes their accounts.

### Working with open issues

The server utility `bin/issues` is used to review or modify open
issues. It has the following subcommands:

* **audit** -- audit and display open issues
* **snooze**, **unsnooze** -- snooze issues (suppress alerts about
  them) for a specified number of hours or days
* **suspend**, **unsuspend** -- suspend hosts until the next time they
  report to the server
* **close** -- manually close open issues rather than waiting for the
  audit script or server to detect that they are resolved and close
  them automatically

As usual, run `bin/issues --help` for more information.

Implementation notes
--------------------

### Plugins

Plugins are the workhorses of PenguinDome. They live in the directory
`client/plugins`. They can be any executable, although currently all
the plugins that ship with PenguinDome are Python scripts. They take
no arguments and are expected to output JSON. The output of each
plugin is stored in the client's document in MongoDB under the key
<code>{plugins: {*plugin-name*: ...}}</code>, where *plugin-name* is
the name of the plugin script with its extension removed.

Plugins are responsible for avoiding "flapping," i.e., frequent
changes in their output which don't reflect substantive changes in
what they are monitoring. For example:

* The `screenlock` plugin, knows that it can't detect whether a
  screen-lock is in use unless someone is logged in with X running, so
  when no one is, it returns cached data from when someone was last
  logged in.

* The `hd_encryption` plugin sorts the list of devices that it
  returns, to avoid changes showing up in the logs that are actually
  nothing more than the order of devices in the list changing.

Plugins should return the (JSON-encoded) string "unknown" to indicate
that they are unable to answer the question they are designed to
answer. For example, the `geolocation` plugin returns "unknown" when
it is unable to contact Google's geolocation API, or when an API key
for it has not been configured.

Plugins which output timestamps should use UTC. See below for how to
include `datetime` objects in your JSON output.

#### Plugin tools

The PenguinDome library provides some useful tools for plugins to use:

* `from penguindome import cached_data` -- Caches and returns the
  specified data, if data is specified, or returns previously cached
  data if `None` is specified. This is useful for using cached data
  when conditions on the client temporarily prevent accurate data from
  being collected. See sample usages in the `guest_session` and
  `screenlock` plugins.

* `from penguindome import var_dir` -- The `var_dir` variable contains
  the full path of a directory into which plugins can store consistent
  state. Make sure the names of files and directories you create
  within `var_dir` are unambiguously associated with your plugin, so
  avoid overwriting other people's data.

* `from penguindome.client import get_setting` -- Fetches a setting
  from `client/settings.xml`. See the help string for details.
  **NOTE:** It is important to import `get_setting` from
  `penguindome.client`, *not from `penguindome`.*

* `from penguindome.client import get_logger` -- Configures Logbook
  logging as specified in `client/settings.xml` and returns a logger
  which the caller can then use to emit logs. **NOTE:** It is
  important to import `get_logger` from `penguindome.client`, *not
  from `penguindome`.*

* `import penguindome.json as json` -- A JSON encoder / decoder built
  on top of Python's built-in `json` implementation, which looks for
  dictionary keys ending in `_at` and tries to encode them as
  `datetime`s. Similarly, the server looks for such keys in plugin
  output and attempts to decode them into `datetime`s before storing
  them into the database.

* `from penguindome.plugin_tools import find_who_x_users` -- Returns a
  list of `(username, $DISPLAY)` tuples of users who appear, from the
  output of `who`, to be logged into X.

* `from penguindome.plugin_tools import find_xinit_users` -- Similarly
  for users who appear to be logged in via `xinit`.

* `from penguindome.plugin_tools import find_x_users` -- Returns the
  merged output of `find_who_x_users` and `find_x_users`.

* `from penguindome.plugin_tools import DBusUser` -- A class for
  executing commands within a user's running DBus context. See the
  help strings on the class for more information.

#### Portability concerns

The guts of the logic for collecting information about clients is in
the plugin scripts. you can run them standalone for debugging by first
doing `. var/client-venv/bin/activate` to activate the virtual
environment so you have access to all the necessary Python modules.
Some of them are more likely than others to require modification for
different environments. In particular:

* `os_updates` currently works on Ubuntu and Arch Linux, assuming that
  you enable the script on the server that periodically downloads
  notifications from the Arch Security mailing list. To support other
  Linux distributions, add another `*_checker` function in the plugin
  modeled after the `arch_checker` and `ubuntu_checker` functions that
  are already there, and add it to the `checkers` variable near the
  bottom of the script.

* `guest_session` knows how to check if guest sessions are disabled in
  [LightDM](https://www.freedesktop.org/wiki/Software/LightDM/),
  assuming that its configuration files are stored in the standard
  location. It also knows how to check if the user(s) running X are
  doing so via `xinit`, and if so assumes that there are no guest
  sessions. If the plugin can't locate LightDM and confirm that guest
  sessions are disabled or confirm that `xinit` is being used, then it
  returns "unknown" and you'll probably need to enhance it to add
  support for the display managers used by your clients.

* `screenlock` knows how to detect GNOME Screensaver as well as
  `xautolock` being used with either `slock` or `i3lock`. You may need
  to add support for other screensavers used by your clients.

* `hd_encryption` -- Checks for LUKS encryption, either directly on a
  raw disk device or through LVM. I've generalized it enough to work
  with the various different HD encryption setups used by our clients,
  though additional work may need to be done to make it support
  configurations I didn't anticipate.

* `eraagent` -- If you're not using the ESET ERA Agent, you can delete
  this. If you delete it on the server before building the release you
  deploy to clients, it won't be active on the clients. If you delete
  it after deploying to clients and then build a new release with
  `bin/client_release`, then the clients will delete it when they
  download and update to the new release.

* `eset` -- If you're not using ESET antivirus, you can delete this.

* `prey` -- Detects if the [Prey](https://www.preyproject.com/) client
  is installed and running. We're not actually using it right now, so
  it's in `library/client/plugins` rather than `client/plugins` and
  therefore isn't deployed to clients in the default configuration. If
  you want to use it, move it to `client/plugins`.

The other plugin scripts not listed here are more generic, and will
probably work on a wide variety of Linux distributions with little or
no modification.

### Client workflow

The client script `bin/client-cron` is called every minute out of the
crontab installed by `client/client-setup.sh`. It does the following:

* Asks the server for any pending updates (new releases, patches) and
  installs them by calling the `bin/update` script.

* If an update was installed, or if the number of minutes configured
  in `schedule:collect_interval` has elapsed, runs plugins and client
  commands using the `bin/collect` script.

* If any plugins or client commands, or if there is collected output
  from previously run plugins or client commands that has not yet been
  successfully submitted to the server and `schedule:submit_interval`
  as elapsed, then submit collected data to the server using the
  `bin/submit` script.

Client-server API
-----------------

The server supports the following queries from clients:

* `/penguindome/v1/submit` for submitting plugin or command results
  (called by `bin/submit` on the client)

* `/penguindome/v1/update` for downloading a new release and/or
  patches as needed (called by `bin/update` on the client)

* `/penguindome/v1/acknowledge_patch` for acknowledging that a
  particular patch has been applied successfully on the client so it
  can be unqueued on the server (also called by `bin/update` on the
  client)

* `/penguindome/v1/download_release` for downloading a tar file
  containing the most recent client release, as documented above.

All of the API endpoints except `download_release` should be called
with `POST` and require two form fields:

* `data` contains the JSON-encoded query data.

* `signature` contains a detached GnuPG signature for the data. More
  on this below.

Security
--------

When the server is configured with `server/server-setup.sh`, two GnuPG
keypairs are generated, one for the server and one for the clients.
All of the files in releases that go down to the clients are signed
with the server's private key, and clients verify that the files are
intact (i.e., the signatures are valid) before using them. Plugins,
command scripts, etc., that aren't signed by the server's private key
won't be run on the clients.

The client key is used to sign all API requests sent by the clients to
the server. The server won't process any request that doesn't have a
valid signature.

All the clients use the same private key.

The architecture allows for rotating either the server or the client
key, though that's not yet fully supported by the code.

Database
--------

The database contains the following collections:

* `clients` contains all the data sent in by clients. Client hostnames
  are assumed to be unique, so if two computers with the same hostname
  are reporting to the server at the same time, bad things will
  happen.

* `audit_trail` contains an audit trail of changes to client data.

* `patches` contains patches that have been deployed to clients in the
  past and/or are still pending deployment.

* `issues` is used to keep track of current and previous issues with
  clients, including the bookkeeping information necessary to
  determine when to alert about them.

* `arch_security_updates` contains data about Arch Linux security
  bulletins, maintained by the
  `server/plugin_managers/arch_os_updates.py` script, for use in
  determining when there are pending security patches for Arch
  clients.

Geolocation
-----------

If you want to use the geolocation plugin, you'll need an API key from
Google. See
https://developers.google.com/maps/documentation/geolocation/intro.

Contacts
--------

[Github](https://github.com/quantopian/PenguinDome)

[Email](mailto:opensource@quantopian.com)

Credits
-------

PenguinDome was written by Jonathan Kamens at
[Quantopian, Inc.](https://www.quantopian.com) Thank you to
Quantopian for supporting the development and open-sourcing of this
project.

License
-------

Quantopian, Inc. licenses this file to you under the Apache License,
Version 2.0 (the "License"); you may not use this file except in
compliance with the License. You may obtain a copy of the License at

>[http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied. See the License for the specific language governing
permissions and limitations under the License.
