[Unit]
Description=PKINIT KDC-CA trust broker
Requires=pkinit-trust-brokerd.socket
After=pkinit-trust-brokerd.socket

[Service]
Type=simple
# --ui auto (the default) is fine here even though this service itself has
# no controlling terminal: "tty" mode prompts on the *connecting client's*
# terminal (found via SO_PEERCRED), not this service's, so a plain-console
# kinit, a root shell, or an SSH session all work with no graphical session
# in the picture. --ui auto additionally tries a desktop notification first
# when one is available.
#
# %S/pins.json is under $XDG_STATE_HOME thanks to StateDirectory=.
ExecStart=@CMAKE_INSTALL_FULL_BINDIR@/pkinit-trust-brokerd --state %S/pins.json
StateDirectory=pkinit-trust-brokerd
