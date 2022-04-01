https://techviewleo.com/how-to-install-kde-plasma-desktop-on-linux-mint/

MINT with KDE installed seems better than Kubuntu

Dolphin as ROOT:

pkexec env DISPLAY=$DISPLAY XAUTHORITY=$XAUTHORITY KDE_SESSION_VERSION=5 KDE_FULL_SESSION=true dolphin

https://www.ventoy.net/

# remove snapd beacuse it sucks

sudo rm -rf /var/cache/snapd/;sudo apt autoremove --purge snapd;sudo apt-mark hold snapd;rm -fr ~/snap

# pipewire
https://linuxconfig.org/how-to-install-pipewire-on-ubuntu-linux

# wayland


 disabling btusb's autosuspend with:

echo 'options btusb enable_autosuspend=0' | sudo tee /etc/modprobe.d/bluetooth.conf


# CURRENT INSTALL NOTES AND SECURITY LIMITATIONS:

sudo add-apt-repository ppa:kubuntu-ppa/backports
sudo apt-get update
sudo apt-get upgrade

also had to sudo ubuntu-drivers autoinstall

reboot

settings > driver manager


get rid of debscan part in my script

old game mode command is broke without installing gamemoded-deamon and cpufregov

fix rivalcfg commands


echo 'kernel.unprivileged_userns_clone=1' > /etc/sysctl.d/unprivileged_userns_clone.conf


fix flatpak

sudo sysctl -w kernel.unprivileged_userns_clone=1


To set it to a value during system startup, create a file in /etc/sysctl.d
containing a line like this:

    user.max_user_namespaces=1000


add this list to ublock origin in settings

https://raw.githubusercontent.com/DandelionSprout/adfilt/master/LegitimateURLShortener.txt

https://github.com/gorhill/uBlock/wiki/Dashboard:-Filter-lists

___________________________________________________________________________________________

https://github.com/ishitatsuyuki/LatencyFleX
