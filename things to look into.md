sysctl kernel.unprivileged_bpf_disabled=1

covers for eBPF backdoor? ( patched in later kernals ? )

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
