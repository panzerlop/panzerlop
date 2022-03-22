sysctl kernel.unprivileged_bpf_disabled=1

covers for eBPF backdoor? ( patched in later kernals ? )

# remove snapd beacuse it sucks

sudo rm -rf /var/cache/snapd/;sudo apt autoremove --purge snapd;sudo apt-mark hold snapd;rm -fr ~/snap

# pipewire
https://linuxconfig.org/how-to-install-pipewire-on-ubuntu-linux

# wayland


 disabling btusb's autosuspend with:

:: Code ::
echo 'options btusb enable_autosuspend=0' | sudo tee /etc/modprobe.d/bluetooth.conf
