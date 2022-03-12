Put the following in the Terminal (If you have logged in but have no application launcher 
press Ctrl+Alt+T to open the Terminal) and press Enter;


`rm ~/.config/plasma-org.kde.plasma.desktop-appletsrc && rm ~/.config/plasmashellrc && rm ~/.config/plasmarc &&
kquitapp5 plasmashell || killall plasmashell && kstart5 plasmashell`

This will remove any modifcations you've done to the deksktop like pinned apps & widgets to fix issues with incorrectly displayed Plasma Desktop.

I have also seen users log in to their wallpaper, mouse and nothing else, Right click > Add Panel > Default panel.
Another case that this can fix is when the search in the Application Launcher displays nothing.

A simpler way to just restart the GUI without removing preferences

kquitapp5 plasmashell || killall plasmashell && kstart5 plasmashell
