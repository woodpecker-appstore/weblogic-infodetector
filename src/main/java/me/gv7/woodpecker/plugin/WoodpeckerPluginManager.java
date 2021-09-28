package me.gv7.woodpecker.plugin;

import infodetec.AllInfoDetector;
import vuldb.weakpass.WeakpassCheckPlugin;

public class WoodpeckerPluginManager implements IPluginManager {
    public void registerPluginManagerCallbacks(IPluginManagerCallbacks iPluginManagerCallbacks) {
        iPluginManagerCallbacks.registerInfoDetectorPlugin(new AllInfoDetector());
        iPluginManagerCallbacks.registerVulPlugin(new WeakpassCheckPlugin());
    }
}
