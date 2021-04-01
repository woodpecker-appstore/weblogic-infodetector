package me.gv7.woodpecker.plugin;

import infodetec.AllInfoDetector;

public class WoodpeckerPluginManager implements IPluginManager {
    public void registerPluginManagerCallbacks(IPluginManagerCallbacks iPluginManagerCallbacks) {
        iPluginManagerCallbacks.registerInfoDetectorPlugin(new AllInfoDetector());
    }
}
