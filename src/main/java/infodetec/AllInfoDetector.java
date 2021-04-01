package infodetec;

import me.gv7.woodpecker.plugin.*;

import java.util.ArrayList;
import java.util.List;

public class AllInfoDetector implements InfoDetectorPlugin {
    public static InfoDetectorPluginCallbacks infoDetecPluginCallbacks;
    public static IPluginHelper pluginHelper;

    public void InfoDetectorPluginMain(InfoDetectorPluginCallbacks infoDetectorPluginCallbacks) {
        this.infoDetecPluginCallbacks = infoDetectorPluginCallbacks;
        this.pluginHelper = infoDetecPluginCallbacks.getPluginHelper();
        this.infoDetecPluginCallbacks.setInfoDetectorPluginName("weblogic infodetector");
        this.infoDetecPluginCallbacks.setInfoDetectorPluginAuthor("c0ny1");
        this.infoDetecPluginCallbacks.setInfoDetectorPluginVersion("0.1.0");
        this.infoDetecPluginCallbacks.setInfoDetectorPluginDescription("description");
        List<InfoDetector> infoDetecs = new ArrayList<InfoDetector>();
        infoDetecs.add(new WeblogicInfoDetectorPlugin());
        this.infoDetecPluginCallbacks.registerInfoDetector(infoDetecs);
    }
}
