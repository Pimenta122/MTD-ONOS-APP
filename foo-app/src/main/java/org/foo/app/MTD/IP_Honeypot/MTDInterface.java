package org.foo.app.MTD.IP_Honeypot;

import org.onosproject.net.DeviceId;

public interface MTDInterface {

    void emptyTable(DeviceId deviceId);
    void updateVirtualIP();
}
