package org.foo.app.MTD;

import org.onosproject.net.DeviceId;

public interface IPShufflingInterface {

    void emptyTable(DeviceId deviceId);
    void updateVirtualIP();

}
