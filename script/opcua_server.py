#!/usr/bin/python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import sys
import random
sys.path.insert(0, "..")
import time

from opcua import ua, Server

if __name__ == "__main__":
    server = Server()
    server.set_endpoint("opc.tcp://0.0.0.0:4840/test/scada/")
    uri = "http://aws.scada.dr.aws.io"
    idx = server.register_namespace(uri)
    objects = server.get_objects_node()
    myobj = objects.add_object(idx, "Transformer")
    freq = myobj.add_variable(idx, "Frequency", 0.0)
    vol = myobj.add_variable(idx, "AC_voltage", 0.0)
    pow = myobj.add_variable(idx, "AC_power", 0.0)
    apow = myobj.add_variable(idx, "Apparent_Power", 0.0)
    pf = myobj.add_variable(idx, "Power_Factor", 0.0)
    setpoint = myobj.add_variable(idx, "SetpointX", 0.0)
    setpoint.set_writable()
    server.start()
    flag = 0
    try:
        while True:
            freq.set_value(random.uniform(1.5, 1.9))
            vol.set_value(random.uniform(239.0, 240.9))
            pow.set_value(random.uniform(90.1, 91.9))
            apow.set_value(random.uniform(2.5, 5.9))
            pf.set_value(random.uniform(0.1, 0.9))
            time.sleep(1)
    finally:
        server.stop()