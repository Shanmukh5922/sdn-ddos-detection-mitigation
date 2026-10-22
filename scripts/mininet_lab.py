#!/usr/bin/env python3
from __future__ import annotations

import argparse

from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import Topo


class SingleSwitchTopo(Topo):
    def build(self) -> None:
        s1 = self.addSwitch("s1")
        h1 = self.addHost("h1", ip="10.0.0.1/24")
        h2 = self.addHost("h2", ip="10.0.0.2/24")
        h3 = self.addHost("h3", ip="10.0.0.3/24")
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)


def run_lab(controller_ip: str = "127.0.0.1", controller_port: int = 6633, keep_running: bool = False) -> None:
    net = Mininet(
        topo=SingleSwitchTopo(),
        controller=RemoteController,
        switch=OVSSwitch,
        autoSetMacs=True,
        autoStaticArp=True,
    )
    c0 = net.addController("c0", ip=controller_ip, port=controller_port)
    net.start()
    print("Topology started. Hosts: h1, h2, h3; switch: s1")
    print("Controller: c0")
    if keep_running:
        net.interact()
    else:
        net.stop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Start a Mininet lab for DDoS detection")
    parser.add_argument("--controller-ip", default="127.0.0.1")
    parser.add_argument("--controller-port", type=int, default=6633)
    parser.add_argument("--interactive", action="store_true")
    args = parser.parse_args()
    run_lab(controller_ip=args.controller_ip, controller_port=args.controller_port, keep_running=args.interactive)
