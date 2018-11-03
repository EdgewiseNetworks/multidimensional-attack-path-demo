#
# Copyright (c) 2016-2018, Edgewise Networks Inc. All rights reserved.
#
from collections import namedtuple, defaultdict
import VulnerabilityWeights, Graph
from random import choice, random, sample, gauss
from math import sqrt, ceil
import networkx as nx
from itertools import cycle

HostInfo = namedtuple('HostInfo', 'IP, OS, OpenedPorts, ClosedPorts, FilteredPorts, conns')

def createHostInfo(IP, OS, OpenedPorts, ClosedPorts, FilteredPorts, conns):
    newConns = [x for x in conns if x[1] == "Open"]
    return HostInfo(IP, OS, OpenedPorts, ClosedPorts, FilteredPorts, newConns)

PortScannerFilename = "/Users/oneil/Desktop/BSides/SolarWindsPortScanner 2018.10.31 09-04-18.csv"

def loadPortScannerInfo():
    fn = PortScannerFilename
    with open(fn, 'r') as f:
        l = [x.strip() for x in f]
    tops = [i for i, x in enumerate(l) if x == "IP,hostname,MAC,OS,Ping,Opened Ports,Closed ports,Filtered ports,"]
    tops.append(len(l))
    hostInfos = []
    for i in range(len(tops)-1):
        hostInfos.append( parseServer(l, tops[i], tops[i+1]) )
    return hostInfos


def parseServer(lns, start, end):
    IP,hostname,MAC,OS,Ping,OpenedPorts,ClosedPorts,FilteredPorts,BLANK = lns[start+1].strip().split(",")
    #Ports,Status,IANA name,
    conns = []
    for i in range(start+3, end-1):
        conns.append(lns[i].strip().split(",")[:3])
    return createHostInfo(IP, OS, OpenedPorts,ClosedPorts,FilteredPorts, conns)

def harmonicMean(weightList):
    s = sum(1/x for x in weightList if x is not None)
    return len(weightList)/s

def getNodeVulnerabilities():
    hostInfos = loadPortScannerInfo()
    openNameCounts = defaultdict(int)
    for hostInfo in hostInfos:
        for x in hostInfo.conns:
            openNameCounts[x[-1]] += 1
    oses = frozenset(x.OS.strip() for x in hostInfos if len(x.OS.strip()) > 0)
    app2vuln = {}
    translate = {"epmap": "End Point Mapper", "microsoft-ds": "Microsoft Directory Services",
                 "epmd": "Erlang Port Mapper Daemon", "netbios-ssn": "NETBIOS Session Service",
                 "sunproxyadmin": "Sun Proxy Admin", "sunrpc": "Sun Remote Procedure Call",
                 "wsman": "WS-Management", "wsmans": "WS-Management"}
    vw = VulnerabilityWeights.VulnerabilityWeights()
    for n in openNameCounts.keys():
        if n in translate:
            n = translate[n]
        if len(n.strip()) > 0:
            app2vuln[n] = vw.queryVulnerability(n)
    for os in oses:
        app2vuln[os] = vw.queryVulnerability(os)
    host2vuln = {}
    for hostInfo in hostInfos:
        host = hostInfo.IP
        hostVulns = []
        if hostInfo.OS in app2vuln:
            hostVulns.append( app2vuln[hostInfo.OS] )
        hostVulns.extend( [app2vuln.get(x[-1], 1) for x in hostInfo.conns 
                           if len(x[-1].strip()) > 0] )
        if len(hostVulns) > 0:
            host2vuln[host] = harmonicMean(hostVulns) * 10.0 #vuln
        else:
            host2vuln[host] = 30.0
    return host2vuln

def getSmallGraph(edgeDensity=0.5):
    ip2vuln = getNodeVulnerabilities()
    # make random graph
    nodes = sorted(ip2vuln.keys())
    edges = []
    for i, src in enumerate(nodes):
        for j, dst in enumerate(nodes):
            if src == dst: continue
            if random() < edgeDensity:
                edges.append( (src, dst, 1) )
    # get most central node and most peripheral nodes
    gx = nx.DiGraph()
    gx.add_weighted_edges_from(edges)
    centrality = nx.eigenvector_centrality(gx)
    sortedCentrality = sorted([(x, n) for n, x in centrality.items()])
    selectedNode = sortedCentrality[0][-1]
    #
    peripheryCount = ceil(sqrt(len(nodes)))
    periphery = [x[-1] for x in sortedCentrality[-peripheryCount:]]
    g = Graph.Graph(edges, periphery)
    return g, ip2vuln, selectedNode


def duplicateIp2Vuln(ip2vuln, factor):
    """ assume for the time being that factor <= 10000"""
    dup2vuln = {k:v for k, v in ip2vuln.items()}
    ipset = set(ip2vuln.keys())
    iplist = sorted(ip2vuln.keys())
    origin = [10, 10, 20, 1]
    iplen = len(ip2vuln)
    ipiter = cycle(iplist)
    def iptuple2ip(iptuple):
        return '.'.join(str(i) for i in iptuple)
    def incrIptuple(iptuple):
        flag = True
        while flag:
            if iptuple[-1] < 255:
                iptuple[-1] += 1
            else:
                iptuple[-2] += 1
                iptuple[-1] = 1
            if iptuple2ip(iptuple) not in ipset:
                flag = False
        return iptuple
    def noise():
        return 0.5 - random()
    total = factor * iplen
    for i, val in enumerate(ipiter):
        if i >= total:
            break
        dup2vuln[ iptuple2ip(origin) ] = ip2vuln[val] + noise()
        incrIptuple(origin)
    return dup2vuln

def getLargeGraph(factor=100, edgeDensity=0.01):
    ip2vuln = getNodeVulnerabilities()
    dup2vuln = duplicateIp2Vuln(ip2vuln, factor)
    # make random graph
    nodes = sorted(dup2vuln.keys())
    edges = []
    for i, src in enumerate(nodes):
        for j, dst in enumerate(nodes):
            if src == dst: continue
            if random() < edgeDensity:
                edges.append( (src, dst, 1) )
    print("len(nodes) =", len(dup2vuln))
    print("len(edges) =", len(edges))
    # get most central node and most peripheral nodes
    gx = nx.DiGraph()
    #gx = nx.Graph()
    gx.add_weighted_edges_from(edges)
    centrality = nx.eigenvector_centrality(gx)
    #avg_centrality = sum(centrality.values()) / len(gx)
    sortedCentrality = sorted([(x, n) for n, x in centrality.items()])
    selectedNode = sortedCentrality[0][-1]
    #
    peripheryCount = ceil(sqrt(len(nodes)))
    #periphery = sample(nodes, peripheryCount)
    periphery = [x[-1] for x in sortedCentrality[-peripheryCount:]]
    g = Graph.Graph(edges, periphery)
    return g, dup2vuln, selectedNode