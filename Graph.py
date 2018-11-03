#
# Copyright (c) 2016-2018, Edgewise Networks Inc. All rights reserved.
#
from collections import deque, namedtuple, defaultdict
from random import random, sample, choice
import networkx as nx
import matplotlib.pyplot as plt

inf = float('inf')
Edge = namedtuple('Edge', 'start, end, cost')


def createEdge(start, end, cost=1):
  return Edge(start, end, cost)

class Graph:
    def __init__(self, edges, peripheralVertices):
        self.edges = [createEdge(*edge) for edge in edges]
        self.map = defaultdict(dict)
        for e in self.edges:
            self.map[e.start][e.end] = e
        self.invmap = defaultdict(dict)
        for e in self.edges:
            self.invmap[e.end][e.start] = e
        self.peripherals = frozenset(peripheralVertices)

    def vertices(self):
        return set( sum( ([edge.start, edge.end] for edge in self.edges), [] ) )

    def periphery(self):
        return self.peripherals

    def removeEdge(self, src, dest):
        if src not in self.map:
            return False
        elif dest not in self.map[src]:
            return False
        else:
            e = self.map[src][dest]
            del self.map[src][dest]
            self.edges.remove(e)
            del self.invmap[dest][src]
            return True

    def addEdge(self, src, dest, cost=1):
        if src in self.map and dest in self.map[src]:
            return False
        else:
            e = createEdge(src, dest, cost)
            self.map[src][dest] = e
            self.invmap[dest][src] = e
            self.edges.append(e)
            return True

    def neighbors(self, node):
        if node in self.map:
            return [(dest, e.cost) for dest, e in self.map[node].items()]
        else:
            return []

    def makeVulnerabilityGraph(self, vulnerabilityDict):
        newEdges = [Edge(e.start, e.end, vulnerabilityDict.get(e.end, 1)) for e in self.edges]
        g = Graph(newEdges, self.peripherals)
        return g

    def distanceToNode(self, startNode):
        ginv = self.inverse()
        cumDistDict = defaultdict(int)
        prevNodeDict = {}
        dq = deque()
        dq.append(startNode)
        while len(dq) > 0:
            currNode = dq.popleft()
            cumDist = cumDistDict[currNode]
            for dest, cost in ginv.neighbors(currNode):
                totalCost = cost + cumDist
                if dest not in cumDistDict:
                    dq.append(dest)
                    cumDistDict[dest] = totalCost
                    prevNodeDict[dest] = currNode
                elif totalCost < cumDistDict[dest]:
                    cumDistDict[dest] = totalCost
                    prevNodeDict[dest] = currNode
        return cumDistDict, prevNodeDict

    def getShortestPaths(self, startNode, cnt=5):
        cumDistDict, prevNodeDict = self.distanceToNode(startNode)
        pathStarts = sorted( [(cumDistDict[node], node) for node in self.peripherals], reverse=True )[:cnt]
        def getFullPath(n):
            l = []
            curr = n
            while True:
                l.append(curr)
                if curr == startNode:
                    break
                curr = prevNodeDict[curr]
            #l.reverse()
            return l
        return sorted( (cost, getFullPath(node)) for cost, node in pathStarts )

    def getShortestPathsByDistance(self, startNode, distance):
        cumDistDict, prevNodeDict = self.distanceToNode(startNode)
        pathStarts = [(cumDistDict[node], node) for node in self.peripherals
                      if cumDistDict[node] <= distance]
        def getFullPath(n):
            l = []
            curr = n
            while True:
                l.append(curr)
                if curr == startNode:
                    break
                curr = prevNodeDict[curr]
            return l
        return sorted( (cost, getFullPath(node)) for cost, node in pathStarts )

    def inverse(self):
        invEdges = [Edge(e.end, e.start, e.cost) for e in self.edges]
        g_inv = Graph(invEdges, self.peripherals)
        return g_inv

    def makeNetworkX(self):
        edges = [(e.start, e.end) for e in self.edges]
        gx = nx.Graph()
        gx.add_edges_from(edges)
        return gx

    def drawGraph(self, selectedNode, weightPathList ):
        gx = self.makeNetworkX()
        pos = nx.spring_layout(gx)
        nxEdges = gx.edges()
        redEdges = []
        blueEdges = []
        for src, dst in nxEdges:
            inColor = False
            for _, path in weightPathList:
                for i in range(len(path) - 1):
                    if (src == path[i] and dst == path[i + 1]) or \
                       (src == path[i + 1] and dst == path[i]):
                        inColor = True
                        break
            if inColor:
                # edgeColors.append(20)
                redEdges.append((src, dst))
            else:
                # edgeColors.append(5)
                blueEdges.append((src, dst))
        plt.figure(figsize=(16, 12))
        # nodes
        nx.draw_networkx_nodes(gx, pos, nodelist=[selectedNode], node_color='r', node_size=800)
        nx.draw_networkx_nodes(gx, pos, nodelist=list(self.periphery()), node_color='g', node_size=500)
        otherNodes = list(set(self.vertices()) - set([selectedNode]) - set(self.periphery()))
        nx.draw_networkx_nodes(gx, pos, nodelist=otherNodes, node_color='b', node_size=200)
        # edges
        nx.draw_networkx_edges(gx, pos,
                              edgelist=redEdges,
                               width=4, alpha=0.5, edge_color='r')
        nx.draw_networkx_edges(gx, pos,
                              edgelist=blueEdges,
                               width=4, alpha=0.5, edge_color='b')
        # labels
        labels = {l: l for i, l in enumerate(list(gx.nodes()))}
        nx.draw_networkx_labels(gx, pos, labels, font_size=16)
        plt.axis('off')

    def drawSparsePathGraph(self, selectedNode, weightPathList ):
        # make new graph with only weightPathList nodes and edges
        pathSet = set()
        peripherySet = set()
        for dist, path in weightPathList:
            for n in path:
                pathSet.add(n)
                if n != selectedNode:
                    peripherySet.add(n)
        es = [e for e in self.edges if e.start in pathSet and e.end in pathSet]
        newG = Graph(es, list(peripherySet))
        # make networkx graph from the new one
        gx = newG.makeNetworkX()
        pos = nx.spring_layout(gx)
        nxEdges = gx.edges()
        redEdges = []
        blueEdges = []
        for src, dst in nxEdges:
            inColor = False
            for _, path in weightPathList:
                for i in range(len(path) - 1):
                    if (src == path[i] and dst == path[i + 1]) or \
                       (src == path[i + 1] and dst == path[i]):
                        inColor = True
                        break
            if inColor:
                # edgeColors.append(20)
                redEdges.append((src, dst))
            else:
                # edgeColors.append(5)
                blueEdges.append((src, dst))
        plt.figure(figsize=(16, 12))
        # nodes
        nx.draw_networkx_nodes(gx, pos, nodelist=[selectedNode], node_color='r', node_size=800)
        nx.draw_networkx_nodes(gx, pos, nodelist=list(newG.periphery()), node_color='g', node_size=500)
        #otherNodes = list(set(newG.vertices()) - set([selectedNode]) - set(newG.periphery()))
        #nx.draw_networkx_nodes(gx, pos, nodelist=otherNodes, node_color='b', node_size=200)
        # edges
        nx.draw_networkx_edges(gx, pos,
                              edgelist=redEdges,
                               width=4, alpha=0.5, edge_color='r')
        nx.draw_networkx_edges(gx, pos,
                              edgelist=blueEdges,
                               width=4, alpha=0.5, edge_color='b')
        # labels
        labels = {l: l for i, l in enumerate(list(gx.nodes()))}
        nx.draw_networkx_labels(gx, pos, labels, font_size=16)
        plt.axis('off')


def test1():
    """ note the weights should be 1 - vulnerability(worstSrcApp, worstDestApp)
    """
    graph = Graph([
        ("a", "b", 0.07),  ("a", "c", 0.09),  ("a", "f", 0.14), ("b", "c", 0.10),
        ("b", "d", 0.15), ("c", "d", 0.11), ("c", "f", 0.02),  ("d", "e", 0.06),
        ("e", "f", 0.09)], ['e', 'f'])
    print( graph.getShortestPaths('a', 2) )

def makeGraph(hostCount, edgeCount, peripherySize):
    hosts = ["host_%i" % i for i in range(hostCount)]
    vulns = {host:(1/(9 * random() + 1)) for host in hosts}
    edges = []
    for _ in range(edgeCount):
        src, dest = sample(hosts, 2)
        edges.append( (src, dest, 1) )
    periphery = sample(hosts, peripherySize)
    return Graph(edges, periphery), vulns


def test2():
    graph, host2vuln = makeGraph(1000, 50000, 100)
    start = choice( list(graph.vertices()) )
    while start in graph.periphery():
        start = choice(graph.vertices)
    print("have graph, now shortest paths")
    g = graph.inverse().makeGraphWithNodeWeights(host2vuln)
    results = g.getShortestPaths(start, 5)
    print("start:", start, "\nperiphery:", sorted(g.periphery()))
    for cost, path in results:
        print(cost, [(x, host2vuln[x]) for x in path])
