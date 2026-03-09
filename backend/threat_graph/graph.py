"""
Threat Intelligence Graph
Local AI-Powered Security Operations Center

Graph-based visualization of threat relationships.
"""

import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional, Set
import structlog
import networkx as nx

from config import settings

logger = structlog.get_logger()


class ThreatGraph:
    """Threat intelligence graph database."""
    
    def __init__(self):
        self.graph = nx.MultiDiGraph()
        self.threat_intel_dir = Path(settings.THREAT_INTEL_DIR)
        
        logger.info("ThreatGraph initialized")
    
    async def load_from_datasets(self):
        """Load threat intelligence data into graph."""
        logger.info("Loading threat intelligence into graph")
        
        try:
            # Load threat actors
            threat_actor_file = self.threat_intel_dir / "threat_actors.json"
            if threat_actor_file.exists():
                with open(threat_actor_file, "r") as f:
                    threat_actors = json.load(f)
                    for actor in threat_actors:
                        self.add_entity(
                            entity_type="threat_actor",
                            entity_id=actor.get("id", actor.get("name")),
                            properties=actor,
                        )
                        
                        # Add relationships
                        for malware in actor.get("malware_used", []):
                            self.add_relationship(
                                source_type="threat_actor",
                                source_id=actor.get("id", actor.get("name")),
                                target_type="malware",
                                target_id=malware,
                                relationship_type="uses",
                            )
            
            # Load malware families
            malware_file = self.threat_intel_dir / "malware_families.json"
            if malware_file.exists():
                with open(malware_file, "r") as f:
                    malware = json.load(f)
                    for mal in malware:
                        self.add_entity(
                            entity_type="malware",
                            entity_id=mal.get("id", mal.get("name")),
                            properties=mal,
                        )
            
            # Load CVEs
            cve_file = self.threat_intel_dir / "cve_database.json"
            if cve_file.exists():
                with open(cve_file, "r") as f:
                    cves = json.load(f)
                    for cve in cves:
                        self.add_entity(
                            entity_type="vulnerability",
                            entity_id=cve.get("id", cve.get("cve_id")),
                            properties=cve,
                        )
            
            logger.info(
                f"Graph loaded: {self.graph.number_of_nodes()} nodes, "
                f"{self.graph.number_of_edges()} edges",
            )
            
        except Exception as e:
            logger.error(f"Failed to load graph: {str(e)}")
    
    def add_entity(
        self,
        entity_type: str,
        entity_id: str,
        properties: Optional[Dict[str, Any]] = None,
    ):
        """
        Add an entity to the graph.
        
        Args:
            entity_type: Type of entity (threat_actor, malware, vulnerability, etc.)
            entity_id: Unique identifier
            properties: Entity properties
        """
        node_id = f"{entity_type}:{entity_id}"
        
        self.graph.add_node(
            node_id,
            type=entity_type,
            id=entity_id,
            **(properties or {}),
        )
        
        logger.debug(f"Added entity: {node_id}")
    
    def add_relationship(
        self,
        source_type: str,
        source_id: str,
        target_type: str,
        target_id: str,
        relationship_type: str,
        properties: Optional[Dict[str, Any]] = None,
    ):
        """
        Add a relationship between entities.
        
        Args:
            source_type: Source entity type
            source_id: Source entity ID
            target_type: Target entity type
            target_id: Target entity ID
            relationship_type: Relationship type
            properties: Relationship properties
        """
        source_node = f"{source_type}:{source_id}"
        target_node = f"{target_type}:{target_id}"
        
        self.graph.add_edge(
            source_node,
            target_node,
            type=relationship_type,
            **(properties or {}),
        )
        
        logger.debug(f"Added relationship: {source_node} -[{relationship_type}]-> {target_node}")
    
    async def query(
        self,
        entity_type: Optional[str] = None,
        entity_id: Optional[str] = None,
        relationship_type: Optional[str] = None,
        depth: int = 2,
    ) -> Dict[str, Any]:
        """
        Query the threat graph.
        
        Args:
            entity_type: Filter by entity type
            entity_id: Specific entity ID
            relationship_type: Filter by relationship type
            depth: Relationship depth to traverse
            
        Returns:
            Query results with nodes and edges
        """
        logger.info(f"Querying graph: type={entity_type}, id={entity_id}")
        
        # Find starting nodes
        start_nodes = []
        
        for node, data in self.graph.nodes(data=True):
            if entity_type and data.get("type") != entity_type:
                continue
            if entity_id and data.get("id") != entity_id:
                continue
            start_nodes.append(node)
        
        if not start_nodes:
            return {
                "nodes": [],
                "edges": [],
                "message": "No matching entities found",
            }
        
        # Traverse graph
        visited_nodes: Set[str] = set()
        visited_edges: List[Dict[str, Any]] = []
        
        for start_node in start_nodes:
            # BFS traversal
            queue = [(start_node, 0)]
            
            while queue:
                current_node, current_depth = queue.pop(0)
                
                if current_node in visited_nodes or current_depth > depth:
                    continue
                
                visited_nodes.add(current_node)
                
                # Get neighbors
                for neighbor in self.graph.neighbors(current_node):
                    edge_data = self.graph.get_edge_data(current_node, neighbor)
                    
                    for key, data in edge_data.items():
                        if relationship_type and data.get("type") != relationship_type:
                            continue
                        
                        visited_edges.append({
                            "source": current_node,
                            "target": neighbor,
                            "type": data.get("type", "related"),
                            "properties": {k: v for k, v in data.items() if k != "type"},
                        })
                    
                    if current_depth < depth:
                        queue.append((neighbor, current_depth + 1))
        
        # Build response
        nodes = []
        for node in visited_nodes:
            data = self.graph.nodes[node]
            nodes.append({
                "id": node,
                "type": data.get("type", "unknown"),
                "entity_id": data.get("id", ""),
                "properties": {k: v for k, v in data.items() if k not in ["type", "id"]},
            })
        
        return {
            "nodes": nodes,
            "edges": visited_edges,
            "total_nodes": len(nodes),
            "total_edges": len(visited_edges),
            "timestamp": datetime.utcnow().isoformat(),
        }
    
    def get_entity_types(self) -> List[str]:
        """
        Get all entity types in the graph.
        
        Returns:
            List of entity types
        """
        types = set()
        for _, data in self.graph.nodes(data=True):
            if "type" in data:
                types.add(data["type"])
        return sorted(list(types))
    
    def find_paths(
        self,
        source_type: str,
        source_id: str,
        target_type: str,
        target_id: str,
    ) -> List[List[Dict[str, Any]]]:
        """
        Find all paths between two entities.
        
        Args:
            source_type: Source entity type
            source_id: Source entity ID
            target_type: Target entity type
            target_id: Target entity ID
            
        Returns:
            List of paths (each path is a list of nodes)
        """
        source_node = f"{source_type}:{source_id}"
        target_node = f"{target_type}:{target_id}"
        
        try:
            paths = list(nx.all_simple_paths(
                self.graph,
                source=source_node,
                target=target_node,
                cutoff=5,
            ))
            
            # Convert to readable format
            readable_paths = []
            for path in paths:
                readable_path = []
                for node in path:
                    data = self.graph.nodes[node]
                    readable_path.append({
                        "type": data.get("type", ""),
                        "id": data.get("id", ""),
                    })
                readable_paths.append(readable_path)
            
            return readable_paths
            
        except nx.NetworkXNoPath:
            return []
    
    def get_neighbors(
        self,
        entity_type: str,
        entity_id: str,
        relationship_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Get all neighbors of an entity.
        
        Args:
            entity_type: Entity type
            entity_id: Entity ID
            relationship_type: Optional filter
            
        Returns:
            Neighbor entities
        """
        node_id = f"{entity_type}:{entity_id}"
        
        if node_id not in self.graph:
            return {"error": "Entity not found"}
        
        neighbors = []
        
        for neighbor in self.graph.neighbors(node_id):
            edge_data = self.graph.get_edge_data(node_id, neighbor)
            
            for key, data in edge_data.items():
                if relationship_type and data.get("type") != relationship_type:
                    continue
                
                neighbor_data = self.graph.nodes[neighbor]
                neighbors.append({
                    "entity_type": neighbor_data.get("type", ""),
                    "entity_id": neighbor_data.get("id", ""),
                    "relationship": data.get("type", ""),
                    "properties": {
                        k: v for k, v in neighbor_data.items()
                        if k not in ["type", "id"]
                    },
                })
        
        return {
            "entity_type": entity_type,
            "entity_id": entity_id,
            "neighbors": neighbors,
            "total_neighbors": len(neighbors),
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get graph statistics.
        
        Returns:
            Graph statistics
        """
        nodes = self.graph.number_of_nodes()
        edges = self.graph.number_of_edges()
        
        # Count by type
        type_counts: Dict[str, int] = {}
        for _, data in self.graph.nodes(data=True):
            node_type = data.get("type", "unknown")
            type_counts[node_type] = type_counts.get(node_type, 0) + 1
        
        # Relationship types
        relationship_counts: Dict[str, int] = {}
        for _, _, data in self.graph.edges(data=True):
            rel_type = data.get("type", "related")
            relationship_counts[rel_type] = relationship_counts.get(rel_type, 0) + 1
        
        return {
            "total_nodes": nodes,
            "total_edges": edges,
            "entity_types": type_counts,
            "relationship_types": relationship_counts,
            "density": nx.density(self.graph) if nodes > 0 else 0,
            "timestamp": datetime.utcnow().isoformat(),
        }
    
    async def save_graph(self, filepath: Optional[str] = None):
        """Save graph to disk."""
        if not filepath:
            filepath = str(self.threat_intel_dir / "threat_graph.json")
        
        graph_data = nx.node_link_data(self.graph)
        
        with open(filepath, "w") as f:
            json.dump(graph_data, f, indent=2)
        
        logger.info(f"Graph saved to {filepath}")
    
    async def load_graph(self, filepath: Optional[str] = None):
        """Load graph from disk."""
        if not filepath:
            filepath = str(self.threat_intel_dir / "threat_graph.json")
        
        if Path(filepath).exists():
            with open(filepath, "r") as f:
                graph_data = json.load(f)
            
            self.graph = nx.node_link_graph(graph_data, multigraph=True, directed=True)
            logger.info(f"Graph loaded from {filepath}")
