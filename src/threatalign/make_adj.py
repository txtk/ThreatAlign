import sys
from collections import defaultdict
from loguru import logger

def find_directed_links(file_path):
    """
    Read a directed triple file and build two adjacency tables:
    1. Store outgoing links for each entity.
    2. Store incoming links for each entity.
    
    Data structure:
    - Key: entity ID (int).
    - Value: a list containing relation-neighbor tuples.
    - Tuple format: (relationship_id, neighbor_id).
    
    Args:
        file_path (str): Path to the .txt triple file.
        
    Returns:
        tuple: (outgoing_links, incoming_links, all_entities)
        - outgoing_links (dict): Dictionary of outgoing links.
        - incoming_links (dict): Dictionary of incoming links.
        - all_entities (set): Set containing all entity IDs.
    """
    # Use defaultdict(list) because one entity can have multiple outgoing/incoming links.
    # For example, (e1, r1, e2) and (e1, r2, e2) are two distinct outgoing links.
    outgoing_links = defaultdict(list)
    incoming_links = defaultdict(list)
    
    # Track every entity observed in the file.
    all_entities = set()
    
    logger.info(f"--- Processing file in directed-graph mode: {file_path} ---")
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for i, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue
                    
                parts = line.split()
                
                if len(parts) == 3:
                    try:
                        e1 = int(parts[0])
                        r = int(parts[1])  # Keep the relation id.
                        e2 = int(parts[2])
                        
                        # Add entity IDs to the global set.
                        all_entities.add(e1)
                        all_entities.add(e2)
                        
                        # --- Core directed-graph logic. ---
                        # 1. Store the outgoing link: e1 -> e2 via relation r.
                        outgoing_links[e1].append((r, e2))
                        
                        # 2. Store the incoming link: e2 <- e1.
                        incoming_links[e2].append((r, e1))
                        
                    except ValueError:
                        logger.info(f"Warning: Malformed line {i+1} (non-numeric), skipped: '{line}'", file=sys.stderr)
                else:
                    logger.info(f"Warning: Malformed line {i+1} (not 3 columns), skipped: '{line}'", file=sys.stderr)

    except FileNotFoundError:
        logger.info(f"Error: file not found '{file_path}'", file=sys.stderr)
        return None, None, None
    except Exception as e:
        logger.info(f"Unexpected error while reading file: {e}", file=sys.stderr)
        return None, None, None

    logger.info(f"--- Processing complete ---")
    return outgoing_links, incoming_links, all_entities