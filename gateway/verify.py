"""
Cross-node verification.

For each block index from 0 up to the maximum chain length across nodes:
  - All three block_hashes match            -> consistent
  - 2 match, 1 differs                      -> flag the differing node
  - 1 missing                               -> flag deletion/truncation
                                              (in quorum mode this may be
                                              benign offline lag)
  - all 3 differ                            -> system-wide inconsistency
  - any node's local verify fails           -> include that as the headline
"""


class VerificationService:
    def __init__(self, replicator):
        self.replicator = replicator

    def verify_system(self) -> dict:
        node_ids = list(self.replicator.nodes_cfg.keys())

        nodes_report = []
        chains: dict[str, list[dict]] = {}

        for node_id in node_ids:
            try:
                local = self.replicator.fetch_local_verify(node_id)
            except Exception as e:
                nodes_report.append({"node_id": node_id, "valid": False, "reason": f"unreachable: {e}"})
                chains[node_id] = []
                continue
            nodes_report.append(local)
            try:
                chains[node_id] = self.replicator.fetch_chain(node_id)
            except Exception as e:
                chains[node_id] = []
                nodes_report[-1]["reason"] = nodes_report[-1].get("reason") or f"chain fetch failed: {e}"

        max_index = max((len(c) for c in chains.values()), default=0)
        cross_node_issues = []
        mode = self.replicator.mode

        for i in range(max_index):
            hashes_at_i: dict[str, str | None] = {}
            for node_id in node_ids:
                blocks = chains[node_id]
                if i < len(blocks):
                    hashes_at_i[node_id] = blocks[i].get("hash")
                else:
                    hashes_at_i[node_id] = None

            present = {n: h for n, h in hashes_at_i.items() if h is not None}
            missing = [n for n, h in hashes_at_i.items() if h is None]
            distinct = set(present.values())

            if not missing and len(distinct) == 1:
                continue  # consistent

            if missing and len(distinct) <= 1:
                # all present agree, some are missing
                reason = (
                    "missing_due_to_offline_lag"
                    if mode == "quorum"
                    else "missing or truncated block"
                )
                cross_node_issues.append({
                    "block_index": i,
                    "missing_nodes": missing,
                    "present_nodes": list(present.keys()),
                    "reason": reason,
                })
                continue

            if len(distinct) == 2 and len(present) >= 2:
                from collections import Counter
                counts = Counter(present.values())
                most_common_hash, most_common_count = counts.most_common(1)[0]
                if most_common_count >= 2:
                    suspicious = [n for n, h in present.items() if h != most_common_hash]
                    cross_node_issues.append({
                        "block_index": i,
                        "suspicious_node": suspicious[0] if len(suspicious) == 1 else suspicious,
                        "agreeing_nodes": [n for n, h in present.items() if h == most_common_hash],
                        "reason": "majority disagreement: minority node differs",
                    })
                    continue

            cross_node_issues.append({
                "block_index": i,
                "hashes": hashes_at_i,
                "reason": "system-wide inconsistency",
            })

        all_local_valid = all(n.get("valid") for n in nodes_report)
        consistent = not cross_node_issues
        system_status = "valid" if (all_local_valid and consistent) else "compromised"

        return {
            "system_status": system_status,
            "mode": mode,
            "nodes": nodes_report,
            "cross_node_issues": cross_node_issues,
        }
