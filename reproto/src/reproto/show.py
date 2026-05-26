# SPDX-FileCopyrightText: Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

from pathlib import Path, PurePosixPath
from typing import cast

import yaml
from pyvis.network import Network


def _fqdn_matches_any(fqdn: str, patterns: tuple[str, ...]) -> bool:
    for p in patterns:
        if PurePosixPath(f'/{fqdn}').full_match(f'/{p}'):
            return True
    return False


def _make_network(title: str) -> Network:
    """Create a pyvis Network with shared settings."""
    net = Network(
        height="90vh",
        width="100%",
        directed=True,
        bgcolor="#222222",
        cdn_resources='in_line',
    )
    net.heading = ''
    net.barnes_hut()
    net.set_options("""{
  "physics": {
    "enabled": true,
    "barnesHut": {
      "gravitationalConstant": -8000,
      "centralGravity": 0.3,
      "springLength": 100,
      "springConstant": 0.04,
      "damping": 0.09,
      "avoidOverlap": 1
    },
    "minVelocity": 0.75
  }
}""")
    return net


def _node_colour(fqdns: list[str], max_count: int) -> str:
    """Compute node colour for a non-leaf message node.

    Top-level nodes (those that appear in any 'entries' list, i.e. have at
    least one FQDN) use a red hue; internal nodes (no FQDN) use blue.
    Brightness scales with the number of FQDNs: more merged types → brighter.
    min brightness ~60, max brightness ~255.
    """
    count = len(fqdns)
    if count == 0:
        return '#3355aa'  # dim blue — internal node with no named root
    # Red hue: scale brightness from 80 (count=1) up toward 255 (many).
    # brightness = 80 + 175 * min(count, max_count) / max(max_count, 1)
    t = min(count, max_count) / max(max_count, 1)
    v = int(80 + 175 * t)
    # Red channel full, green and blue scale down to keep it red.
    r = v
    g = int(v * 0.2)
    b = int(v * 0.2)
    return f'#{r:02x}{g:02x}{b:02x}'


def render_scoring_graph(
    compiled_yaml: str,
    output_path: Path,
    title: str,
    with_leaf_nodes: bool = False,
    hide: tuple[str, ...] = (),
) -> None:
    """Render a compiled scoring graph (states/transitions/roots YAML) to HTML."""
    data = cast(dict, yaml.safe_load(compiled_yaml))
    net = _make_network(title)

    # Determine which states have outgoing transitions (non-leaf) vs leaf.
    states_with_outgoing: set[int] = {t['from'] for t in data.get('transitions', [])}
    leaf_states: set[int] = {
        s['id'] for s in data.get('states', []) if s['id'] not in states_with_outgoing
    }

    # Build tooltip: state_id -> sorted list of FQDNs from roots.
    state_fqdns: dict[int, list[str]] = {}
    for root in data.get('roots', []):
        sid = root['state']
        state_fqdns.setdefault(sid, []).append(root['fqdn'])
    for fqdns in state_fqdns.values():
        fqdns.sort()

    # Compute hidden state IDs from --hide patterns.
    hidden_ids: set[int] = set()
    if hide:
        for sid, fqdns in state_fqdns.items():
            if any(_fqdn_matches_any(f, hide) for f in fqdns):
                hidden_ids.add(sid)

    # Max FQDN count across all non-leaf nodes, for brightness scaling.
    max_count = max(
        (len(fqdns) for sid, fqdns in state_fqdns.items() if sid not in leaf_states),
        default=1,
    )

    for state in data.get('states', []):
        sid = state['id']
        wt = state['wire_type']
        is_string = state.get('is_string', False)
        is_leaf = sid in leaf_states

        if sid in hidden_ids:
            continue
        if is_leaf and not with_leaf_nodes:
            continue

        fqdns = state_fqdns.get(sid, [])
        tooltip = '<br>'.join(fqdns) if fqdns else ''

        if not is_leaf:
            net.add_node(
                sid,
                label=str(sid),
                title=tooltip,
                shape='dot',
                color=_node_colour(fqdns, max_count),
                size=20,
            )
        else:
            if wt == 2 and is_string:
                label = 'string'
                colour = '#ff8844'
            elif wt == 0:
                label = 'varint'
                colour = '#ffcc44'
            elif wt == 1:
                label = 'i64'
                colour = '#ffcc44'
            elif wt == 2:
                label = 'len'
                colour = '#ffcc44'
            elif wt == 5:
                label = 'i32'
                colour = '#ffcc44'
            else:
                label = str(wt)
                colour = '#ffcc44'
            net.add_node(
                sid,
                label=label,
                title=tooltip,
                shape='square',
                color=colour,
                size=12,
            )

    edge_colours = {
        'optional': '#4444ff',
        'repeated': '#44aaff',
        'packed':   '#884488',
    }
    for t in data.get('transitions', []):
        if t['from'] in hidden_ids or t['to'] in hidden_ids:
            continue
        if not with_leaf_nodes and t['to'] in leaf_states:
            continue
        colour = edge_colours.get(t['label'], '#888888')
        net.add_edge(
            t['from'],
            t['to'],
            label=str(t['field']),
            color=colour,
        )

    net.write_html(str(output_path))
