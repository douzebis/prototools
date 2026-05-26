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
  "nodes": {
    "font": { "face": "sans-serif", "color": "#88cc88", "size": 13 }
  },
  "edges": {
    "font": { "face": "sans-serif", "color": "#888888", "size": 11,
              "align": "middle" }
  },
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


_BRIGHTNESS_CAP = 8   # FQDNs at which brightness maxes out


def _node_colour(fqdns: list[str]) -> str:
    """Compute node colour for a non-leaf message node.

    Top-level nodes (have at least one FQDN) use an amber/gold hue.
    Brightness scales linearly from count=1 (dim but readable) to
    count>=8 (full brightness).  Internal nodes (no FQDN) use dim blue.
    """
    count = len(fqdns)
    if count == 0:
        return '#3355aa'  # dim blue — internal node with no named root
    # t in [0, 1]: 0 at count=1, 1 at count>=_BRIGHTNESS_CAP
    t = min(count - 1, _BRIGHTNESS_CAP - 1) / (_BRIGHTNESS_CAP - 1)
    # Amber hue: R stays high, G scales with brightness, B stays low.
    # dim: #886010  bright: #ffcc20
    r = int(0x88 + t * (0xff - 0x88))
    g = int(0x60 + t * (0xcc - 0x60))
    b = int(0x10 + t * (0x20 - 0x10))
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
        tooltip = '\n'.join(fqdns) if fqdns else ''
        # Label: short type name for named nodes, "+N" suffix when merged, blank for internal.
        if len(fqdns) == 1:
            node_label = fqdns[0].rsplit('.', 1)[-1]
        elif len(fqdns) > 1:
            node_label = f'{fqdns[0].rsplit(".", 1)[-1]}+{len(fqdns) - 1}'
        else:
            node_label = ''

        if not is_leaf:
            net.add_node(
                sid,
                label=node_label,
                title=tooltip,
                shape='dot',
                color=_node_colour(fqdns),
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
    # Patch tooltip CSS: pyvis uses white-space:nowrap which prevents line
    # breaks in multi-FQDN tooltips.  Switch to pre-wrap so \n is respected.
    html = output_path.read_text()
    html = html.replace('white-space:nowrap', 'white-space:pre-wrap', 1)
    output_path.write_text(html)
