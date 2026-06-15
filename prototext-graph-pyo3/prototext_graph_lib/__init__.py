# SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

from .prototext_graph_lib import build_fds_index, build_graph
from . import prototext_graph_lib

__doc__ = prototext_graph_lib.__doc__
__all__ = ["build_graph", "build_fds_index"]
