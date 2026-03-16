#!/usr/bin/env python3
from __future__ import annotations

from stage import stage02a_taint as _stage02a_taint

main = _stage02a_taint.main


if __name__ == '__main__':
    raise SystemExit(main())
