# Windows test fixtures

Files from [fox-it/dissect.target](https://github.com/fox-it/dissect.target) `tests/_data`
(AGPL-3.0), unmodified, used only by the test suite.

| File | Original path in `tests/_data` |
|---|---|
| SYSTEM.gz | tools/reg/SYSTEM.gz |
| MPCMDRUN.EXE-962E6200.pf | plugins/os/windows/prefetch/MPCMDRUN.EXE-962E6200.pf |
| Amcache.hve | plugins/os/windows/amcache/amcache-new.hve |
| pestudio.lnk | plugins/os/windows/lnk/pestudio.lnk |
| SRUDB.dat | plugins/os/windows/sru/SRUDB.dat |
| 5f7b5f1e01b83767.automaticDestinations-ms | plugins/os/windows/jumplist/ (same name) |
| ActivitiesCache.db | plugins/os/windows/activitiescache/ActivitiesCache.db |
| Microsoft-Windows-Windows Defender%4Operational.evtx | plugins/os/windows/defender/operational.evtx |
| small.E01 | containers/ewf/small.E01 |

`tests/helpers/windows_tree.py` arranges them into a minimal Windows directory tree and adds a
virtual SOFTWARE hive (real images always have one).
