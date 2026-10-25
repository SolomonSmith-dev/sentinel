-- D1 bills every index entry as a row written. Windows is the hot table (about 43k rows/day for
-- a 30-device LAN), so keep one secondary index. idx_windows_ts(ts, ...) now also serves:
--   prune:        DELETE ... WHERE is_seed = ? AND ts < ?   (ts range, is_seed in index)
--   seed check:   WHERE is_seed = 0 AND ts > now - 900      (ts range, is_seed in index)
DROP INDEX IF EXISTS idx_windows_seed_ts;
DROP INDEX IF EXISTS idx_windows_seed_received;
