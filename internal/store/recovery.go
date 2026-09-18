package store

import (
	"context"
)

// AdvanceAllDevices re-runs the contiguous-prefix advancement for every
// device. It is the crash-recovery safety net: if a process died between
// staging candidates and recording the ingestion response, the next related
// request normally advances; this sweep guarantees the watermark catches up
// even when no such request arrives.
func (s *Store) AdvanceAllDevices(ctx context.Context) (int, error) {
	ids, err := s.ListDeviceIDs(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, id := range ids {
		if ctx.Err() != nil {
			return n, ctx.Err()
		}
		tx, err := s.pool.BeginTx(ctx, pgxTxWrite())
		if err != nil {
			return n, err
		}
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", deviceBarrierKey(id)); err != nil {
			_ = tx.Rollback(ctx)
			return n, err
		}
		adv, _, _, err := advanceFromLocked(tx, ctx, id)
		if err != nil {
			_ = tx.Rollback(ctx)
			return n, err
		}
		var hwm int64
		if err := tx.QueryRow(ctx,
			`SELECT contiguous_high_watermark FROM devices WHERE device_id=$1`, id).Scan(&hwm); err != nil {
			_ = tx.Rollback(ctx)
			return n, err
		}
		if len(adv) > 0 {
			if _, err := tx.Exec(ctx, notifySQL(id, hwm)); err != nil {
				_ = tx.Rollback(ctx)
				return n, err
			}
			n++
		}
		if err := tx.Commit(ctx); err != nil {
			return n, err
		}
	}
	return n, nil
}

// notifySQL builds a parameter-free NOTIFY statement for the device channel.
func notifySQL(deviceID string, hwm int64) string {
	return "NOTIFY " + NotifyChannel + ", " + quoteLiteral(DeviceChannelToken(deviceID)+":"+itoa(hwm))
}
