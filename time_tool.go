package main

import "time"

func UnixStampToTime(stamp int64) time.Time {
	return time.Unix(stamp, 0)
}
