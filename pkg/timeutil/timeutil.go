package timeutil

import "time"

// GetFirstDayOfNextMonth returns the first day of the next month for a given date.
// If the current day is already the first day of the month then it returns date.
func GetFirstDayOfNextMonth(date time.Time) time.Time {
	date = date.UTC()
	if date.Day() == 1 {
		return date
	}

	return time.Date(date.Year(), date.Month(), 1, date.Hour(), date.Minute(), date.Second(), 0, time.UTC).
		AddDate(0, 1, 0)
}

func GetFirstDayOfTheMonth(date time.Time) time.Time {
	return time.Date(date.Year(), date.Month(), 1, date.Hour(), date.Minute(), date.Second(), 0, time.UTC)
}
