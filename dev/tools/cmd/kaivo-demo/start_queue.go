package main

import (
	"fmt"
	"os"
	"slices"
	"strconv"
	"time"
)

const startMargin = 5 * time.Second

func startPolicy(env map[string]string) (int, time.Duration) {
	limit, window := 3, 5*time.Minute
	var err error
	if value, ok := env["AIPAY_IAM_REGISTRATION_PER_USER"]; ok {
		limit, err = strconv.Atoi(value)
		require(err == nil && limit >= 1, "AIPAY_IAM_REGISTRATION_PER_USER must be a positive integer")
	}
	if value, ok := env["AIPAY_IAM_ATTEMPT_WINDOW"]; ok {
		window, err = time.ParseDuration(value)
		require(err == nil && window >= 30*time.Second && window <= time.Hour, "AIPAY_IAM_ATTEMPT_WINDOW must be between 30s and 1h")
	}
	return limit, window
}

func startWait(history []time.Time, now time.Time, limit int, window time.Duration) (time.Duration, []time.Time) {
	cutoff := now.Add(-window - startMargin)
	var recent []time.Time
	for _, sent := range history {
		if sent.After(cutoff) {
			recent = append(recent, sent)
		}
	}
	if len(recent) < limit {
		return 0, recent
	}
	// If the limit was lowered, the newest limit attempts determine the next slot.
	slices.SortFunc(recent, time.Time.Compare)
	recent = recent[len(recent)-limit:]
	return recent[0].Sub(cutoff), recent
}

func (d *driver) queueStart(user int64) {
	limit, window := startPolicy(d.env("iam"))
	key := "telegram/start-window/" + strconv.FormatInt(user, 10)
	var history []time.Time
	d.read(key, &history)
	for {
		now := time.Now().UTC()
		wait, recent := startWait(history, now, limit, window)
		if wait == 0 {
			d.put(key, append(recent, now))
			return
		}
		line := fmt.Sprintf("/start 已达到 IAM 每用户 %s 内 %d 次的注册上限，预计等待 %s", window, limit, max(time.Second, wait.Round(time.Second)))
		d.trace(line)
		fmt.Fprintln(os.Stderr, line)
		d.sleep(wait)
	}
}
