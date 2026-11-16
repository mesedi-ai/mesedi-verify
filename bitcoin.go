package main

// Bitcoin timestamps: the second public anchor (owner decision D, 21
// October 2026).
//
// Each checkpoint since 16 November 2026 also carries OpenTimestamps
// receipts. A complete receipt is a list of operations that turns the
// checkpoint hash into a Bitcoin block's Merkle root, so a match proves
// the checkpoint existed by the time that block was mined, independently
// of Sigstore. The receipt is read with the same code that wrote it
// (attest.ParseOTSTimestamp); the block's real Merkle root comes from a
// block explorer online (--bitcoin-api, any Esplora-compatible service),
// and offline the report states the block and the value to compare, which
// anyone can check against any Bitcoin node.
//
// A receipt that does not read, or leads to a value that is not its
// block's Merkle root, is a FAILURE: the export carries evidence that is
// false. A pending receipt, an explorer that cannot be reached, or an
// offline run is not: the report says what was not checked.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mesedi-ai/mesedi/backend/attest"
)

// DefaultBitcoinAPI is a public Esplora instance.
const DefaultBitcoinAPI = "https://blockstream.info/api"

// timestampCheck is the result for one checkpoint's receipts.
type timestampCheck struct {
	Seq    uint64 `json:"seq"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

// blockSource returns a block's Merkle root in display byte order and its
// time. Nil means offline.
type blockSource interface {
	merkleRoot(ctx context.Context, height uint64) (string, time.Time, error)
}

type esplora struct {
	base string
	http *http.Client
}

func newEsplora(base string) *esplora {
	return &esplora{base: strings.TrimRight(base, "/"), http: &http.Client{Timeout: 20 * time.Second}}
}

func (e *esplora) get(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.base+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := e.http.Do(req)
	if err != nil {
		return nil, logUnreachable{fmt.Errorf("could not reach the block explorer: %w", err)}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, logUnreachable{err}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, logUnreachable{fmt.Errorf("the block explorer answered HTTP %d", resp.StatusCode)}
	}
	return body, nil
}

func (e *esplora) merkleRoot(ctx context.Context, height uint64) (string, time.Time, error) {
	hash, err := e.get(ctx, "/block-height/"+strconv.FormatUint(height, 10))
	if err != nil {
		return "", time.Time{}, err
	}
	raw, err := e.get(ctx, "/block/"+strings.TrimSpace(string(hash)))
	if err != nil {
		return "", time.Time{}, err
	}
	var b struct {
		MerkleRoot string `json:"merkle_root"`
		Timestamp  int64  `json:"timestamp"`
	}
	if err := json.Unmarshal(raw, &b); err != nil || len(b.MerkleRoot) != 64 {
		return "", time.Time{}, logUnreachable{errors.New("the block explorer's answer has no Merkle root")}
	}
	return strings.ToLower(b.MerkleRoot), time.Unix(b.Timestamp, 0).UTC(), nil
}

func reverseHex(b []byte) string {
	r := make([]byte, len(b))
	for i := range b {
		r[i] = b[len(b)-1-i]
	}
	return hex.EncodeToString(r)
}

// checkTimestamps reads every receipt and, with a block source, compares
// each Bitcoin claim with the real block.
func checkTimestamps(ctx context.Context, export attest.ChainExport, src blockSource) []timestampCheck {
	out := make([]timestampCheck, 0, len(export.Intervals))
	for _, iv := range export.Intervals {
		out = append(out, checkIntervalTimestamps(ctx, iv, src))
	}
	return out
}

func checkIntervalTimestamps(ctx context.Context, iv attest.ExportedInterval, src blockSource) timestampCheck {
	c := timestampCheck{Seq: iv.Checkpoint.Seq}
	if len(iv.Timestamps) == 0 {
		c.Status = "none"
		c.Detail = "no Bitcoin timestamp in the export"
		return c
	}
	digest, err := hex.DecodeString(iv.Checkpoint.Hash)
	if err != nil {
		c.Status, c.Detail = StatusFailed, "the checkpoint hash is not hex, so no receipt can be read"
		return c
	}
	var pending, unchecked []string
	for _, r := range iv.Timestamps {
		ts, err := attest.ParseOTSTimestamp(digest, r.Receipt)
		if err != nil {
			c.Status, c.Detail = StatusFailed, fmt.Sprintf("the receipt from %s does not read: %v", r.Calendar, err)
			return c
		}
		claims := ts.BitcoinClaims()
		if len(claims) == 0 {
			pending = append(pending, r.Calendar)
			continue
		}
		for _, cl := range claims {
			want := reverseHex(cl.Msg)
			if src == nil {
				unchecked = append(unchecked, fmt.Sprintf("block %d, Merkle root %s", cl.Height, want))
				continue
			}
			root, mined, err := src.merkleRoot(ctx, cl.Height)
			if err != nil {
				unchecked = append(unchecked, fmt.Sprintf("block %d (%v)", cl.Height, err))
				continue
			}
			if root != want {
				c.Status = StatusFailed
				c.Detail = fmt.Sprintf("the receipt from %s says block %d, but it leads to %s and that "+
					"block's Merkle root is %s", r.Calendar, cl.Height, want, root)
				return c
			}
			c.Status = StatusVerified
			c.Detail = fmt.Sprintf("in Bitcoin block %d, mined %s", cl.Height, mined.Format(time.RFC3339))
		}
	}
	switch {
	case c.Status == StatusVerified:
	case len(unchecked) > 0:
		c.Status = StatusUnverifiable
		c.Detail = "not compared with Bitcoin: " + strings.Join(unchecked, "; ")
	default:
		c.Status = "pending"
		c.Detail = "not yet in a Bitcoin block (pending at " + strings.Join(pending, ", ") + ")"
	}
	return c
}

// timestampNotes summarises the Bitcoin timestamps: what was established,
// what was not, and whether any receipt is false.
func timestampNotes(checks []timestampCheck, offline bool) (established, notChecked string, failed bool) {
	var ok, open []uint64
	for _, c := range checks {
		switch c.Status {
		case StatusVerified:
			ok = append(ok, c.Seq)
		case StatusFailed:
			failed = true
		default:
			open = append(open, c.Seq)
		}
	}
	if len(ok) > 0 {
		established = fmt.Sprintf(" Checkpoints %v are also in Bitcoin, through OpenTimestamps: "+
			"each receipt leads to its block's real Merkle root.", ok)
	}
	if len(open) > 0 {
		how := "each line above says why"
		if offline {
			how = "an offline run cannot compare a receipt with Bitcoin; each line above names the " +
				"block and the value, which any Bitcoin node can confirm"
		}
		notChecked = fmt.Sprintf("Checkpoints %v have no Bitcoin timestamp that was checked: %s.", open, how)
	}
	return established, notChecked, failed
}
