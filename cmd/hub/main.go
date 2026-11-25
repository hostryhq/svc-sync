// Command hub is the restaurant LAN hub (ADR-0002 S8, A3) as a plain binary. Running it as a Windows service is the installer's
// job. Two commands:
//
//	hub activate   register this hub with identity once (internet needed): makes the device key through the key provider,
//	               activates with the 8-character code, stores the signed hub pack. The installer calls it.
//	hub            run the hub: TLS 1.3 listener, encrypted store, pack refresh and cloud sync.
//
// Configuration is environment only (12-factor):
//
//	SYNC_HUB_STATE_DIR         directory for hub.db, device.key and hub-device.json (default ./hub-state)
//	SYNC_HUB_IDENTITY_URL      identity base URL (https; plain http only in dev, test, ci)
//	SYNC_HUB_ACTIVATION_CODE   (activate) the 8-character code
//	SYNC_HUB_NAME              (activate) display name (default "Hub")
//	SYNC_HUB_CLOUD_URL         the cloud gateway base URL; the hub works on the LAN only if unset
//	SYNC_HUB_ADDR              listen address (default :8082)
//	SYNC_HUB_MDNS              "0" to disable the mDNS advertisement
//	SYNC_HUB_KEY_PROVIDER      dpapi (default on Windows) or dev (Linux CI and the soak; NOT protection; HOSTRY_ENV dev, test, ci only)
//	SYNC_HUB_DEV_KEY_FILE      (dev) key file, created when absent; or SYNC_HUB_DEV_KEY holds the key text
//	SYNC_HUB_DEV_PII_LIFT      "1" lifts the pii placement rule for the soak (HOSTRY_ENV dev, test, ci only)
//
// A binary built with the tag `devlan` also reads SYNC_HUB_PACK (a pack file) and SYNC_HUB_PLAIN=1 (a plain HTTP listener) and
// refuses to start outside HOSTRY_ENV dev, test and ci.
package main

import (
	"log/slog"
	"os"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cmd := ""
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	var err error
	switch cmd {
	case "activate":
		err = activate(log, os.Getenv)
	case "", "run":
		err = run(log, os.Getenv)
	default:
		log.Error("unknown command; use activate or run", "command", cmd)
		os.Exit(2)
	}
	if err != nil {
		log.Error("hub stopped", "err", err.Error())
		os.Exit(1)
	}
}
