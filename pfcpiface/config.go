// SPDX-License-Identifier: Apache-2.0
// Copyright 2022-present Open Networking Foundation

package pfcpiface

import (
	"encoding/json"
	"net"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	// Default values
	maxReqRetriesDefault = 5
	respTimeoutDefault   = 2 * time.Second
	hbIntervalDefault    = 5 * time.Second
	readTimeoutDefault   = 15 * time.Second
)

// Conf : Json conf struct.
type Conf struct {
	Mode                     string           `json:"mode"`
	AccessIface              IfaceType        `json:"access"`
	CoreIface                IfaceType        `json:"core"`
	CPIface                  CPIfaceInfo      `json:"cpiface"`
	EnableGtpuPathMonitoring bool             `json:"enable_gtpu_path_monitoring"`
	EnableFlowMeasure        bool             `json:"measure_flow"`
	SimInfo                  SimModeInfo      `json:"sim"`
	ConnTimeout              uint32           `json:"conn_timeout"` // TODO(max): unused, remove
	ReadTimeout              uint32           `json:"read_timeout"` // TODO(max): convert to duration string
	EnableNotifyBess         bool             `json:"enable_notify_bess"`
	EnableEndMarker          bool             `json:"enable_end_marker"`
	NotifySockAddr           string           `json:"notify_sockaddr"`
	EndMarkerSockAddr        string           `json:"endmarker_sockaddr"`
	LogLevel                 zapcore.Level    `json:"log_level"`
	QciQosConfig             []QciQosConfig   `json:"qci_qos_config"`
	SliceMeterConfig         SliceMeterConfig `json:"slice_rate_limit_config"`
	MaxReqRetries            uint8            `json:"max_req_retries"`
	RespTimeout              string           `json:"resp_timeout"`
	EnableHBTimer            bool             `json:"enable_hbTimer"`
	HeartBeatInterval        string           `json:"heart_beat_interval"`
	N4Addr                   string           `json:"n4_addr"`
	Li                       *LiConfig        `json:"li,omitempty"`
}

// LiConfig configures the Lawful Interception CC-POI (X3 shipper). It is opt-in:
// when absent, the LI content-of-communication egress is inactive and the UPF
// behaves exactly as before. The X3 socket is the userspace UnixSocketPort the
// BESS pipeline tees duplicated packets to (see conf).
type LiConfig struct {
	X3SockAddr string `json:"x3_sockaddr"` // unixpacket socket the datapath tees LI copies to
	Cert       string `json:"cert"`        // X0 LI PKI: this NE's certificate
	Key        string `json:"key"`         // its private key
	CACert     string `json:"ca_cert"`     // the LI CA trust anchor
	NEID       string `json:"ne_id"`       // this NE's identifier (for X1 issue reports)
	AdmfURL    string `json:"admf_url"`    // ADMF X1 endpoint for NE-initiated issue reports (optional)
	AdmfID     string `json:"admf_id"`     // responsible ADMF identifier (for reports)
	// X1Listen is the address the CC-POI's LI_T3 triggering interface binds. The
	// CC Triggering Function in the SMF tasks this UPF over it (TS 33.128 clause
	// 6.2.3.3), which is where the warrant XID, the correlation identifier and the
	// X3 destination come from; without it the datapath can duplicate traffic but
	// nothing can attribute the result.
	X1Listen string `json:"x1_listen"`
	// TFID is the identifier of the CC Triggering Function authorised to task this
	// CC-POI — the SMF's, not the ADMF's. It is checked against the identity bound
	// into the peer's certificate (TS 103 221-1 clause 8.2.4), so a certificate
	// from the LI CA does not by itself grant the authority to task this UPF.
	TFID string `json:"tf_id"`
	// X3RcvBuf is the receive buffer requested on the datapath egress socket, in
	// bytes; 0 leaves the kernel default. Deepening it absorbs bursts of duplicated
	// packets that would otherwise be discarded on the datapath's write.
	//
	// It is only half the story, and the other half is not in this process: an
	// AF_UNIX SEQPACKET socket rejects a write once its queue holds
	// net.unix.max_dgram_qlen datagrams — 10 by default, regardless of buffer size.
	// That sysctl is per network namespace and must be raised before this socket is
	// created, so it belongs to the deployment (see li/README.md).
	X3RcvBuf int `json:"x3_rcvbuf"`
	// TriggerKeepalive is how long this CC-POI keeps its tasking after the last
	// message from its triggering function, as a Go duration ("5m"). Empty leaves
	// the fail-safe off.
	//
	// It exists because tasking must not outlive the party responsible for it: a
	// triggering function that restarts forgets the triggers it installed, and
	// without this the POI would keep intercepting content nobody can withdraw —
	// past the point where the warrant itself is revoked. The triggering function
	// keeps tasking alive by sending keepalives, so this only lapses when it is
	// genuinely gone.
	TriggerKeepalive string `json:"trigger_keepalive"`
}

// QciQosConfig : Qos configured attributes.
type QciQosConfig struct {
	QCI                uint8  `json:"qci"`
	CBS                uint32 `json:"cbs"`
	PBS                uint32 `json:"pbs"`
	EBS                uint32 `json:"ebs"`
	BurstDurationMs    uint32 `json:"burst_duration_ms"`
	SchedulingPriority uint32 `json:"priority"`
}

type SliceMeterConfig struct {
	N6RateBps    uint64 `json:"n6_bps"`
	N6BurstBytes uint64 `json:"n6_burst_bytes"`
	N3RateBps    uint64 `json:"n3_bps"`
	N3BurstBytes uint64 `json:"n3_burst_bytes"`
}

// SimModeInfo : Sim mode attributes.
type SimModeInfo struct {
	MaxSessions uint32 `json:"max_sessions"`
	StartUEIP   net.IP `json:"start_ue_ip"`
	StartENBIP  net.IP `json:"start_enb_ip"`
	StartAUPFIP net.IP `json:"start_aupf_ip"`
	N6AppIP     net.IP `json:"n6_app_ip"`
	N9AppIP     net.IP `json:"n9_app_ip"`
	StartN3TEID string `json:"start_n3_teid"`
	StartN9TEID string `json:"start_n9_teid"`
	UplinkMBR   uint64 `json:"uplink_mbr"`
	DownlinkMBR uint64 `json:"downlink_mbr"`
	UplinkGBR   uint64 `json:"uplink_gbr"`
	DownlinkGBR uint64 `json:"downlink_gbr"`
}

// CPIfaceInfo : CPIface interface settings.
type CPIfaceInfo struct {
	Peers           []string `json:"peers"`
	UseFQDN         bool     `json:"use_fqdn"`
	NodeID          string   `json:"hostname"`
	HTTPPort        string   `json:"http_port"`
	Dnn             string   `json:"dnn"`
	EnableUeIPAlloc bool     `json:"enable_ue_ip_alloc"`
	UEIPPool        string   `json:"ue_ip_pool"`
}

// IfaceType : Gateway interface struct.
type IfaceType struct {
	IfName string `json:"ifname"`
}

// validateConf checks that the given config reaches a baseline of correctness.
func validateConf(conf Conf) error {
	// Mode is only relevant in a BESS deployment.
	validModes := map[string]struct{}{
		"af_xdp":    {},
		"af_packet": {},
		"dpdk":      {},
		"sim":       {},
	}
	if _, ok := validModes[conf.Mode]; !ok {
		return ErrInvalidArgumentWithReason("conf.Mode", conf.Mode, "invalid mode")
	}

	if conf.CPIface.EnableUeIPAlloc {
		_, _, err := net.ParseCIDR(conf.CPIface.UEIPPool)
		if err != nil {
			return ErrInvalidArgumentWithReason("conf.UEIPPool", conf.CPIface.UEIPPool, err.Error())
		}
	}

	for _, peer := range conf.CPIface.Peers {
		ip := net.ParseIP(peer)
		if ip == nil {
			return ErrInvalidArgumentWithReason("conf.CPIface.Peers", peer, "invalid IP")
		}
	}

	if _, err := time.ParseDuration(conf.RespTimeout); err != nil {
		return ErrInvalidArgumentWithReason("conf.RespTimeout", conf.RespTimeout, "invalid duration")
	}

	if conf.ReadTimeout == 0 {
		return ErrInvalidArgumentWithReason("conf.ReadTimeout", conf.ReadTimeout, "invalid duration")
	}

	if conf.MaxReqRetries == 0 {
		return ErrInvalidArgumentWithReason("conf.MaxReqRetries", conf.MaxReqRetries, "invalid number of retries")
	}

	if conf.EnableHBTimer {
		if _, err := time.ParseDuration(conf.HeartBeatInterval); err != nil {
			return err
		}
	}

	// Lawful Interception is opt-in, but if it IS configured every field is
	// mandatory — an incomplete Li block would otherwise fail open (the UPF runs
	// healthy while performing no interception), which for LI is a compliance risk.
	if conf.Li != nil {
		for name, val := range map[string]string{
			"li.x3_sockaddr": conf.Li.X3SockAddr,
			"li.cert":        conf.Li.Cert,
			"li.key":         conf.Li.Key,
			"li.ca_cert":     conf.Li.CACert,
			// The triggering interface is not optional either: a CC-POI with no
			// LI_T3 listener receives no warrant identity, so it can only produce
			// content no mediation function is able to attribute.
			"li.x1_listen": conf.Li.X1Listen,
			"li.tf_id":     conf.Li.TFID,
			"li.ne_id":     conf.Li.NEID,
		} {
			if val == "" {
				return ErrInvalidArgumentWithReason(name, val, "required when li is configured")
			}
		}
		// An unparseable fail-safe window is rejected here rather than treated as
		// "off": a deployment that asked for the fail-safe and silently did not get
		// it keeps tasking that nothing will ever reclaim.
		if _, err := triggerKeepalive(conf.Li.TriggerKeepalive); err != nil {
			return ErrInvalidArgumentWithReason("li.trigger_keepalive", conf.Li.TriggerKeepalive,
				"must be a positive Go duration (e.g. \"5m\") or empty to disable")
		}
	}

	return nil
}

// removeComments strips // line comments and /* */ block comments from a JSONC
// document, leaving comment markers that appear inside string literals alone.
//
// That last part is the whole point: a regex sweep for `//.*$` also eats the
// scheme separator of any URL-valued setting, and because this configuration is
// rendered as a single line, "https://..." truncated everything after it and the
// file failed to parse as "unexpected end of JSON input" — with nothing to
// suggest a URL was to blame.
func removeComments(jsonc string) string {
	var b strings.Builder

	b.Grow(len(jsonc))

	inString, escaped := false, false

	for i := 0; i < len(jsonc); i++ {
		c := jsonc[i]

		if inString {
			b.WriteByte(c)

			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}

			continue
		}

		switch {
		case c == '"':
			inString = true

			b.WriteByte(c)
		case c == '/' && i+1 < len(jsonc) && jsonc[i+1] == '/':
			// Line comment: drop it, but keep the newline so line numbers in any
			// subsequent parse error still point at the right place.
			for i < len(jsonc) && jsonc[i] != '\n' {
				i++
			}

			if i < len(jsonc) {
				b.WriteByte('\n')
			}
		case c == '/' && i+1 < len(jsonc) && jsonc[i+1] == '*':
			i += 2
			for i+1 < len(jsonc) && (jsonc[i] != '*' || jsonc[i+1] != '/') {
				i++
			}

			i++ // the loop's own i++ steps past the closing '/'
		default:
			b.WriteByte(c)
		}
	}

	return b.String()
}

// LoadConfigFile : parse jsonc file and populate corresponding struct
func LoadConfigFile(filepath string) (Conf, error) {
	// Open up file.
	jsoncFile, err := os.ReadFile(filepath)
	if err != nil {
		return Conf{}, err
	}

	jsonData := removeComments(string(jsoncFile))

	var conf Conf
	conf.LogLevel = zap.InfoLevel

	err = json.Unmarshal([]byte(jsonData), &conf)
	if err != nil {
		return Conf{}, err
	}

	// Set defaults, when missing.
	if conf.RespTimeout == "" {
		conf.RespTimeout = respTimeoutDefault.String()
	}

	if conf.ReadTimeout == 0 {
		conf.ReadTimeout = uint32(readTimeoutDefault.Seconds())
	}

	if conf.MaxReqRetries == 0 {
		conf.MaxReqRetries = maxReqRetriesDefault
	}

	if conf.EnableHBTimer {
		if conf.HeartBeatInterval == "" {
			conf.HeartBeatInterval = hbIntervalDefault.String()
		}
	}

	// Perform basic validation.
	err = validateConf(conf)
	if err != nil {
		return Conf{}, err
	}

	return conf, nil
}
