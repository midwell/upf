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
	// blockErr, when non-nil, is why this `li` object was refused by the strict decode — an
	// unrecognised key, most likely a misspelling of one this element does model.
	//
	// Unexported so no configuration file can set it, and carried rather than returned from
	// LoadConfigFile because refusing a configuration is not the same as refusing to run. This
	// element forwards subscriber traffic; stopping it over an optional subsystem is an outage
	// of the user plane, and a user plane that will not start is the loudest way there is to
	// disclose that this element is LI-provisioned. Interception does not start on it; the
	// datapath does. Read in startLIShipper, beside validateLiConfig, which exists for exactly
	// this reason.
	blockErr error

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

	// The X2/X3 keepalive mechanism of ETSI TS 103 221-2 clause 6.2.4, on the X3
	// delivery connections this shipper holds. A different mechanism from
	// trigger_keepalive above, which is the fail-safe against the triggering
	// function going quiet; the prefix keeps the two apart in a file that would
	// otherwise carry two unrelated settings called keepalive.
	//
	// Enabled is a pointer so that unset is distinguishable from false: unset runs
	// the mechanism at the specification's own timers (60 s and 180 s), which is
	// what a deployment that configures nothing must get. False is for a mediation
	// function that does not implement the MDF half of the clause and would
	// therefore be disconnected every TIME_P2.
	X2X3KeepaliveEnabled *bool  `json:"x2x3_keepalive_enabled,omitempty"`
	X2X3KeepaliveTimeP1  string `json:"x2x3_keepalive_time_p1,omitempty"` // Go duration; default 60s
	X2X3KeepaliveTimeP2  string `json:"x2x3_keepalive_time_p2,omitempty"` // Go duration; default 180s
	// DeactivateAllTasks and RemoveAllDestinations carry what TS 103 221-1 leaves to
	// advance agreement between the parties on an X1 interface: whether this element
	// performs a bulk deactivation of all its tasking, and whether it performs a bulk
	// removal of all its destinations.
	//
	// Both are tri-state. Unset — the pointer is nil — is "no agreement in advance",
	// the standard's own phrase, and yields the standard's own defaults: bulk
	// deactivation performed, bulk destination removal refused. They are pointers
	// rather than plain bools so that "the operator said false" is a state distinct
	// from "the operator said nothing".
	//
	// Unlike the fields above they are optional, because an unstated agreement is a
	// conformant deployment rather than an incomplete one.
	//
	// Nothing this project ships sends either message to a UPF: the peer here is the
	// SMF's CC Triggering Function, whose x1.Requester implements no bulk request. So
	// disabling both removes an unused capability from an interface reachable by
	// anyone holding an SMF-bound LI certificate — see li/README.md.
	DeactivateAllTasks    *bool `json:"deactivate_all_tasks,omitempty"`
	RemoveAllDestinations *bool `json:"remove_all_destinations,omitempty"`
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

	// The `li` block is deliberately NOT validated here.
	//
	// A validateConf error reaches logger.InitLog.Fatalln("error reading conf file:",
	// err) in cmd/pfcpiface/main.go, and these errors are built by
	// ErrInvalidArgumentWithReason — so a mistyped optional LI value printed
	// `invalid argument 'li.trigger_keepalive'=30 (…)` into the general operator log
	// and then took the **user plane** down. Two violations at once: an LI typo causing
	// a network outage, and an LI-attributable line in a log far more widely readable
	// than the config file it describes. bess.go's own handling of a startLIShipper
	// failure is deliberately vague for exactly that reason, so this contradicted it.
	//
	// The checks live in startLIShipper instead, where the fault reporter exists and a
	// refusal stops interception and nothing else.
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

	// The decode above is upstream's and stays lenient — this fork must keep starting when
	// upstream adds a key it does not model. The LI object is held to a stricter standard, on
	// its own, because a key dropped there lands on a default that fails unsafely and says
	// nothing: see strictLiBlock.
	//
	// **Recorded, not returned.** Returning it failed the whole configuration load, and
	// cmd/pfcpiface's only caller answers that with Fatalln — so a single mistyped LI key
	// crash-looped the user plane, carrying every subscriber's traffic with it, and echoed the
	// offending LI field into the general operator log four lines above the comment forbidding
	// exactly that. startLIShipper's own comment records this lesson, learned once for
	// validateConf and repeated here one layer up.
	//
	// The refusal is carried on the LI object instead and acted on by the LI subsystem, which
	// declines to intercept and tells the ADMF, at a point where the reporting channel exists.
	if liErr := strictLiBlock([]byte(jsonData)); liErr != nil && conf.Li != nil {
		conf.Li.blockErr = liErr
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
