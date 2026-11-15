// modemctl - CLI for the ZTE MC888x web API (goform).
package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"
	"unicode/utf16"
)

const usage = `modemctl - CLI for the ZTE MC888x web API (goform)

  modemctl status                     signal / network / WAN summary
  modemctl devices                    connected Wi-Fi and LAN clients, as a table
  modemctl name MAC NAME              give a device a name on the modem
  modemctl ussd CODE [REPLY...]       run a USSD code (e.g. '*111#'), then answer its menus
  modemctl sms                        list SMS
  modemctl sms send NUMBER TEXT       send SMS
  modemctl sms rm ID [ID...]          delete SMS
  modemctl get NV[,NV...] [k=v...]    read any variable(s), raw JSON
  modemctl set GOFORM_ID [k=v...]     run any write action, raw JSON
  modemctl ids                        list every NV name / GOFORM_ID the web UI uses
  modemctl reboot | logout

Env: MODEM_HOST (192.168.1.1), MODEM_USER (User).
Password: macOS keychain, service "modem-admin", account "password".
`

const statusNVs = "modem_main_state,network_provider_fullname,network_type,network_signalbar,ppp_status," +
	"wan_ipaddr,ipv6_wan_ipaddr,wan_active_band,nr5g_action_band,Z5g_rsrp,Z5g_SINR,lte_rsrp,lte_rssi," +
	"lte_snr,wan_lte_ca,cell_id,nr5g_pci,flux_realtime_rx_thrpt,flux_realtime_tx_thrpt,flux_monthly_rx_bytes," +
	"flux_monthly_tx_bytes,flux_realtime_time,sms_unread_num,wa_inner_version,hardware_version,imei"

var (
	base   = "http://" + env("MODEM_HOST", "192.168.1.1")
	client = &http.Client{Timeout: 30 * time.Second}
	cookie string // raw `stok="..."` pair, cached on disk between runs
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}

func cookiePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		die("%v", err)
	}
	return filepath.Join(home, ".cache", "modemctl", "stok")
}

func do(method, path string, form url.Values) *http.Response {
	var body io.Reader
	if method == http.MethodPost {
		body = strings.NewReader(form.Encode())
	} else if form != nil {
		path += "?" + form.Encode()
	}
	req, err := http.NewRequest(method, base+path, body)
	if err != nil {
		die("%v", err)
	}
	req.Header.Set("Referer", base+"/index.html") // modem rejects requests without it
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, err := client.Do(req)
	if err != nil {
		die("%v", err)
	}
	return resp
}

func decode(resp *http.Response) map[string]any {
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		die("unexpected response (HTTP %d): %.200s", resp.StatusCode, b)
	}
	return out
}

func get(cmd string, extra map[string]string) map[string]any {
	q := url.Values{"isTest": {"false"}, "cmd": {cmd}}
	if strings.Contains(cmd, ",") {
		q.Set("multi_data", "1")
	}
	for k, v := range extra {
		q.Set(k, v)
	}
	return decode(do(http.MethodGet, "/goform/goform_get_cmd_process", q))
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func post(goformID string, params map[string]string) *http.Response {
	f := url.Values{"isTest": {"false"}, "goformId": {goformID}}
	for k, v := range params {
		f.Set(k, v)
	}
	return do(http.MethodPost, "/goform/goform_set_cmd_process", f)
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return strings.ToUpper(hex.EncodeToString(h[:]))
}

func md5Hex(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

// loginHash is what the web UI sends as "password": SHA256(SHA256(pw) + LD), uppercase hex.
func loginHash(pw, ld string) string { return sha256Hex(sha256Hex(pw) + ld) }

// adToken authorizes one write: md5(md5(cr_version + wa_inner_version) + RD). RD is one-shot.
func adToken(crVersion, waInnerVersion, rd string) string {
	return md5Hex(md5Hex(crVersion+waInnerVersion) + rd)
}

// login reuses the cached session cookie and only logs in when the modem says it expired.
func login() {
	if b, err := os.ReadFile(cookiePath()); err == nil {
		cookie = strings.TrimSpace(string(b))
		if str(get("loginfo", nil), "loginfo") == "ok" {
			return
		}
		cookie = ""
	}
	pw, err := exec.Command("security", "find-generic-password", "-s", "modem-admin", "-a", "password", "-w").Output()
	if err != nil {
		die("reading password from keychain: %v", err)
	}
	ld := str(get("LD", nil), "LD")
	resp := post("LOGIN_MULTI_USER", map[string]string{
		"user":     env("MODEM_USER", "User"),
		"password": loginHash(strings.TrimRight(string(pw), "\n"), ld),
	})
	setCookie := resp.Header.Get("Set-Cookie")
	r := decode(resp)
	if res := str(r, "result"); res != "0" && res != "4" {
		// 1=fail 2=another user is logged in 3=bad password 5=locked out
		die("login failed: result=%s (attempts left before lockout: %s)", res, str(get("psw_fail_num_str", nil), "psw_fail_num_str"))
	}
	cookie, _, _ = strings.Cut(setCookie, ";")
	if err := os.MkdirAll(filepath.Dir(cookiePath()), 0o700); err != nil {
		die("%v", err)
	}
	if err := os.WriteFile(cookiePath(), []byte(cookie), 0o600); err != nil {
		die("%v", err)
	}
}

func set(goformID string, params map[string]string) map[string]any {
	v := get("cr_version,wa_inner_version,RD", nil)
	if params == nil {
		params = map[string]string{}
	}
	params["AD"] = adToken(str(v, "cr_version"), str(v, "wa_inner_version"), str(v, "RD"))
	return decode(post(goformID, params))
}

func show(v any) {
	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", "  ")
	e.SetEscapeHTML(false)
	e.Encode(v)
}

func kv(args []string) map[string]string {
	m := map[string]string{}
	for _, a := range args {
		k, v, ok := strings.Cut(a, "=")
		if !ok {
			die("expected key=value, got: %s", a)
		}
		m[k] = v
	}
	return m
}

// The modem stores SMS text (and alphanumeric senders) as UTF-16BE hex.
func smsEncode(s string) string {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.BigEndian.PutUint16(b[2*i:], c)
	}
	return strings.ToUpper(hex.EncodeToString(b))
}

func smsDecode(h string) string {
	b, err := hex.DecodeString(h)
	if err != nil || len(b)%2 != 0 {
		return h
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.BigEndian.Uint16(b[2*i:])
	}
	return string(utf16.Decode(u))
}

// printable replaces control characters so an SMS cannot send escape sequences to the terminal.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || unicode.IsPrint(r) {
			return r
		}
		return unicode.ReplacementChar
	}, s)
}

func smsList() {
	r := get("sms_data_total", map[string]string{
		"page": "0", "data_per_page": "500", "mem_store": "1", "tags": "10", "order_by": "order by id desc",
	})
	hexNum := str(get("zte_wms_number_encode", nil), "zte_wms_number_encode") == "1"
	msgs, _ := r["messages"].([]any)
	for _, x := range msgs { // tag: 0 read, 1 unread, 2 sent, 3 failed, 4 draft
		m, _ := x.(map[string]any)
		num := str(m, "number")
		if hexNum {
			num = smsDecode(num)
		}
		fmt.Printf("[%s] %s  %s  tag=%s\n  %s\n", str(m, "id"), str(m, "date"), printable(num), str(m, "tag"), printable(smsDecode(str(m, "content"))))
	}
}

// privateMAC reports a locally administered address: phones randomize these per network,
// so such a MAC identifies "this phone on this Wi-Fi", not the hardware vendor.
func privateMAC(mac string) bool {
	b, err := hex.DecodeString(strings.ReplaceAll(mac, ":", ""))
	return err == nil && len(b) == 6 && b[0]&2 != 0
}

func devices() {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tIP\tMAC\tLINK\tNOTE")
	names := map[string]string{} // names saved with "modemctl name" win over what the device announces
	saved, _ := get("hostNameList", nil)["devices"].([]any)
	for _, x := range saved {
		m, _ := x.(map[string]any)
		names[strings.ToUpper(str(m, "mac"))] = str(m, "hostname")
	}
	row := func(list any, link func(map[string]any) string) {
		items, _ := list.([]any)
		for _, x := range items {
			m, _ := x.(map[string]any)
			if n := names[strings.ToUpper(str(m, "mac_addr"))]; n != "" {
				m["hostname"] = n
			}
			note := ""
			if privateMAC(str(m, "mac_addr")) {
				note = "private (randomized) MAC"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", printable(str(m, "hostname")),
				printable(str(m, "ip_addr")), str(m, "mac_addr"), link(m), note)
		}
	}
	row(get("station_list", nil)["station_list"], func(m map[string]any) string {
		if strings.Contains(str(m, "ssid_index"), "2") || strings.Contains(str(m, "interfacetype"), "5") {
			return "wifi 5GHz"
		}
		return "wifi 2.4GHz"
	})
	row(get("lan_station_list", nil)["lan_station_list"], func(map[string]any) string { return "ethernet" })
	w.Flush()
}

// ussd runs one USSD session: send code, print the reply, answer menus with replies, then hang up.
func ussd(code string, replies []string) {
	step := func(params map[string]string) (action string) {
		if r := set("USSD_PROCESS", params); str(r, "result") != "success" {
			die("ussd rejected: %v", r)
		}
		for i := 0; ; i++ { // ussd_write_flag: 15 = waiting for the network, 16 = reply ready
			flag := str(get("ussd_write_flag", nil), "ussd_write_flag")
			if flag == "16" {
				break
			}
			if flag != "15" || i > 30 {
				die("ussd failed: ussd_write_flag=%q (1 no service, 2 network terminated, 3/4 timeout, 99 unsupported)", flag)
			}
			time.Sleep(time.Second)
		}
		r := get("ussd_data_info", nil)
		text := str(r, "ussd_data")
		if str(r, "ussd_dcs") != "15" { // dcs 15 is plain text, anything else is UTF-16BE hex
			text = smsDecode(text)
		}
		fmt.Println(printable(text))
		return str(r, "ussd_action")
	}
	action := step(map[string]string{"USSD_operator": "ussd_send", "USSD_send_number": code})
	for _, reply := range replies {
		fmt.Println("> " + reply)
		action = step(map[string]string{"USSD_operator": "ussd_reply", "USSD_reply_number": reply})
	}
	if action != "0" { // network still waits for an answer: close the session
		set("USSD_PROCESS", map[string]string{"USSD_operator": "ussd_cancel"})
	}
}

func ids() {
	resp := do(http.MethodGet, "/js/service.js", nil)
	defer resp.Body.Close()
	js, _ := io.ReadAll(resp.Body)
	uniq := func(re string, split bool) []string {
		seen := map[string]bool{}
		for _, m := range regexp.MustCompile(re).FindAllSubmatch(js, -1) {
			if !split {
				seen[string(m[1])] = true
				continue
			}
			for _, nv := range strings.Split(string(m[1]), ",") {
				seen[nv] = true
			}
		}
		out := make([]string, 0, len(seen))
		for k := range seen {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	fmt.Println("# GOFORM_IDs (set)\n" + strings.Join(uniq(`goformId[=:]"(\w+)"`, false), "\n"))
	fmt.Println("\n# NV names (get)\n" + strings.Join(uniq(`cmd[=:]"([^"]+)"`, true), "\n"))
}

func main() {
	a := os.Args[1:]
	if len(a) == 0 || a[0] == "-h" || a[0] == "--help" || a[0] == "help" {
		fmt.Print(usage)
		return
	}
	cmd, rest := a[0], a[1:]
	login()
	switch {
	case cmd == "status":
		show(get(statusNVs, nil))
	case cmd == "devices":
		devices()
	case cmd == "name" && len(rest) == 2:
		show(set("EDIT_HOSTNAME", map[string]string{"mac": rest[0], "hostname": rest[1]}))
	case cmd == "ussd" && len(rest) > 0:
		ussd(rest[0], rest[1:])
	case cmd == "get" && len(rest) > 0:
		show(get(rest[0], kv(rest[1:])))
	case cmd == "set" && len(rest) > 0:
		show(set(rest[0], kv(rest[1:])))
	case cmd == "sms" && len(rest) == 0:
		smsList()
	case cmd == "sms" && len(rest) == 3 && rest[0] == "send":
		_, off := time.Now().Zone()
		// ponytail: always UNICODE (70 chars/segment); add GSM7 detection if 160-char segments matter
		show(set("SEND_SMS", map[string]string{
			"Number":      rest[1],
			"sms_time":    time.Now().Format("06;01;02;15;04;05;") + fmt.Sprintf("%+d", off/3600),
			"MessageBody": smsEncode(rest[2]),
			"ID":          "-1",
			"encode_type": "UNICODE",
		}))
	case cmd == "sms" && len(rest) > 1 && rest[0] == "rm":
		show(set("DELETE_SMS", map[string]string{"msg_id": strings.Join(rest[1:], ";") + ";"}))
	case cmd == "ids":
		ids()
	case cmd == "reboot":
		fmt.Print("reboot the modem? [y/N] ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if strings.EqualFold(strings.TrimSpace(line), "y") {
			show(set("REBOOT_DEVICE", nil))
		}
	case cmd == "logout":
		show(set("LOGOUT", nil))
		os.Remove(cookiePath())
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}
}
